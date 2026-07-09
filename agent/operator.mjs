#!/usr/bin/env node
// P42 autonomous OPERATOR client (Phase 1 plumbing) — the defensive half of the
// loop. It watches on-chain reveals, independently re-runs the exact verifier on
// the fetched solution, publishes a transcript, and AUTO-CHALLENGES any
// submission that is invalid or whose claimedScoreAtoms is UNDER-claimed
// (claimed better than the re-derived truth, which would inflate its marginal
// credit) — filing a bonded challenge on-chain, with a hard bond cap as the
// safety backstop. The legacy improvementAtoms figure is advisory-only and is
// logged, never challenged (see the fraud predicate below).
//
// It never needs the solver to tell it the answer: it fetches the solution
// bytes — from the reveal-tx calldata for on-chain-DA problems, or from the
// off-chain content-addressed store for the large ones — verifies they hash to
// the on-chain sha256 anchor (commitDaHash), and re-derives the verdict itself.
//
// Usage:
//   OPERATOR_PRIVATE_KEY=0x... node operator.mjs \
//     --rpc https://sepolia.base.org \
//     --manifest ../deployments/base-sepolia/<manifest>.json \
//     --problem ../problems/hadamard-mini \
//     --da-dir /tmp/p42-da \
//     --transcripts ./transcripts \
//     --max-challenge-bond 0.01 \
//     [--from-block N] [--once]

import { ethers } from "ethers";
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, mkdtempSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { atomsFromImprovement, chainScoreAtoms, problemObjective, queryChunked, runVerifier } from "./lib.mjs";
import { getBlob } from "./da-local.mjs";
import { fetchFromArweave, findTxidByCid } from "./da-arweave.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
function arg(name, def = undefined) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return def;
  const v = process.argv[i + 1];
  return v && !v.startsWith("--") ? v : true;
}

const RPC = arg("rpc", "https://sepolia.base.org");
const MANIFEST = arg("manifest");
const PROBLEM = arg("problem");
const DA_DIR = arg("da-dir");
const ARWEAVE = arg("arweave", false); // fetch off-chain solution bytes from live Arweave (located by CID tag, then verified against the on-chain sha256 anchor)
const TRANSCRIPTS = resolve(arg("transcripts", `${HERE}/transcripts`));
const MAX_BOND = ethers.parseEther(String(arg("max-challenge-bond", "0.01")));
const ONCE = arg("once", false);
const REPO_ROOT = resolve(arg("repo-root", resolve(HERE, "..")));
// An off-chain store (--da-dir/--arweave) is only needed for off-chain-DA
// problems; on-chain-DA reveals are read straight from the reveal-tx calldata.
// So it is NOT required at startup — it is enforced only when an off-chain
// reveal is actually encountered (see the off-chain fetch branch below).
if (!MANIFEST || !PROBLEM) { console.error("required: --manifest --problem"); process.exit(2); }
const KEY = process.env.OPERATOR_PRIVATE_KEY;
if (!KEY) { console.error("set OPERATOR_PRIVATE_KEY"); process.exit(2); }

const abi = (n) => JSON.parse(readFileSync(`${REPO_ROOT}/contracts/artifacts/src/${n}.sol/${n}.json`, "utf8")).abi;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(...a);

const manifest = JSON.parse(readFileSync(resolve(MANIFEST), "utf8"));
const provider = new ethers.JsonRpcProvider(RPC);
const wallet = new ethers.Wallet(KEY, provider);
const subs = new ethers.Contract(manifest.contracts.submissions.address, abi("P42SubmissionManager"), wallet);
const chal = new ethers.Contract(manifest.contracts.challenges.address, abi("P42ChallengeManager"), wallet);

if (!existsSync(TRANSCRIPTS)) mkdirSync(TRANSCRIPTS, { recursive: true });
// Loud, persisted alert trail for conditions this operator cannot act on
// (e.g. a fraud whose challenge bond exceeds --max-challenge-bond) so a
// human / second operator can escalate even if stdout is lost.
const ALERTS = `${TRANSCRIPTS}/ALERTS.log`;
// Per-run private temp dir (mode 0700, unpredictable suffix) for verifier
// inputs — never a predictable name in the shared os.tmpdir() root, which is
// symlink-followable by other local users.
const RUN_TMP = mkdtempSync(join(tmpdir(), "p42-op-"));
// Objective direction (problem.yaml): maximize problems ride the on-chain
// minimization frontier negated — the operator must re-encode its re-run score
// with the exact same mapping the honest solver uses (see lib.mjs).
const objective = problemObjective(resolve(PROBLEM));
const seen = new Set();
let fromBlock = Number(arg("from-block", manifest.indexer?.startBlock ?? 0));


async function scanOnce() {
  const latest = await provider.getBlockNumber();
  const events = await queryChunked(subs, subs.filters.Revealed(), fromBlock, latest);
  // Reveals we leave for retry this pass (DA not yet available, bond over cap,
  // …) must be RE-SCANNED next pass: track the lowest block among them and
  // rewind fromBlock to it below, instead of unconditionally jumping past them.
  let lowestPendingBlock = Infinity;
  const retryLater = (ev) => { lowestPendingBlock = Math.min(lowestPendingBlock, ev.blockNumber); };
  for (const ev of events) {
    const id = ev.args.submissionId;
    const key = id.toString();
    if (seen.has(key)) continue;
    const cid = ev.args.solutionCid;
    const claimedAtoms = ev.args.improvementAtoms;

    const sub = await subs.submissions(id);
    if (Number(sub.status) !== 2) { seen.add(key); continue; } // not Revealed anymore (finalized/challenged/rejected)

    // Where do the solution bytes live? The Revealed event carries
    // solutionBytesLength: >0 iff the reveal posted the raw bytes on-chain (data
    // availability rides the reveal-tx calldata, equivalent to subs.onchainDa()
    // ==true). ==0 means the bytes live in the off-chain content-addressed store.
    const solLen = ev.args.solutionBytesLength ?? 0n;
    const onchainDa = solLen > 0n;
    log(`\n[reveal] submission #${id}  claimedAtoms=${claimedAtoms}  cid=${cid.slice(0, 20)}…  da=${onchainDa ? `on-chain(${solLen}B)` : "off-chain"}`);

    let blob;
    if (onchainDa) {
      // On-chain DA: the bytes are provably bound to the commit inside the very
      // tx that emitted this Revealed log. Pull them straight from calldata — no
      // external DA store is consulted for these problems.
      log(`  reading solution bytes from reveal-tx calldata ${ev.transactionHash.slice(0, 12)}…`);
      let tx;
      try { tx = await provider.getTransaction(ev.transactionHash); }
      catch (e) { log(`  reveal-tx fetch failed: ${e.message} — leaving for now`); retryLater(ev); continue; }
      if (!tx) { log(`  DA MISS: reveal tx ${ev.transactionHash} not retrievable yet — leaving for now`); retryLater(ev); continue; }
      let parsed;
      try { parsed = subs.interface.parseTransaction({ data: tx.data, value: tx.value }); }
      catch (e) { log(`  could not decode reveal tx: ${e.message} — leaving for now`); retryLater(ev); continue; }
      if (!parsed || parsed.name !== "reveal") { log(`  DA FAULT: log's tx is not a reveal() call — skipping`); seen.add(key); continue; }
      blob = ethers.getBytes(parsed.args.solution);
    } else if (!DA_DIR && !ARWEAVE) {
      // Off-chain reveal but this operator was started without a store. Don't
      // mark seen — leave it for retry once an operator with --da-dir/--arweave
      // (or this one, restarted with a store) can fetch and police it.
      log(`  DA FAULT: off-chain reveal (0 on-chain bytes) but no --da-dir/--arweave configured — cannot fetch to re-verify. Leaving for retry.`);
      retryLater(ev); continue;
    } else if (ARWEAVE) {
      log(`  locating solution on Arweave by CID…`);
      const txid = await findTxidByCid(cid, {});
      if (!txid) { log(`  DA MISS: ${cid} not found on Arweave yet — leaving for now`); retryLater(ev); continue; }
      log(`  fetching from Arweave txid ${txid}…`);
      try { blob = await fetchFromArweave(txid); }
      catch (e) { log(`  Arweave fetch failed: ${e.message} — leaving for now`); retryLater(ev); continue; }
    } else {
      blob = getBlob(DA_DIR, cid);
      if (!blob) { log(`  DA MISS: no blob for ${cid} — cannot re-verify, leaving for now`); retryLater(ev); continue; }
    }

    // Integrity gate — identical for both DA paths: the fetched bytes MUST hash
    // to the on-chain sha256 anchor bound at commit (commitDaHash). This is the
    // same digest the CID encodes (cid="sha256:"+hex, commitDaHash="0x"+hex).
    // On-chain DA cannot actually mismatch (consensus enforces sha256==anchor at
    // reveal); off-chain DA can, which is exactly the tamper/unavailability we
    // must refuse to act on. Don't mark seen — leave for retry.
    const anchor = sub.commitDaHash;
    const got = ethers.sha256(blob);
    if (got !== anchor) {
      log(`  DA FAULT: sha256(fetched bytes)=${got} != on-chain anchor ${anchor} — bytes unavailable/tampered, NOT trusting them; leaving for now`);
      retryLater(ev); continue;
    }

    // Independent re-run of the exact verifier on the fetched bytes (written
    // into the per-run private temp dir, not a predictable shared-tmp name).
    const tmp = join(RUN_TMP, `${key}.json`);
    writeFileSync(tmp, blob);
    const verdict = runVerifier(PROBLEM, tmp, REPO_ROOT);
    const trueAtoms = verdict.valid ? atomsFromImprovement(verdict.improvement) : 0n;
    // ABSOLUTE score fraud check (audit F1): claimedScoreAtoms is the payout
    // driver (marginal credit = previous best - claimed score), so a solver who
    // UNDER-claims its score (claimed lower/better than the re-derived truth)
    // inflates its marginal. Re-encode the re-run's exact score with the shared
    // ceil(score * 1e18) convention and compare to the on-chain claim.
    const claimedScoreAtoms = sub.claimedScoreAtoms;
    const trueScoreAtoms = verdict.valid ? chainScoreAtoms(verdict.score, objective.direction) : null;
    const scoreUnderClaimed = verdict.valid && claimedScoreAtoms < trueScoreAtoms;
    // Challenge ONLY on the two conditions that actually drive payout: an invalid
    // solution, or an under-claimed absolute score (which inflates the marginal
    // credit). The old 1e6 advisory-improvement comparison (claimedAtoms >
    // trueAtoms) is NOT a challenge trigger: it drives no payout and, since a
    // genuine improvement in [1e-12, 1e-6) floors to trueAtoms=0, an honest
    // client reporting any nonzero display figure would be baited into a
    // wrongful (bond-losing) challenge (audit F1 review). Keep it as a logged
    // discrepancy only.
    const improvementDiscrepancy = claimedAtoms > trueAtoms;
    const fraudulent = !verdict.valid || scoreUnderClaimed;

    // Decide the TRUE outcome before publishing: a fraud whose challenge bond
    // exceeds our cap is NOT challenged, and the transcript must say so.
    let bond = 0n;
    let decision = fraudulent ? "CHALLENGE" : "OK";
    if (fraudulent) {
      const disputed = await subs.disputedEntitlementWei(id);
      bond = await chal.requiredChallengeBond(disputed);
      if (bond > MAX_BOND) decision = "UNPOLICED_FRAUD_BOND_OVER_CAP";
    }

    // Publish transcript (durable-store stand-in: a local file + hash).
    const transcript = {
      submissionId: key, solutionCid: cid, verifier_verdict: verdict,
      claimed_atoms: claimedAtoms.toString(), true_atoms: trueAtoms.toString(),
      improvement_discrepancy: improvementDiscrepancy, // advisory only; NOT a challenge trigger
      claimed_score_atoms: claimedScoreAtoms.toString(),
      true_score_atoms: trueScoreAtoms === null ? null : trueScoreAtoms.toString(),
      objective_direction: objective.direction,
      required_bond_wei: bond.toString(),
      decision,
    };
    const tHash = "sha256:" + ethers.sha256(ethers.toUtf8Bytes(JSON.stringify(transcript))).slice(2);
    writeFileSync(`${TRANSCRIPTS}/${key}.json`, JSON.stringify({ ...transcript, transcript_hash: tHash }, null, 2) + "\n");
    log(`  re-run: valid=${verdict.valid} true_improvement=${verdict.improvement ?? "0/1"} true_score_atoms=${trueScoreAtoms ?? "n/a"} claimed_score_atoms=${claimedScoreAtoms}${scoreUnderClaimed ? " (UNDER-CLAIMED SCORE)" : ""} -> ${fraudulent ? "FRAUDULENT" : "honest"}`);

    if (!fraudulent) { seen.add(key); continue; }

    // Bond-cap backstop: we can't afford this challenge, but the fraud is real.
    // Do NOT mark it seen — keep re-scanning it — and persist a loud alert so a
    // human / better-capitalized second operator can escalate.
    if (bond > MAX_BOND) {
      const alert = `${new Date().toISOString()} UNPOLICED FRAUD (bond over cap): submission #${key} requires bond ${ethers.formatEther(bond)} ETH > cap ${ethers.formatEther(MAX_BOND)} ETH — NOT challenged, needs escalation (transcript ${tHash})`;
      console.error(`  !!! ${alert}`);
      appendFileSync(ALERTS, alert + "\n");
      retryLater(ev); continue;
    }

    // Auto-challenge, with the bond cap as the safety backstop.
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes(`p42-operator: verifier re-run says ${cid} is invalid/inflated (${tHash})`));
    log(`  CHALLENGING #${id}  bond=${ethers.formatEther(bond)} ETH`);
    const tx = await chal.challenge(id, reasonHash, { value: bond });
    const rec = await tx.wait();
    log(`  challenged: ${tx.hash} (status ${rec.status})`);
    seen.add(key);
  }
  // Advance past fully-handled blocks only; rewind to the oldest reveal we left
  // for retry so it is re-scanned next pass (seen[] holds the resolved ones).
  fromBlock = Math.min(latest + 1, lowestPendingBlock);
}

async function main() {
  log(`P42 operator — ${wallet.address}  net=${RPC}`);
  log(`watching SubmissionManager ${manifest.contracts.submissions.address} from block ${fromBlock}`);
  if (ONCE) { await scanOnce(); log("\n[once] done."); return; }
  // A transient RPC/network error must not kill the daemon: log and retry next
  // poll (fromBlock is only advanced at the END of a successful scanOnce, so a
  // failed pass simply re-scans the same window).
  for (;;) {
    try { await scanOnce(); }
    catch (e) { console.error(`[scan error] ${e.shortMessage || e.message} — retrying next poll`); }
    await sleep(12000);
  }
}
main().catch((e) => { console.error("FAILED:", e.shortMessage || e.message); process.exit(1); });
