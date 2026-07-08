#!/usr/bin/env node
// P42 autonomous OPERATOR client (Phase 1 plumbing) — the defensive half of the
// loop. It watches on-chain reveals, independently re-runs the exact verifier on
// the fetched solution, publishes a transcript, and AUTO-CHALLENGES any
// submission that is invalid or whose claimed improvement is inflated — filing a
// bonded challenge on-chain, with a hard bond cap as the safety backstop.
//
// It never needs the solver to tell it the answer: it fetches the solution bytes
// by CID from the DA store and re-derives the verdict itself.
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
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { atomsFromImprovement, runVerifier } from "./lib.mjs";
import { getBlob } from "./da-local.mjs";

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
const TRANSCRIPTS = resolve(arg("transcripts", `${HERE}/transcripts`));
const MAX_BOND = ethers.parseEther(String(arg("max-challenge-bond", "0.01")));
const ONCE = arg("once", false);
const REPO_ROOT = resolve(arg("repo-root", resolve(HERE, "..")));
if (!MANIFEST || !PROBLEM || !DA_DIR) { console.error("required: --manifest --problem --da-dir"); process.exit(2); }
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
const seen = new Set();
let fromBlock = Number(arg("from-block", manifest.indexer?.startBlock ?? 0));

async function scanOnce() {
  const latest = await provider.getBlockNumber();
  const events = await subs.queryFilter(subs.filters.Revealed(), fromBlock, latest);
  for (const ev of events) {
    const id = ev.args.submissionId;
    const key = id.toString();
    if (seen.has(key)) continue;
    const cid = ev.args.solutionCid;
    const claimedAtoms = ev.args.improvementAtoms;

    const sub = await subs.submissions(id);
    if (Number(sub.status) !== 2) { seen.add(key); continue; } // not Revealed anymore (finalized/challenged/rejected)

    log(`\n[reveal] submission #${id}  claimedAtoms=${claimedAtoms}  cid=${cid.slice(0, 20)}…`);
    const blob = getBlob(DA_DIR, cid);
    if (!blob) { log(`  DA MISS: no blob for ${cid} — cannot re-verify, leaving for now`); continue; }

    // Independent re-run of the exact verifier on the fetched bytes.
    const tmp = `${tmpdir()}/p42-op-${key}.json`;
    writeFileSync(tmp, blob);
    const verdict = runVerifier(PROBLEM, tmp, REPO_ROOT);
    const trueAtoms = verdict.valid ? atomsFromImprovement(verdict.improvement) : 0n;
    const fraudulent = !verdict.valid || claimedAtoms > trueAtoms;

    // Publish transcript (durable-store stand-in: a local file + hash).
    const transcript = {
      submissionId: key, solutionCid: cid, verifier_verdict: verdict,
      claimed_atoms: claimedAtoms.toString(), true_atoms: trueAtoms.toString(),
      decision: fraudulent ? "CHALLENGE" : "OK",
    };
    const tHash = "sha256:" + ethers.sha256(ethers.toUtf8Bytes(JSON.stringify(transcript))).slice(2);
    writeFileSync(`${TRANSCRIPTS}/${key}.json`, JSON.stringify({ ...transcript, transcript_hash: tHash }, null, 2) + "\n");
    log(`  re-run: valid=${verdict.valid} true_improvement=${verdict.improvement ?? "0/1"} -> ${fraudulent ? "FRAUDULENT" : "honest"}`);

    if (!fraudulent) { seen.add(key); continue; }

    // Auto-challenge, with the bond cap as the safety backstop.
    const disputed = await subs.disputedEntitlementWei(id);
    const bond = await chal.requiredChallengeBond(disputed);
    if (bond > MAX_BOND) { log(`  bond ${ethers.formatEther(bond)} > cap ${ethers.formatEther(MAX_BOND)} — SKIP (safety)`); seen.add(key); continue; }
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes(`p42-operator: verifier re-run says ${cid} is invalid/inflated (${tHash})`));
    log(`  CHALLENGING #${id}  bond=${ethers.formatEther(bond)} ETH`);
    const tx = await chal.challenge(id, reasonHash, { value: bond });
    const rec = await tx.wait();
    log(`  challenged: ${tx.hash} (status ${rec.status})`);
    seen.add(key);
  }
  fromBlock = latest + 1;
}

async function main() {
  log(`P42 operator — ${wallet.address}  net=${RPC}`);
  log(`watching SubmissionManager ${manifest.contracts.submissions.address} from block ${fromBlock}`);
  if (ONCE) { await scanOnce(); log("\n[once] done."); return; }
  for (;;) { await scanOnce(); await sleep(12000); }
}
main().catch((e) => { console.error("FAILED:", e.shortMessage || e.message); process.exit(1); });
