#!/usr/bin/env node
// P42 autonomous solver client (Phase 1 plumbing).
//
// Given a deployment manifest, a problem directory, and a candidate solution,
// this client runs the FULL on-chain lifecycle UNATTENDED, signing every
// transaction itself:
//
//   self-verify (local exact verifier) -> [fund pool] -> commit (CID+DA anchor
//   bound, posting bond) -> reveal (on-chain-DA problems carry the raw solution
//   bytes in the tx) -> wait out the challenge window -> finalize -> [owner
//   close] -> claim payout -> reclaim bond.
//
// Data availability now rides the CHAIN. The on-chain commitDaHash is the
// sha256 of the raw solution bytes (== the CID digest) — a content ANCHOR, not
// a provider txid. For on-chain-DA problems (contract.onchainDa()==true, the 7
// small <=512KB problems) the raw bytes go directly in the reveal-tx calldata,
// provably bound to the commit; no external DA provider is required. For
// off-chain-DA problems (onchainDa()==false, the large autoconvolution
// certificates) the bytes are too big for calldata, so the solver puts them in
// a content-addressed off-chain store (--da-dir local dir and/or --arweave) and
// reveals empty bytes ("0x"); any fetcher re-verifies sha256(bytes)==anchor.
// Arweave is therefore OPTIONAL — a mirror/store, no longer a launch dependency.
// The "improvement" it submits comes from the problem's own exact verifier, so
// on a genuinely-solved problem (e.g. hadamard-mini's optimal defect-0 matrix)
// the Δ and payout are real.
//
// Usage:
//   AGENT_PRIVATE_KEY=0x... node solver.mjs \
//     --rpc https://sepolia.base.org \
//     --manifest ../deployments/base-sepolia/<manifest>.json \
//     --problem ../problems/hadamard-mini \
//     --solution ../problems/hadamard-mini/examples/valid-4.json \
//     [--fund 0.003]   # sponsor-fund the pool first (demo)
//     [--close]        # owner-close the ledger after finalize (demo: owner==agent)
//     [--repo-root ..] # where contracts/artifacts + src live (default: parent of this file's dir)

import { ethers } from "ethers";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { atomsFromImprovement, runVerifier } from "./lib.mjs";
import { putBlob } from "./da-local.mjs";
import { uploadToArweave } from "./da-arweave.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

function arg(name, def = undefined) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return def;
  const v = process.argv[i + 1];
  return v && !v.startsWith("--") ? v : true; // bare flag -> true
}

const RPC = arg("rpc", "https://sepolia.base.org");
const MANIFEST = arg("manifest");
const PROBLEM = arg("problem");
const SOLUTION = arg("solution");
const FUND = arg("fund", null);        // ETH string, e.g. "0.003"
const CLOSE = arg("close", false);
const DA_DIR = arg("da-dir", null);    // off-chain content-addressed store dir (REQUIRED for off-chain-DA problems; optional mirror otherwise)
const ARWEAVE = arg("arweave", false); // OPTIONAL: mirror/store the solution on live Arweave (Irys devnet). Only needed as an off-chain store for off-chain-DA problems; a mirror otherwise. The on-chain anchor is always sha256(bytes), never the txid.
const FORCE = arg("force", false);     // adversarial test: submit even if the local verifier says invalid
const IMPROVEMENT_OVERRIDE = arg("improvement", null); // adversarial test: claim an inflated improvement
const SUBMIT_ONLY = arg("submit-only", false);         // stop after reveal (leave it for the operator to challenge)
const REPO_ROOT = resolve(arg("repo-root", resolve(HERE, "..")));
if (!MANIFEST || !PROBLEM || !SOLUTION) {
  console.error("required: --manifest <path> --problem <dir> --solution <file>");
  process.exit(2);
}
const KEY = process.env.AGENT_PRIVATE_KEY;
if (!KEY) { console.error("set AGENT_PRIVATE_KEY"); process.exit(2); }

const log = (...a) => console.log(...a);
const abi = (name) => JSON.parse(readFileSync(`${REPO_ROOT}/contracts/artifacts/src/${name}.sol/${name}.json`, "utf8")).abi;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const manifest = JSON.parse(readFileSync(resolve(MANIFEST), "utf8"));
const provider = new ethers.JsonRpcProvider(RPC);
const wallet = new ethers.Wallet(KEY, provider);
const solver = wallet.address;

const pool = new ethers.Contract(manifest.contracts.pool.address, abi("P42BountyPool"), wallet);
const ledger = new ethers.Contract(manifest.contracts.ledger.address, abi("P42PayoutLedger"), wallet);
const subs = new ethers.Contract(manifest.contracts.submissions.address, abi("P42SubmissionManager"), wallet);

const receipts = [];
async function send(label, txPromise) {
  const tx = await txPromise;
  const rec = await tx.wait();
  receipts.push({ label, hash: tx.hash, status: rec.status });
  log(`  ${label}: ${tx.hash} (status ${rec.status})`);
  return rec;
}

async function main() {
  log(`P42 autonomous solver — agent ${solver}`);
  log(`network: ${RPC}  manifest: ${MANIFEST}`);
  log(`balance: ${ethers.formatEther(await provider.getBalance(solver))} ETH\n`);

  // 0. self-verify (an honest solver aborts on an invalid solution; --force submits anyway)
  const verdict = runVerifier(PROBLEM, SOLUTION, REPO_ROOT);
  log(`[0] self-verify: valid=${verdict.valid} improvement=${verdict.improvement} score=${verdict.score}`);
  if (!verdict.valid && !FORCE) { log("solution is not valid per the local verifier — aborting (use --force to submit anyway)."); process.exit(1); }
  const claimedImprovement = IMPROVEMENT_OVERRIDE || verdict.improvement;
  const improvementAtoms = atomsFromImprovement(claimedImprovement);
  if (improvementAtoms <= 0n) { log("claimed improvement is zero — nothing to submit."); process.exit(1); }
  if (!verdict.valid) log("  [--force] submitting an INVALID solution (adversarial test — expect the operator to challenge).");
  if (IMPROVEMENT_OVERRIDE) log(`  [--improvement] claiming ${IMPROVEMENT_OVERRIDE} vs true ${verdict.improvement}.`);
  const claimedScoreAtoms = 0n; // informational; score is carried in the DA'd solution

  // Read the SAME file bytes that will be revealed — never re-serialize; their
  // sha256 IS the on-chain content anchor and must match the revealed bytes exactly.
  const solutionBytes = readFileSync(resolve(SOLUTION));
  const cid = "sha256:" + ethers.sha256(solutionBytes).slice(2);
  // The on-chain commitDaHash is the content ANCHOR: sha256 of the raw bytes as
  // a bytes32. It equals the CID digest (commitDaHash === ethers.sha256(bytes)).
  const daHash = ethers.sha256(solutionBytes);

  // DA mode is a property of the deployed problem contract.
  const onchainDa = await subs.onchainDa();

  let arweave = null;
  let mirrorReceiptHash = ethers.ZeroHash; // optional off-chain-mirror receipt, recorded at finalize if a mirror is written
  if (onchainDa) {
    // On-chain-at-reveal DA: the raw bytes ride the reveal-tx calldata, provably
    // bound to commitDaHash by the contract's sha256 check. No external DA needed.
    const maxBytes = await subs.maxSolutionBytes();
    if (BigInt(solutionBytes.length) > maxBytes) {
      log(`solution is ${solutionBytes.length} bytes > on-chain max ${maxBytes} — this problem cannot carry its bytes on-chain. Aborting.`);
      process.exit(1);
    }
    log(`  DA: on-chain-at-reveal — ${solutionBytes.length} bytes ride the tx (max ${maxBytes}); anchor sha256=${daHash.slice(0, 18)}…`);
    // --arweave / --da-dir are OPTIONAL mirrors here (belt-and-suspenders), never required.
    if (ARWEAVE) {
      log("  DA(mirror): uploading OPTIONAL Arweave mirror (Irys devnet)…");
      const up = await uploadToArweave(solutionBytes, {});
      arweave = { txid: up.txid, url: up.url, network: up.network };
      mirrorReceiptHash = up.txidBytes32; // record the mirror receipt at finalize
      log(`  DA(mirror): on Arweave — ${up.url}`);
    }
    if (DA_DIR) { putBlob(DA_DIR, solutionBytes); log(`  DA(mirror): wrote OPTIONAL local mirror to ${DA_DIR}`); }
  } else {
    // Off-chain-DA problem (large certificate): bytes exceed calldata limits, so
    // the solver MUST make them retrievable off-chain, content-addressed by the
    // same on-chain sha256 anchor. reveal then carries empty bytes ("0x").
    if (!ARWEAVE && !DA_DIR) {
      log("this problem uses off-chain DA (onchainDa=false) — you MUST provide an off-chain store: pass --da-dir <dir> and/or --arweave. Aborting.");
      process.exit(1);
    }
    if (ARWEAVE) {
      log("  DA: uploading solution to Arweave (Irys devnet)…");
      const up = await uploadToArweave(solutionBytes, {});
      arweave = { txid: up.txid, url: up.url, network: up.network };
      mirrorReceiptHash = up.txidBytes32; // record the Arweave receipt at finalize
      log(`  DA: on Arweave — txid ${up.txid}`);
      log(`      ${up.url}`);
    }
    if (DA_DIR) { putBlob(DA_DIR, solutionBytes); log(`  DA: posted solution blob to local store ${DA_DIR}`); }
    log(`  DA: off-chain store gated by on-chain sha256 anchor ${daHash.slice(0, 18)}… (fetchers verify sha256(bytes)==anchor)`);
  }
  const salt = "p42-agent-" + Date.now().toString();

  // 1. optional: sponsor-fund the pool so there is a payout to collect
  if (FUND) {
    log(`\n[1] fund pool with ${FUND} ETH (demo sponsor)`);
    await send("pool.fund", pool.fund({ value: ethers.parseEther(String(FUND)) }));
  }

  // 2. commit (bind CID + DA hash in the preimage; pay the posting bond)
  const commitment = await subs["computeCommitment(string,address,bytes32,string)"](cid, solver, daHash, salt);
  const bond = await subs.requiredPostingBondNow();
  log(`\n[2] commit  cid=${cid.slice(0, 16)}…  bond=${ethers.formatEther(bond)} ETH`);
  await send("commit", subs.commit(commitment, daHash, { value: bond }));
  const submissionId = await subs.submissionCount();
  log(`  submissionId=${submissionId}`);

  // 3. reveal (open the salt; publish CID + claimed improvement).
  //    on-chain-DA: pass the RAW solution bytes (contract enforces sha256==anchor
  //    & length<=max). off-chain-DA: pass empty "0x" (bytes live in the store).
  const revealBytes = onchainDa ? solutionBytes : "0x";
  log(`\n[3] reveal  improvementAtoms=${improvementAtoms}  bytes=${onchainDa ? solutionBytes.length + " on-chain" : "0x (off-chain DA)"}`);
  await send("reveal", subs.reveal(submissionId, cid, claimedScoreAtoms, improvementAtoms, salt, revealBytes));

  if (SUBMIT_ONLY) {
    log(`\n[submit-only] committed + revealed (submission #${submissionId}); exiting before finalize.`);
    if (arweave) log(`solution on Arweave: ${arweave.url}`);
    log(`final balance: ${ethers.formatEther(await provider.getBalance(solver))} ETH`);
    return;
  }

  // 4. wait out the challenge window
  const sub = await subs.submissions(submissionId);
  const endsAt = Number(sub.challengeEndsAt);
  log(`\n[4] challenge window until ${new Date(endsAt * 1000).toISOString()} — polling…`);
  for (;;) {
    const now = Number((await provider.getBlock("latest")).timestamp);
    if (now >= endsAt) break;
    log(`    now ${now} < endsAt ${endsAt}  (waiting ${endsAt - now}s)`);
    await sleep(Math.min(15000, (endsAt - now) * 1000 + 3000));
  }

  // 5. finalize (records credit). permanenceHash is OPTIONAL: pass ZeroHash
  //    normally; pass the off-chain-mirror receipt only if a mirror was written.
  log(`\n[5] finalize${mirrorReceiptHash !== ethers.ZeroHash ? "  (recording off-chain-mirror receipt)" : ""}`);
  await send("finalize", subs.finalize(submissionId, mirrorReceiptHash));

  // 6. optional: owner closes the pool (demo: owner == agent). In production this is a governance action.
  if (CLOSE) {
    log(`\n[6] close pool (owner)`);
    await send("ledger.close", ledger.close());
  } else {
    log(`\n[6] skip close (pass --close to owner-close in the demo)`);
  }

  // 7. claim payout + 8. reclaim posting bond
  const claimableBefore = await ledger.claimable(solver);
  log(`\n[7] claim payout  claimable=${ethers.formatEther(claimableBefore)} ETH`);
  if (claimableBefore > 0n) await send("claim", pool.claim());
  else log("  nothing claimable yet (pool not closed?) — run again after close.");

  const bondClaimable = await subs.claimableBondWei(solver);
  if (bondClaimable > 0n) {
    log(`\n[8] reclaim posting bond  ${ethers.formatEther(bondClaimable)} ETH`);
    await send("claimBond", subs.claimBond());
  }

  log(`\n=== DONE ===`);
  if (arweave) log(`solution on Arweave: ${arweave.url}`);
  log(`final balance: ${ethers.formatEther(await provider.getBalance(solver))} ETH`);
  log(`txs:`);
  for (const r of receipts) log(`  ${r.label.padEnd(14)} ${r.hash}`);
}

main().catch((e) => { console.error("FAILED:", e.shortMessage || e.message); process.exit(1); });
