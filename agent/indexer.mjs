#!/usr/bin/env node
// P42 on-chain indexer (Gate-2 plumbing).
//
// Reconstructs the full protocol state — problems, pool funding, the submission
// lifecycle, the improvement FRONTIER, and the PAYOUT LEDGER (who is owed/paid
// what) — purely from on-chain EVENTS, then cross-checks the reconstruction
// against each contract's own view. If the checks pass, an independent party can
// rebuild the exact settlement state from the chain alone (no trusted server).
//
// Usage:
//   node indexer.mjs --manifest ../deployments/base-sepolia/<manifest>.json \
//     [--rpc https://sepolia.base.org] [--out state.json]

import { ethers } from "ethers";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i === -1 ? d : process.argv[i + 1]; };
const REPO_ROOT = resolve(HERE, "..");
const abi = (n) => JSON.parse(readFileSync(`${REPO_ROOT}/contracts/artifacts/src/${n}.sol/${n}.json`, "utf8")).abi;

const MANIFEST = arg("manifest");
const RPC = arg("rpc", "https://sepolia.base.org");
const OUT = arg("out", null);
if (!MANIFEST) { console.error("required: --manifest <path>"); process.exit(2); }

const manifest = JSON.parse(readFileSync(resolve(MANIFEST), "utf8"));
const provider = new ethers.JsonRpcProvider(RPC, Number(manifest.network?.chainId ?? 84532), { staticNetwork: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const c = manifest.contracts;
const pool = new ethers.Contract(c.pool.address, abi("P42BountyPool"), provider);
const ledger = new ethers.Contract(c.ledger.address, abi("P42PayoutLedger"), provider);
const subs = new ethers.Contract(c.submissions.address, abi("P42SubmissionManager"), provider);
const chal = new ethers.Contract(c.challenges.address, abi("P42ChallengeManager"), provider);
const registry = new ethers.Contract(c.registry.address, abi("P42ProblemRegistry"), provider);

const STATUS = ["None", "Committed", "Revealed", "Challenged", "Finalized", "Rejected"];

// Public RPCs cap getLogs block ranges and rate-limit; page through small
// windows SEQUENTIALLY with retries and aggregate.
async function queryChunked(contract, filter, from, to, step = 2000) {
  const out = [];
  for (let start = from; start <= to; start += step) {
    const end = Math.min(start + step - 1, to);
    let lastErr;
    for (let attempt = 0; attempt < 5; attempt++) {
      try { out.push(...(await contract.queryFilter(filter, start, end))); lastErr = null; break; }
      catch (e) { lastErr = e; await sleep(1200 * (attempt + 1)); }
    }
    if (lastErr) throw lastErr;
  }
  return out;
}

async function main() {
  const fromBlock = Number(manifest.indexer?.startBlock ?? 0);
  const toBlock = await provider.getBlockNumber();

  // sequential (one paged scan at a time) to stay under public-RPC rate limits
  const funded = await queryChunked(pool, pool.filters.Funded(), fromBlock, toBlock);
  const claimed = await queryChunked(pool, pool.filters.Claimed(), fromBlock, toBlock);
  const credits = await queryChunked(ledger, ledger.filters.CreditRecorded(), fromBlock, toBlock);
  const closed = await queryChunked(ledger, ledger.filters.Closed(), fromBlock, toBlock);
  const reveals = await queryChunked(subs, subs.filters.Revealed(), fromBlock, toBlock);
  const finals = await queryChunked(subs, subs.filters.Finalized(), fromBlock, toBlock);
  const challenged = await queryChunked(subs, subs.filters.SubmissionChallenged(), fromBlock, toBlock);
  const resolved = await queryChunked(subs, subs.filters.SubmissionChallengeResolved(), fromBlock, toBlock);
  const registered = await queryChunked(registry, registry.filters.ProblemRegistered(), fromBlock, toBlock);

  // --- reconstruct from events alone ---
  const idxFunded = funded.reduce((t, e) => t + e.args.amount, 0n);
  const idxClaimed = claimed.reduce((t, e) => t + e.args.amount, 0n);
  const creditBySolver = {};
  for (const e of credits) creditBySolver[e.args.solver] = (creditBySolver[e.args.solver] ?? 0n) + e.args.atoms;
  const idxTotalCredit = Object.values(creditBySolver).reduce((t, v) => t + v, 0n);
  const closeEvt = closed.length ? closed[closed.length - 1] : null;
  const idxClosed = closeEvt !== null;
  const idxClosedPool = closeEvt ? closeEvt.args.poolBalance : 0n;
  const idxFeeReserve = closeEvt ? closeEvt.args.feeReserve : 0n;
  const distributable = idxClosed ? idxClosedPool - idxFeeReserve : 0n;

  // frontier = finalized improvements, in on-chain order
  const frontier = [];
  let cumulative = 0n;
  for (const e of finals.sort((a, b) => a.blockNumber - b.blockNumber || a.index - b.index)) {
    cumulative += e.args.improvementAtoms;
    frontier.push({ submissionId: e.args.submissionId.toString(), solver: e.args.solver, improvementAtoms: e.args.improvementAtoms.toString(), cumulativeAtoms: cumulative.toString() });
  }

  // payout ledger (reconstructed): finalEntitlement = distributable * credit / total
  const claimedBySolver = {};
  for (const e of claimed) claimedBySolver[e.args.solver] = (claimedBySolver[e.args.solver] ?? 0n) + e.args.amount;
  const payoutLedger = Object.entries(creditBySolver).map(([solver, credit]) => {
    const entitlement = idxClosed && idxTotalCredit > 0n ? (distributable * credit) / idxTotalCredit : 0n;
    const paid = claimedBySolver[solver] ?? 0n;
    return {
      solver,
      creditAtoms: credit.toString(),
      sharePct: idxTotalCredit > 0n ? Number((credit * 10000n) / idxTotalCredit) / 100 : 0,
      finalEntitlementWei: entitlement.toString(),
      claimedWei: paid.toString(),
      claimableWei: (entitlement > paid ? entitlement - paid : 0n).toString(),
    };
  });

  // --- cross-check the reconstruction against each contract's own view ---
  const [cFunded, cClaimed, cTotalCredit, cClosed, cClosedPool, cFeeReserve] = await Promise.all([
    pool.totalFunded(), pool.totalClaimed(), ledger.totalCreditAtoms(), ledger.closed(), ledger.closedPoolBalance(), ledger.feeReserve(),
  ]);
  const checks = [];
  const chk = (name, a, b) => checks.push({ name, ok: a === b, indexer: a.toString?.() ?? String(a), chain: b.toString?.() ?? String(b) });
  chk("pool.totalFunded", idxFunded, cFunded);
  chk("pool.totalClaimed", idxClaimed, cClaimed);
  chk("ledger.totalCreditAtoms", idxTotalCredit, cTotalCredit);
  chk("ledger.closed", idxClosed, cClosed);
  chk("ledger.closedPoolBalance", idxClosedPool, cClosedPool);
  chk("ledger.feeReserve", idxFeeReserve, cFeeReserve);
  for (const [solver, credit] of Object.entries(creditBySolver)) {
    chk(`ledger.creditAtomsOf(${solver.slice(0, 8)})`, credit, await ledger.creditAtomsOf(solver));
    chk(`ledger.finalEntitlement(${solver.slice(0, 8)})`, (idxClosed && idxTotalCredit > 0n ? (distributable * credit) / idxTotalCredit : 0n), await ledger.finalEntitlement(solver));
    chk(`ledger.claimedWeiOf(${solver.slice(0, 8)})`, (claimedBySolver[solver] ?? 0n), await ledger.claimedWeiOf(solver));
  }
  const ok = checks.every((c) => c.ok);

  const state = {
    schema: "p42-indexer-state/v1",
    manifest: MANIFEST,
    network: { chainId: manifest.network?.chainId, fromBlock, toBlock },
    problems: registered.map((e) => ({ problemId: e.args.problemId.toString(), pool: e.args.pool })),
    pool: { funded: idxFunded.toString(), claimed: idxClaimed.toString(), balance: (await provider.getBalance(c.pool.address)).toString() },
    ledger: { closed: idxClosed, closedPoolBalance: idxClosedPool.toString(), feeReserve: idxFeeReserve.toString(), totalCreditAtoms: idxTotalCredit.toString(), distributableWei: distributable.toString() },
    counts: { funded: funded.length, revealed: reveals.length, finalized: finals.length, challenged: challenged.length, resolved: resolved.length, credits: credits.length, claimed: claimed.length },
    frontier,
    payout_ledger: payoutLedger,
    reconstruction: { ok, checks },
  };

  console.log(`indexed ${MANIFEST}  blocks ${fromBlock}..${toBlock}`);
  console.log(`  funded=${ethers.formatEther(idxFunded)} claimed=${ethers.formatEther(idxClaimed)} closed=${idxClosed} totalCreditAtoms=${idxTotalCredit}`);
  console.log(`  frontier: ${frontier.length} finalized;  payout ledger: ${payoutLedger.length} solver(s)`);
  for (const r of payoutLedger) console.log(`    ${r.solver}  ${r.sharePct}%  entitlement=${ethers.formatEther(r.finalEntitlementWei)} claimed=${ethers.formatEther(r.claimedWei)}`);
  console.log(`  reconstruction vs chain: ${ok ? "OK" : "MISMATCH"} (${checks.filter((c) => c.ok).length}/${checks.length} checks)`);
  if (!ok) for (const c of checks.filter((c) => !c.ok)) console.log(`    MISMATCH ${c.name}: indexer=${c.indexer} chain=${c.chain}`);

  if (OUT) { writeFileSync(resolve(OUT), JSON.stringify(state, null, 2) + "\n"); console.log(`  wrote ${OUT}`); }
  process.exit(ok ? 0 : 1);
}
main().catch((e) => { console.error("FAILED:", e.shortMessage || e.message); process.exit(1); });
