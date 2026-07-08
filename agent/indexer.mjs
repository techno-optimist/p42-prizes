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
//     [--rpc https://sepolia.base.org] [--out state.json] [--archive <dir>]
//
// --archive <dir>  Durable content-addressed CALLDATA ARCHIVE. For every
//   Revealed event that posted on-chain solution bytes (solutionBytesLength>0),
//   fetch the reveal tx, parse its calldata back to `solution`, VERIFY
//   sha256(solution) == the submission's on-chain commitDaHash anchor, and
//   persist the raw bytes to <dir>/<cid>.bin plus a manifest entry. This
//   rehydrates the >18-day later-Δ tail from tx calldata so the record survives
//   L1 blob pruning. Off-chain-DA reveals (solutionBytesLength==0) are annotated
//   in the manifest as living in an off-chain store, not fetched. Idempotent:
//   already-archived CIDs are skipped on re-run.

import { ethers } from "ethers";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i === -1 ? d : process.argv[i + 1]; };
const REPO_ROOT = resolve(HERE, "..");
const abi = (n) => JSON.parse(readFileSync(`${REPO_ROOT}/contracts/artifacts/src/${n}.sol/${n}.json`, "utf8")).abi;

const MANIFEST = arg("manifest");
const RPC = arg("rpc", "https://sepolia.base.org");
const OUT = arg("out", null);
const ARCHIVE = arg("archive", null);
if (!MANIFEST) { console.error("required: --manifest <path>"); process.exit(2); }

const manifest = JSON.parse(readFileSync(resolve(MANIFEST), "utf8"));
const provider = new ethers.JsonRpcProvider(RPC, Number(manifest.network?.chainId ?? 84532), { staticNetwork: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const c = manifest.contracts;
const pool = new ethers.Contract(c.pool.address, abi("P42BountyPool"), provider);
const ledger = new ethers.Contract(c.ledger.address, abi("P42PayoutLedger"), provider);
const subs = new ethers.Contract(c.submissions.address, abi("P42SubmissionManager"), provider);
const chal = new ethers.Contract(c.challenges.address, abi("P42ChallengeManager"), provider);
// The registry only supplies problem metadata for the state output; the
// settlement reconstruction and the calldata archive run off the core
// contracts' events, so a manifest without a registry is still fully indexable.
const registry = c.registry ? new ethers.Contract(c.registry.address, abi("P42ProblemRegistry"), provider) : null;

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

// Map a CID ("sha256:<hex>") to a safe, collision-free filename. The CID is the
// content address, so the filename is deterministic and self-describing.
function cidToFilename(cid) {
  return cid.replace(/[^a-zA-Z0-9._-]/g, "_") + ".bin";
}

// Durable content-addressed CALLDATA ARCHIVE.
//
// For each Revealed event we recover the solution bytes from the reveal tx
// calldata and pin them under <dir>, keyed by their CID, with a manifest entry.
// The bytes are only persisted after sha256(solution) is checked against the
// submission's on-chain `commitDaHash` anchor — so the archive is exactly as
// trustworthy as the chain, and any mismatch is surfaced loudly. Off-chain-DA
// reveals carry no bytes and are annotated (not fetched). Idempotent: a CID that
// is already on disk is not re-fetched.
async function archiveCalldata(dir, reveals) {
  const outDir = resolve(dir);
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  const manifestPath = `${outDir}/manifest.json`;

  // Load any prior manifest so idempotent re-runs preserve/reuse existing entries.
  const prior = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, "utf8")) : { entries: [] };
  const priorByCid = {};
  for (const e of prior.entries ?? []) priorByCid[e.cid] = e;

  const entries = [];
  const mismatches = [];
  let archived = 0, skipped = 0, offChain = 0;

  // stable on-chain order
  const ordered = [...reveals].sort((a, b) => a.blockNumber - b.blockNumber || a.index - b.index);
  for (const ev of ordered) {
    const submissionId = ev.args.submissionId.toString();
    const cid = ev.args.solutionCid;
    const byteLen = BigInt(ev.args.solutionBytesLength);

    // Off-chain-DA submission: no calldata bytes to pin; annotate and move on.
    if (byteLen === 0n) {
      offChain++;
      entries.push({ submissionId, cid, anchor: null, byteLength: 0, revealTxHash: ev.transactionHash, store: "off-chain" });
      continue;
    }

    const filePath = `${outDir}/${cidToFilename(cid)}`;

    // The independent, chain-derived truth we validate the calldata against.
    // Fetched BEFORE the idempotency check: an already-pinned file must be
    // re-verified against this anchor too, or tampered/bit-rotted bytes would
    // pass a re-run with mismatches=0.
    const anchor = (await subs.submissions(ev.args.submissionId)).commitDaHash;

    // Idempotent: already pinned -> re-hash the on-disk bytes against the
    // on-chain anchor (and byte length). Only verified bytes skip the fetch;
    // a mismatch is surfaced AND the bytes are re-fetched from calldata below.
    // Entries are rebuilt with the verified anchor — never anchor:null — so
    // every on-chain-calldata manifest entry carries its integrity commitment.
    if (existsSync(filePath)) {
      const onDisk = readFileSync(filePath);
      const diskHash = ethers.sha256(onDisk);
      if (diskHash === anchor && BigInt(onDisk.length) === byteLen) {
        skipped++;
        entries.push({ submissionId, cid, anchor, byteLength: onDisk.length, revealTxHash: ev.transactionHash, store: "on-chain-calldata" });
        continue;
      }
      mismatches.push({ submissionId, cid, anchor, computed: diskHash, reason: `ARCHIVE TAMPER/ROT: on-disk bytes (sha256=${diskHash}, len=${onDisk.length}) do not match anchor/event (len=${byteLen}) — re-fetching from calldata` });
      // fall through: re-fetch from the reveal tx and overwrite the bad file
    }

    const tx = await provider.getTransaction(ev.transactionHash);
    if (!tx) { mismatches.push({ submissionId, cid, reason: "reveal tx not found" }); continue; }
    let parsed;
    try { parsed = subs.interface.parseTransaction({ data: tx.data, value: tx.value }); }
    catch (e) { mismatches.push({ submissionId, cid, reason: `unparseable calldata: ${e.shortMessage || e.message}` }); continue; }
    if (parsed?.name !== "reveal") { mismatches.push({ submissionId, cid, reason: `tx is not a reveal (${parsed?.name})` }); continue; }

    const solution = parsed.args.solution; // "0x..." hex from the reveal calldata
    const got = ethers.sha256(solution);
    const derivedCid = "sha256:" + got.slice(2);

    // sha256(solution) MUST equal the on-chain anchor; the CID must be consistent too.
    if (got !== anchor || derivedCid !== cid) {
      mismatches.push({ submissionId, cid, anchor, computed: got, derivedCid, reason: "ANCHOR MISMATCH: sha256(solution) != on-chain commitDaHash" });
      continue;
    }

    const bytes = ethers.getBytes(solution);
    if (BigInt(bytes.length) !== byteLen) {
      mismatches.push({ submissionId, cid, reason: `byte-length mismatch: calldata=${bytes.length} event=${byteLen}` });
      continue;
    }

    writeFileSync(filePath, bytes);
    archived++;
    entries.push({ submissionId, cid, anchor, byteLength: bytes.length, revealTxHash: ev.transactionHash, store: "on-chain-calldata" });
  }

  const manifest = {
    schema: "p42-calldata-archive/v1",
    dir: outDir,
    updatedAt: new Date().toISOString(),
    summary: { archived, skipped, offChain, mismatches: mismatches.length, total: entries.length },
    entries,
    mismatches,
  };
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");

  console.log(`  calldata archive -> ${outDir}`);
  console.log(`    ${archived} archived, ${skipped} already-pinned, ${offChain} off-chain-store, ${entries.length} manifest entries`);
  if (mismatches.length) {
    console.error(`  !!! ${mismatches.length} ANCHOR-MISMATCH / archive error(s) — ARCHIVE NOT TRUSTWORTHY:`);
    for (const m of mismatches) console.error(`      submission ${m.submissionId} cid=${m.cid}: ${m.reason}`);
  }
  return { ok: mismatches.length === 0, archived, skipped, offChain, mismatches };
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
  const registered = registry ? await queryChunked(registry, registry.filters.ProblemRegistered(), fromBlock, toBlock) : [];

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

  // frontier = finalized submissions in on-chain order. Since the F1 redesign,
  // Finalized carries the MARGINAL creditAtoms (0 for a superseded submission
  // that finalized behind the live frontier), the absolute claimedScoreAtoms,
  // and the resulting bestScoreAtoms. Cumulative credit sums the marginals
  // (== seed - final best), so a share is creditAtoms_i / SigmaCreditAtoms.
  const frontier = [];
  let cumulative = 0n;
  for (const e of finals.sort((a, b) => a.blockNumber - b.blockNumber || a.index - b.index)) {
    cumulative += e.args.creditAtoms;
    frontier.push({
      submissionId: e.args.submissionId.toString(),
      solver: e.args.solver,
      creditAtoms: e.args.creditAtoms.toString(),
      claimedScoreAtoms: e.args.claimedScoreAtoms.toString(),
      bestScoreAtoms: e.args.bestScoreAtoms.toString(),
      cumulativeCreditAtoms: cumulative.toString(),
    });
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

  // Optional: durable content-addressed calldata archive of the on-chain solution bytes.
  let archiveOk = true;
  if (ARCHIVE) {
    const res = await archiveCalldata(ARCHIVE, reveals);
    archiveOk = res.ok;
    state.calldata_archive = { dir: resolve(ARCHIVE), ...res, mismatches: res.mismatches.length };
  }

  if (OUT) { writeFileSync(resolve(OUT), JSON.stringify(state, null, 2) + "\n"); console.log(`  wrote ${OUT}`); }
  process.exit(ok && archiveOk ? 0 : 1);
}
main().catch((e) => { console.error("FAILED:", e.shortMessage || e.message); process.exit(1); });
