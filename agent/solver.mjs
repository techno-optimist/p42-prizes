#!/usr/bin/env node
// Persistent P42 solver lifecycle: self-check -> commit -> reveal -> survive
// challenge/rearm/top-up/restart -> finalize -> close/claim -> reclaim bond.

import { ethers } from "ethers";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildSignedTransactionRecord,
  chainScoreAtoms,
  problemRunnerConfig,
  problemObjective,
  runVerifier,
  seedRelativeImprovementAtoms,
  sha256Canonical,
  solverLifecycleDecision,
  submissionIdFromCommittedReceipt,
} from "./lib.mjs";
import {
  manifestProblemContracts,
  manifestProblemForRegistryId,
} from "./indexer.mjs";
import { putBlob } from "./da-local.mjs";
import { uploadToArweave } from "./da-arweave.mjs";
import { assertSignedTransactionRecord } from "./signed-transaction.mjs";
import { validateSolverManifest } from "./solver-manifest.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

const JSON_LIMITS = Object.freeze({ maxBytes: 4 * 1024 * 1024, maxDepth: 64 });

const HERE = dirname(fileURLToPath(import.meta.url));
function arg(name, def = undefined) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return def;
  const value = process.argv[i + 1];
  return value && !value.startsWith("--") ? value : true;
}

const RPC = arg("rpc", "https://sepolia.base.org");
const MANIFEST = arg("manifest");
const PROBLEM = arg("problem");
const SOLUTION = arg("solution");
const REGISTRY_PROBLEM_ID = arg("registry-problem-id", null);
const FUND = arg("fund", null);
const CLOSE = arg("close", false);
const DONATE_WINNINGS_TO_POOL = arg("donate-winnings-to-pool", null);
const DA_DIR = arg("da-dir", null);
const ARWEAVE = arg("arweave", false);
const FORCE = arg("force", false);
const LEGACY_IMPROVEMENT_OVERRIDE = arg("improvement", null);
const SCORE_ATOMS_OVERRIDE = arg("claim-score-atoms", null);
const SUBMIT_ONLY = arg("submit-only", false);
const STATE_ARG = arg("state", null);
const POLL_MS = Number(arg("poll-ms", "15000"));
const MAX_CONSECUTIVE_ERRORS = Number(arg("max-consecutive-errors", "12"));
const REPO_ROOT = resolve(arg("repo-root", resolve(HERE, "..")));

if (!MANIFEST || !PROBLEM || !SOLUTION) {
  console.error("required: --manifest <path> --problem <dir> --solution <file> [--registry-problem-id <id>]");
  process.exit(2);
}
if (LEGACY_IMPROVEMENT_OVERRIDE !== null) {
  console.error("--improvement is disabled; improvementAtoms is derived from the immutable on-chain seed");
  process.exit(2);
}
if (!Number.isInteger(MAX_CONSECUTIVE_ERRORS) || MAX_CONSECUTIVE_ERRORS < 1 || POLL_MS < 0) {
  console.error("--max-consecutive-errors must be positive and --poll-ms must be non-negative");
  process.exit(2);
}
if (DONATE_WINNINGS_TO_POOL !== null && !ethers.isAddress(DONATE_WINNINGS_TO_POOL)) {
  console.error("--donate-winnings-to-pool must be a valid P42 pool address");
  process.exit(2);
}
const KEY = process.env.AGENT_PRIVATE_KEY;
if (!KEY) {
  console.error("set AGENT_PRIVATE_KEY");
  process.exit(2);
}

const log = (...values) => console.log(...values);
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const abi = (name) => JSON.parse(
  readFileSync(`${REPO_ROOT}/contracts/artifacts/src/${name}.sol/${name}.json`, "utf8"),
).abi;
const manifest = readStrictJsonFileSync(resolve(MANIFEST), JSON_LIMITS);
validateSolverManifest(manifest, REGISTRY_PROBLEM_ID);
const manifestProblem = REGISTRY_PROBLEM_ID
  ? manifestProblemForRegistryId(manifest, REGISTRY_PROBLEM_ID)
  : manifest.problems?.[0] ?? null;
const boardContracts = manifestProblem
  ? manifestProblemContracts(manifest, manifestProblem)
  : manifest.contracts;
const donationDestination = DONATE_WINNINGS_TO_POOL === null
  ? null
  : ethers.getAddress(DONATE_WINNINGS_TO_POOL);
if (donationDestination !== null) {
  const registeredPools = new Set((manifest.problems ?? []).map((problem) =>
    ethers.getAddress(manifestProblemContracts(manifest, problem).pool.address)
  ));
  if (!registeredPools.has(donationDestination)) {
    console.error("--donate-winnings-to-pool must name a pool in the validated deployment manifest");
    process.exit(2);
  }
}
const provider = new ethers.JsonRpcProvider(RPC);
const wallet = new ethers.Wallet(KEY, provider);
const solver = wallet.address;
const pool = new ethers.Contract(boardContracts.pool.address, abi("P42BountyPool"), wallet);
const ledger = new ethers.Contract(boardContracts.ledger.address, abi("P42PayoutLedger"), wallet);
const subs = new ethers.Contract(boardContracts.submissions.address, abi("P42SubmissionManager"), wallet);
const chal = new ethers.Contract(boardContracts.challenges.address, abi("P42ChallengeManager"), wallet);
const donationPool = donationDestination === null
  ? null
  : new ethers.Contract(donationDestination, abi("P42BountyPool"), wallet);
const DONATION_FALLBACK_WINDOW_SECONDS = 24n * 60n * 60n;

async function donationDestinationReady(valueWei, now) {
  if (donationPool === null) return false;
  const [accepting, funded, cap, destinationLedgerAddress, destinationManagerAddress] = await Promise.all([
    donationPool.acceptingFunds(),
    donationPool.funded(),
    donationPool.fundingCap(),
    donationPool.ledger(),
    donationPool.submissionManager(),
  ]);
  if (!accepting || funded + valueWei > cap) return false;
  const destinationLedger = new ethers.Contract(destinationLedgerAddress, abi("P42PayoutLedger"), provider);
  const destinationManager = new ethers.Contract(destinationManagerAddress, abi("P42SubmissionManager"), provider);
  const [closed, fundingDeadline, armed, authorizationExpiresAt] = await Promise.all([
    destinationLedger.closed(),
    destinationLedger.fundingDeadline(),
    destinationManager.fundingArmed(),
    destinationManager.fundingAuthorizationExpiresAt(),
  ]);
  return !closed && armed && now <= fundingDeadline && now <= authorizationExpiresAt;
}

let state;
let statePath;

function persistState() {
  state.updated_at_utc = new Date().toISOString();
  const temporary = `${statePath}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  renameSync(temporary, statePath);
}

function loadState(identity, defaultPath) {
  statePath = resolve(STATE_ARG || defaultPath);
  mkdirSync(dirname(statePath), { recursive: true });
  if (!existsSync(statePath)) {
    state = {
      schema_version: "p42-solver-state/v1",
      ...identity,
      salt: `p42-agent-${Date.now()}`,
      submission_id: null,
      phase: "initialized",
      transactions: {},
      arweave: null,
      mirror_receipt_hash: ethers.ZeroHash,
      close_requested: Boolean(CLOSE),
      fund_wei: FUND === null ? "0" : ethers.parseEther(String(FUND)).toString(),
      created_at_utc: new Date().toISOString(),
    };
    persistState();
    return;
  }
  state = readStrictJsonFileSync(statePath, JSON_LIMITS);
  if (state.schema_version !== "p42-solver-state/v1") throw new Error(`unsupported solver state: ${statePath}`);
  for (const [key, expected] of Object.entries(identity)) {
    if (state[key] !== expected) throw new Error(`solver state identity mismatch for ${key}: ${state[key]} != ${expected}`);
  }
  if (FUND !== null && state.fund_wei !== ethers.parseEther(String(FUND)).toString()) {
    throw new Error("--fund differs from the persisted solver state");
  }
  if (CLOSE && !state.close_requested) {
    state.close_requested = true;
    persistState();
  }
}

async function receiptFor(transaction, expectedRequest) {
  const checked = assertSignedTransactionRecord(transaction, {
    signer: wallet.address,
    chainId: manifest.network.chainId,
    to: expectedRequest.to,
    data: expectedRequest.data ?? "0x",
    value: expectedRequest.value ?? 0n,
    hash: transaction.hash,
    nonce: transaction.nonce,
    label: transaction.label,
  });
  const receipt = await provider.getTransactionReceipt(transaction.hash);
  if (receipt) return receipt;
  if (!transaction.raw_tx) {
    const pending = await provider.getTransaction(transaction.hash);
    if (!pending) throw new Error(`persisted transaction ${transaction.hash} is not retrievable yet`);
    return pending.wait();
  }

  let pending = await provider.getTransaction(transaction.hash);
  if (!pending) {
    try {
      pending = await provider.broadcastTransaction(checked.record.raw_tx);
    } catch (error) {
      pending = await provider.getTransaction(transaction.hash);
      if (!pending) throw error;
    }
  }
  if (transaction.status !== "broadcast") {
    transaction.status = "broadcast";
    transaction.broadcast_at_utc = new Date().toISOString();
    persistState();
    log(`  ${transaction.label || "tx"}: broadcast ${transaction.hash}`);
  }
  return pending.wait();
}

async function sendPersistent(label, requestFactory) {
  let record = state.transactions[label];
  if (record?.status === "reverted") {
    throw new Error(`${label} previously reverted (${record.hash}); refusing to replace deterministic nonce tx`);
  }
  const request = await requestFactory();
  if (!record) {
    record = {
      ...(await buildSignedTransactionRecord({ wallet, request, label })),
      status: "signed",
    };
    state.transactions[label] = record;
    persistState();
    log(`  ${label}: signed ${record.hash} nonce=${record.nonce}`);
  }

  assertSignedTransactionRecord(record, {
    signer: wallet.address,
    chainId: manifest.network.chainId,
    to: request.to,
    data: request.data ?? "0x",
    value: request.value ?? 0n,
    hash: record.hash,
    nonce: record.nonce,
    label,
  });

  const receipt = await receiptFor(record, request);
  if (!receipt || receipt.status !== 1) {
    state.transactions[label] = { ...record, status: "reverted", block_number: receipt?.blockNumber ?? null };
    persistState();
    throw new Error(`${label} reverted (${record.hash})`);
  }
  state.transactions[label] = {
    ...record,
    status: "confirmed",
    block_number: receipt.blockNumber,
    confirmed_at_utc: new Date().toISOString(),
  };
  persistState();
  log(`  ${label}: confirmed ${record.hash}`);
  return receipt;
}

async function latestTimestamp() {
  const block = await provider.getBlock("latest");
  if (!block) throw new Error("latest block is unavailable");
  return BigInt(block.timestamp);
}

async function prepareDataAvailability(solutionBytes, onchainDa) {
  if (onchainDa) {
    const maxBytes = await subs.maxSolutionBytes();
    if (BigInt(solutionBytes.length) > maxBytes) {
      throw new Error(`solution is ${solutionBytes.length} bytes, above on-chain cap ${maxBytes}`);
    }
    if (ARWEAVE && !state.arweave) {
      const upload = await uploadToArweave(solutionBytes, {});
      state.arweave = { txid: upload.txid, url: upload.url, network: upload.network };
      state.mirror_receipt_hash = upload.txidBytes32;
      persistState();
    }
    if (DA_DIR) putBlob(DA_DIR, solutionBytes);
    return;
  }
  if (!ARWEAVE && !DA_DIR && !state.arweave) {
    throw new Error("off-chain DA requires --da-dir or --arweave");
  }
  if (ARWEAVE && !state.arweave) {
    const upload = await uploadToArweave(solutionBytes, {});
    state.arweave = { txid: upload.txid, url: upload.url, network: upload.network };
    state.mirror_receipt_hash = upload.txidBytes32;
    persistState();
  }
  if (DA_DIR) putBlob(DA_DIR, solutionBytes);
}

async function bondShortfall(submissionId, submission) {
  const paid = await subs.paidAtCommit(submissionId);
  if (!paid) return 0n;
  const pendingCredit = await subs.pendingCreditAtoms(submissionId);
  if (pendingCredit === 0n) return 0n;
  const required = await subs.requiredPostingBondForPool(await pool.fundingCap());
  return required > submission.bondWei ? required - submission.bondWei : 0n;
}

async function lifecycleSnapshot(submissionId) {
  const submission = await subs.submissions(submissionId);
  const status = Number(submission.status);
  const now = await latestTimestamp();
  let challengeResolved = false;
  let decisionPending = false;
  let disputeEndsAt = 0n;
  let resolverBondReleaseAt = 0n;
  let challengeInstanceHash = ethers.ZeroHash;
  if (status === 3) {
    const challenge = await chal.challenges(submissionId);
    challengeInstanceHash = await chal.challengeInstanceHashOf(submissionId);
    challengeResolved = challenge.resolved;
    decisionPending = challenge.decisionPending;
    disputeEndsAt = BigInt(challenge.disputeEndsAt);
    if (decisionPending) {
      const resolverBond = await chal.resolverBonds(submissionId);
      resolverBondReleaseAt = BigInt(resolverBond.releaseAt);
    }
  }
  const ledgerClosed = await ledger.closed();
  return {
    status,
    now,
    challengeEndsAt: BigInt(submission.challengeEndsAt),
    challengeResolved,
    decisionPending,
    disputeEndsAt,
    resolverBondReleaseAt,
    challengeInstanceHash,
    bondShortfallWei: status === 2 && now >= BigInt(submission.challengeEndsAt)
      ? await bondShortfall(submissionId, submission)
      : 0n,
    bondClaimableWei: await subs.claimableBondWei(solver),
    ledgerClosed,
    closeRequested: state.close_requested,
    openSubmissionCount: ledgerClosed ? 0n : await subs.openSubmissionCount(),
    payoutClaimableWei: ledgerClosed ? await ledger.claimable(solver) : 0n,
    submission,
  };
}

async function runLifecycle(submissionId, revealArgs) {
  let consecutiveErrors = 0;
  for (;;) {
    try {
      const snapshot = await lifecycleSnapshot(submissionId);
      if (SUBMIT_ONLY && snapshot.status >= 2) {
        state.phase = "submit_only";
        persistState();
        return snapshot;
      }
      const decision = solverLifecycleDecision(snapshot);
      if (state.phase !== decision.action) {
        state.phase = decision.action;
        state.last_error = null;
        persistState();
        log(`  lifecycle -> ${decision.action} (status=${snapshot.status})`);
      }

      if (decision.action === "reveal") {
        await sendPersistent("reveal", () => subs.reveal.populateTransaction(...revealArgs));
      } else if (
        decision.action === "wait_challenge_window"
        || decision.action === "wait_resolution"
        || decision.action === "wait_resolution_finality"
      ) {
        const remainingMs = Number((decision.wakeAt - snapshot.now) * 1000n);
        await sleep(Math.min(POLL_MS, Math.max(250, remainingMs + 1000)));
      } else if (decision.action === "top_up_bond") {
        const label = `topUpBond:${snapshot.submission.bondWei}:${decision.valueWei}`;
        await sendPersistent(label, () => subs.topUpBond.populateTransaction(submissionId, { value: decision.valueWei }));
      } else if (decision.action === "finalize") {
        const label = `finalize:${snapshot.challengeEndsAt}`;
        await sendPersistent(label, () => subs.finalize.populateTransaction(submissionId, state.mirror_receipt_hash));
      } else if (decision.action === "expire_challenge") {
        const label = `expireChallenge:${snapshot.disputeEndsAt}:${snapshot.challengeInstanceHash}`;
        await sendPersistent(label, () => chal.expireChallenge.populateTransaction(submissionId, snapshot.challengeInstanceHash));
      } else if (decision.action === "finalize_resolution") {
        const label = `finalizeResolution:${snapshot.resolverBondReleaseAt}:${snapshot.challengeInstanceHash}`;
        await sendPersistent(
          label,
          () => chal.finalizeResolution.populateTransaction(submissionId, snapshot.challengeInstanceHash),
        );
      } else if (decision.action === "refresh_chain_state") {
        await sleep(Math.max(250, POLL_MS));
      } else if (decision.action === "claim_bond") {
        const label = `claimBond:${decision.valueWei}`;
        await sendPersistent(label, () => subs.claimBond.populateTransaction());
      } else if (decision.action === "close") {
        await sendPersistent("ledger.close", () => ledger.close.populateTransaction());
      } else if (decision.action === "wait_close") {
        await sleep(Math.max(250, POLL_MS));
      } else if (decision.action === "claim_payout") {
        if (donationDestination !== null) {
          const destination = donationDestination;
          if (destination === ethers.getAddress(await pool.getAddress())) {
            throw new Error("winnings destination must be a different active pool");
          }
          const now = snapshot.now;
          const claimDeadline = BigInt(await ledger.claimDeadline());
          const feeBps = BigInt(await ledger.feeBps());
          const donationValueWei = decision.valueWei - (decision.valueWei * feeBps / 10_000n);
          let destinationReady = false;
          try {
            destinationReady = await donationDestinationReady(donationValueWei, now);
          } catch {
            destinationReady = false;
          }
          if (destinationReady) {
            const label = `pool.donateClaimToPool:${destination}:${decision.valueWei}`;
            await sendPersistent(label, () => pool.donateClaimToPool.populateTransaction(destination));
          } else if (claimDeadline !== 0n && now + DONATION_FALLBACK_WINDOW_SECONDS >= claimDeadline) {
            state.donation_fallback = {
              at_utc: new Date().toISOString(),
              destination,
              reason: "destination unavailable inside claim-deadline safety window",
            };
            persistState();
            const label = `pool.claim:donation-fallback:${decision.valueWei}`;
            await sendPersistent(label, () => pool.claim.populateTransaction());
          } else {
            state.phase = "waiting_for_donation_destination";
            state.donation_wait = { at_utc: new Date().toISOString(), destination, claimDeadline: claimDeadline.toString() };
            persistState();
            await sleep(Math.max(1000, POLL_MS));
            continue;
          }
        } else {
          const label = `pool.claim:${decision.valueWei}`;
          await sendPersistent(label, () => pool.claim.populateTransaction());
        }
      } else if (decision.action === "done") {
        state.phase = snapshot.status === 4 ? "complete" : "terminated";
        state.completed_at_utc = new Date().toISOString();
        persistState();
        return snapshot;
      } else {
        throw new Error(`unknown lifecycle action: ${decision.action}`);
      }
      consecutiveErrors = 0;
      if (SUBMIT_ONLY) {
        const current = await subs.submissions(submissionId);
        if (Number(current.status) >= 2) {
          state.phase = "submit_only";
          persistState();
          return { status: Number(current.status), submission: current };
        }
      }
    } catch (error) {
      consecutiveErrors += 1;
      state.last_error = {
        at_utc: new Date().toISOString(),
        message: error.shortMessage || error.message,
        consecutive_errors: consecutiveErrors,
      };
      persistState();
      if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) throw error;
      const backoff = Math.min(Math.max(1000, POLL_MS), 1000 * 2 ** Math.min(consecutiveErrors - 1, 6));
      log(`  retryable lifecycle error (${consecutiveErrors}/${MAX_CONSECUTIVE_ERRORS}): ${state.last_error.message}`);
      await sleep(backoff);
    }
  }
}

async function main() {
  const runner = problemRunnerConfig(resolve(PROBLEM));
  if (manifestProblem && runner.problemId !== manifestProblem.problemSlug) {
    throw new Error("--problem does not match the selected deployment-manifest board");
  }
  const verdict = runVerifier(resolve(PROBLEM), resolve(SOLUTION), REPO_ROOT);
  if (!verdict.valid && !FORCE) throw new Error("local exact verifier rejected the solution (use --force only for adversarial testing)");
  const objective = problemObjective(resolve(PROBLEM));
  const trueScoreAtoms = chainScoreAtoms(verdict.score, objective.direction);
  const claimedScoreAtoms = SCORE_ATOMS_OVERRIDE === null ? trueScoreAtoms : BigInt(SCORE_ATOMS_OVERRIDE);
  const solutionBytes = readFileSync(resolve(SOLUTION));
  const daHash = ethers.sha256(solutionBytes);
  const cid = `sha256:${daHash.slice(2)}`;
  const [network, onchainDa, seedScoreAtoms] = await Promise.all([
    provider.getNetwork(),
    subs.onchainDa(),
    subs.seedScoreAtoms(),
  ]);
  if (manifestProblem?.seedScoreAtoms !== undefined && seedScoreAtoms !== BigInt(manifestProblem.seedScoreAtoms)) {
    throw new Error(`manifest seedScoreAtoms ${manifestProblem.seedScoreAtoms} does not match on-chain seed ${seedScoreAtoms}`);
  }
  // Force/adversarial score claims remain available, but their display field is
  // never independently caller-controlled.
  const improvementAtoms = seedRelativeImprovementAtoms(seedScoreAtoms, claimedScoreAtoms);
  const identity = {
    chain_id: Number(network.chainId),
    registry_problem_id: manifestProblem?.problemId ?? null,
    submission_contract: String(subs.target).toLowerCase(),
    solver: solver.toLowerCase(),
    problem: resolve(PROBLEM),
    solution: resolve(SOLUTION),
    solution_cid: cid,
    commit_da_hash: daHash,
    claimed_score_atoms: claimedScoreAtoms.toString(),
    claimed_improvement_atoms: improvementAtoms.toString(),
    seed_score_atoms: seedScoreAtoms.toString(),
  };
  const stateKey = sha256Canonical(identity).slice(7, 23);
  loadState(identity, join(HERE, "runtime", `solver-${stateKey}.json`));

  log(`P42 solver ${solver} chain=${identity.chain_id}`);
  log(`state=${statePath} phase=${state.phase}`);
  log(`self-check valid=${verdict.valid} score=${verdict.score} claim=${claimedScoreAtoms}`);
  await prepareDataAvailability(solutionBytes, onchainDa);

  if (!state.submission_id && !state.transactions.commit) {
    const best = await subs.bestScoreAtoms();
    if (claimedScoreAtoms >= best && !FORCE) {
      throw new Error(`claim ${claimedScoreAtoms} no longer beats frontier ${best}`);
    }
  }
  if (state.fund_wei !== "0") {
    await sendPersistent("pool.fund", () => pool.fund.populateTransaction({ value: BigInt(state.fund_wei) }));
  }
  if (!state.submission_id) {
    const commitment = await subs["computeCommitment(string,address,bytes32,string)"](
      cid,
      solver,
      daHash,
      state.salt,
    );
    const bond = await subs.requiredPostingBondNow();
    const receipt = await sendPersistent("commit", () => subs.commit.populateTransaction(commitment, daHash, { value: bond }));
    const submissionId = submissionIdFromCommittedReceipt(
      receipt,
      subs.interface,
      solver,
      String(subs.target),
    );
    state.submission_id = submissionId.toString();
    state.phase = "committed";
    persistState();
    log(`  submissionId=${submissionId} (from Committed receipt)`);
  }

  const submissionId = BigInt(state.submission_id);
  const revealBytes = onchainDa ? solutionBytes : "0x";
  const final = await runLifecycle(submissionId, [
    submissionId,
    cid,
    claimedScoreAtoms,
    improvementAtoms,
    state.salt,
    revealBytes,
  ]);
  log(`DONE submission #${submissionId} status=${final.status} phase=${state.phase}`);
  if (state.arweave) log(`DA mirror: ${state.arweave.url}`);
}

main().catch((error) => {
  console.error("FAILED:", error.shortMessage || error.message);
  process.exit(1);
});
