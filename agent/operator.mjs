#!/usr/bin/env node
// P42 autonomous operator: chain reveal -> persistent FIFO job -> mandatory
// Docker/cgroup verifier -> canonical challenge candidate -> bounded tx.

import { ethers } from "ethers";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  assertRegistryBindingStable,
  buildRegistryBinding,
  buildChallengeCallPolicy,
  buildOperatorCursor,
  buildSignedTransactionRecord,
  canonicalJson,
  classifyReceiptFinality,
  exactCallRequestFromPolicy,
  nextOperatorScanRange,
  operatorCursorBinding,
  localProblemRuntimeIdentity,
  problemRunnerConfig,
  queryChunked,
  recoverRevealCalldata,
  resolveOperatorFinality,
  runRuntimeBridge,
  sha256Canonical,
  validateRegistryBinding,
  validateOperatorCursor,
  validateOperatorExecutionMode,
} from "./lib.mjs";
import { validateManifestEvidence } from "./indexer.mjs";
import { getBlob } from "./da-local.mjs";
import { fetchFromArweave, findTxidByCid } from "./da-arweave.mjs";

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
const REGISTRY_PROBLEM_ID = arg("registry-problem-id");
const DA_DIR = arg("da-dir");
const ARWEAVE = arg("arweave", false);
const ONCE = arg("once", false);
const LOCAL_TEST = arg("local-test", false);
const AGENT_WALLET = arg("agent-wallet", null);
const CONFIRMATIONS_ARG = arg("confirmations", null);
const REORG_OVERLAP_ARG = arg("reorg-overlap-blocks", null);
const REPO_ROOT = resolve(arg("repo-root", resolve(HERE, "..")));
const RUNTIME = resolve(arg("runtime", join(HERE, "runtime")));
const CURSOR = resolve(arg("cursor", join(RUNTIME, "operator-cursor.json")));
const QUEUE = resolve(arg("queue", join(RUNTIME, "runner-queue.json")));
const TRANSCRIPTS = resolve(arg("transcripts", join(RUNTIME, "transcripts")));
const INPUTS = join(RUNTIME, "inputs");
const JOB_SPECS = join(RUNTIME, "jobs");
const RETRY_STATE = join(RUNTIME, "retry-state");
const ACTIONS = join(RUNTIME, "actions");
const ALERTS = join(RUNTIME, "ALERTS.log");
const MAX_BOND = ethers.parseEther(String(arg("max-challenge-bond", "0.01")));
const MAX_JOBS_PER_SCAN = Number(arg("max-jobs-per-scan", "1"));
const POLL_MS = Number(arg("poll-ms", "12000"));
const RESERVE_MEMORY_MB = Number(arg("reserve-memory-mb", "8192"));
const MAX_SWAP_USED_MB = Number(arg("max-swap-used-mb", "1024"));
const MEMORY_SAFETY_FACTOR = Number(arg("memory-safety-factor", "2"));
const RUNNER_CHAIN_TIMESTAMP_ENV = "P42_RUNNER_CHAIN_TIMESTAMP";
const RETRY_BACKOFF_MS = 15_000;

if (!MANIFEST || !PROBLEM || !REGISTRY_PROBLEM_ID) {
  console.error("required: --manifest <path> --problem <dir> --registry-problem-id <positive numeric id>");
  process.exit(2);
}
if (!/^[1-9][0-9]*$/.test(String(REGISTRY_PROBLEM_ID))) {
  console.error("--registry-problem-id must be a positive canonical integer");
  process.exit(2);
}
if (!Number.isInteger(MAX_JOBS_PER_SCAN) || MAX_JOBS_PER_SCAN < 1) {
  console.error("--max-jobs-per-scan must be a positive integer");
  process.exit(2);
}
const KEY = process.env.OPERATOR_PRIVATE_KEY;
if (!KEY) {
  console.error("set OPERATOR_PRIVATE_KEY (use only a funded, revoked-capable operator/session key)");
  process.exit(2);
}

const abi = (name) => JSON.parse(
  readFileSync(`${REPO_ROOT}/contracts/artifacts/src/${name}.sol/${name}.json`, "utf8"),
).abi;
const manifest = JSON.parse(readFileSync(resolve(MANIFEST), "utf8"));
const problem = resolve(PROBLEM);
const runnerConfig = problemRunnerConfig(problem);
const provider = new ethers.JsonRpcProvider(RPC);
const wallet = new ethers.Wallet(KEY, provider);
const subs = new ethers.Contract(manifest.contracts.submissions.address, abi("P42SubmissionManager"), wallet);
const chal = new ethers.Contract(manifest.contracts.challenges.address, abi("P42ChallengeManager"), wallet);
const registry = new ethers.Contract(manifest.contracts.registry.address, abi("P42ProblemRegistry"), wallet);
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const log = (...values) => console.log(...values);

for (const path of [RUNTIME, TRANSCRIPTS, INPUTS, JOB_SPECS, RETRY_STATE, ACTIONS]) mkdirSync(path, { recursive: true });
const START_BLOCK = Number(arg("from-block", manifest.indexer?.startBlock ?? 0));
let chainId;
let finalityConfirmations;
let reorgOverlapBlocks;
let executionMode;
let agentWallet = null;
let registryProblemId;
let localProblem;
let cursorBinding;
let cursorState;
const blockCache = new Map();

function registryBindingExpected() {
  return {
    chain_id: chainId,
    registry_address: String(registry.target).toLowerCase(),
    problem_id: registryProblemId,
    problem_slug: runnerConfig.problemId,
  };
}

async function registryBindingAt(blockNumber, blockHash) {
  const [registryProblem, isFrozen, explicitlyFrozen] = await Promise.all([
    registry.problems(BigInt(registryProblemId), { blockTag: blockNumber }),
    registry.isFrozen(BigInt(registryProblemId), { blockTag: blockNumber }),
    registry.explicitlyFrozen(BigInt(registryProblemId), { blockTag: blockNumber }),
  ]);
  return buildRegistryBinding({
    manifest,
    localProblem,
    registryAddress: String(registry.target),
    registryProblemId,
    chainId,
    observationBlockNumber: blockNumber,
    observationBlockHash: blockHash,
    registryProblem,
    registryIsFrozen: isFrozen,
    registryExplicitlyFrozen: explicitlyFrozen,
  });
}

async function currentRegistryBinding() {
  const head = await provider.getBlockNumber();
  const safeHead = head - finalityConfirmations;
  if (safeHead < START_BLOCK) {
    throw new Error(`registry binding needs a finalized block at or after manifest start block ${START_BLOCK}`);
  }
  const block = await provider.getBlock(safeHead);
  if (!block?.hash) throw new Error(`cannot load finalized registry observation block ${safeHead}`);
  return registryBindingAt(safeHead, block.hash);
}

async function revalidateRecordedRegistryBinding(value) {
  const recorded = validateRegistryBinding(value, registryBindingExpected());
  if (recorded.observation_block_number < START_BLOCK) {
    throw new Error("recorded registry binding predates the manifest start block");
  }
  const head = await provider.getBlockNumber();
  if (recorded.observation_block_number > head - finalityConfirmations) {
    throw new Error("recorded registry binding observation is not finalized");
  }
  const historicalBlock = await provider.getBlock(recorded.observation_block_number);
  if (!historicalBlock?.hash || historicalBlock.hash.toLowerCase() !== recorded.observation_block_hash) {
    throw new Error("recorded registry binding observation block is no longer canonical");
  }
  const historical = await registryBindingAt(recorded.observation_block_number, historicalBlock.hash);
  assertRegistryBindingStable(recorded, historical);
  const current = await currentRegistryBinding();
  assertRegistryBindingStable(recorded, current);
  return current;
}

function bridge(...args) {
  return runRuntimeBridge(REPO_ROOT, args);
}

function readQueue() {
  return bridge("read", "--queue", QUEUE);
}

function writeCanonicalAtomic(path, value, mode = 0o600) {
  const text = `${canonicalJson(value)}\n`;
  if (existsSync(path)) {
    if (readFileSync(path, "utf8") !== text) throw new Error(`immutable runtime artifact changed: ${path}`);
    return;
  }
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, text, { encoding: "utf8", mode, flag: "wx" });
  renameSync(temporary, path);
}

function writePayloadAtomic(path, bytes) {
  const payload = Buffer.from(bytes);
  if (existsSync(path)) {
    const existing = readFileSync(path);
    if (!existing.equals(payload)) throw new Error(`immutable payload changed: ${path}`);
    return;
  }
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, payload, { mode: 0o600, flag: "wx" });
  renameSync(temporary, path);
}

function readJsonOrNull(path) {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeJsonAtomic(path, value, mode = 0o600) {
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${canonicalJson(value)}\n`, { encoding: "utf8", mode, flag: "wx" });
  renameSync(temporary, path);
}

function replaceJsonAtomic(path, value, mode = 0o600) {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(temporary, `${canonicalJson(value)}\n`, { encoding: "utf8", mode, flag: "wx" });
  renameSync(temporary, path);
}

const RETRYABLE_DA_FAILURE_KINDS = new Set([
  "calldata_unavailable",
  "arweave_lookup_unavailable",
  "arweave_retrieval_unavailable",
]);

function retryableDaFailure(kind, error) {
  return { kind, error, retryable: true };
}

export function isExplicitRetryableDaFailure(failure) {
  return Boolean(
    failure
    && typeof failure === "object"
    && failure.retryable === true
    && RETRYABLE_DA_FAILURE_KINDS.has(failure.kind),
  );
}

function retryPaths(jobId) {
  const name = sha256Canonical({ job_id: jobId }).slice(7);
  return {
    solutionPath: join(INPUTS, `${name}.json`),
    statePath: join(RETRY_STATE, `${name}.json`),
  };
}

function retryStateHasTerminalFailure(job) {
  try {
    const state = readJsonOrNull(job.retry_state_path);
    const failure = state?.da_failure;
    return Boolean(
      state
      && state.schema_version === "p42-retry-state/v1"
      && state.job_id === job.job_id
      && failure
      && typeof failure === "object"
      && !isExplicitRetryableDaFailure(failure),
    );
  } catch {
    return false;
  }
}

export function retryableJobIsEligible(job, latestTimestamp, nowMs = Date.now()) {
  const claim = job?.chain_claim;
  if (
    !job
    || job.status !== "queued"
    || job.canonical_status === "orphaned_reorg"
    || job.action
    || !isExplicitRetryableDaFailure(job.da_failure)
    || !claim
    || typeof claim !== "object"
  ) return false;
  if (job.retry_not_before_utc !== undefined) {
    if (typeof job.retry_not_before_utc !== "string") return false;
    const retryNotBeforeMs = Date.parse(job.retry_not_before_utc);
    if (!Number.isFinite(retryNotBeforeMs) || retryNotBeforeMs > nowMs) return false;
  }
  try {
    return BigInt(claim.challenge_ends_at) > BigInt(latestTimestamp);
  } catch {
    return false;
  }
}

function sourceEventHashFor(event, submission) {
  return sha256Canonical({
    schema_version: "p42-reveal-event/v1",
    chain_id: chainId,
    problem_id: runnerConfig.problemId,
    submission_contract: String(subs.target).toLowerCase(),
    challenge_contract: String(chal.target).toLowerCase(),
    submission_id: event.args.submissionId.toString(),
    block_number: event.blockNumber,
    block_hash: event.blockHash,
    transaction_hash: event.transactionHash,
    transaction_index: Number(event.transactionIndex ?? 0),
    log_index: Number(event.index ?? event.logIndex),
    solver: String(event.args.solver).toLowerCase(),
    solution_cid: event.args.solutionCid,
    commit_da_hash: submission.commitDaHash.toLowerCase(),
    claimed_score_atoms: event.args.claimedScoreAtoms.toString(),
    claimed_improvement_atoms: event.args.improvementAtoms.toString(),
    reveal_instance_hash: String(event.args.revealInstanceHash).toLowerCase(),
    challenge_ends_at: event.args.challengeEndsAt.toString(),
    solution_bytes_length: Number(event.args.solutionBytesLength ?? 0n),
    onchain_da: Number(event.args.solutionBytesLength ?? 0n) > 0,
  });
}

async function canonicalRevealRecords(events) {
  const byJobId = new Map();
  const bySourceHash = new Set();
  for (const event of events) {
    const submission = await subs.submissions(event.args.submissionId);
    const sourceEventHash = sourceEventHashFor(event, submission);
    byJobId.set(eventJobId(event), sourceEventHash);
    bySourceHash.add(sourceEventHash);
  }
  return { byJobId, bySourceHash };
}

function loadOperatorCursor() {
  const existing = readJsonOrNull(CURSOR);
  if (existing) return validateOperatorCursor(existing, cursorBinding);
  return buildOperatorCursor({
    binding: cursorBinding,
    nextBlock: START_BLOCK,
    anchors: [],
    overlapBlocks: reorgOverlapBlocks,
  });
}

async function cursorAnchorMismatch(cursor) {
  for (const anchor of cursor.anchors ?? []) {
    const block = await provider.getBlock(anchor.block_number);
    if (!block || String(block.hash).toLowerCase() !== String(anchor.block_hash).toLowerCase()) {
      return anchor.block_number;
    }
  }
  return null;
}

async function persistCursor(nextBlock) {
  const anchorFrom = Math.max(START_BLOCK, nextBlock - reorgOverlapBlocks - 1);
  const anchors = [];
  for (let number = anchorFrom; number < nextBlock; number += 1) {
    const block = await provider.getBlock(number);
    if (block?.hash) anchors.push({ block_number: number, block_hash: block.hash.toLowerCase() });
  }
  cursorState = buildOperatorCursor({
    binding: cursorBinding,
    nextBlock,
    anchors,
    overlapBlocks: reorgOverlapBlocks,
  });
  writeJsonAtomic(CURSOR, cursorState);
}

function jobIsCurrentOperator(job, fromBlock, toBlock) {
  const claim = job.chain_claim;
  if (!claim || claim.schema_version !== "p42-chain-claim/v1") return false;
  if (Number(claim.chain_id) !== chainId) return false;
  if (String(claim.problem_id) !== runnerConfig.problemId) return false;
  if (String(claim.submission_contract).toLowerCase() !== String(subs.target).toLowerCase()) return false;
  try {
    validateRegistryBinding(claim.registry_binding, registryBindingExpected());
  } catch {
    return false;
  }
  const blockNumber = Number(claim.block_number);
  return Number.isInteger(blockNumber) && blockNumber >= fromBlock && blockNumber <= toBlock;
}

async function quarantineOrphanedJobs(fromBlock, toBlock, canonical, reason) {
  const queue = readQueue();
  const targets = queue.jobs
    .filter((job) => jobIsCurrentOperator(job, fromBlock, toBlock))
    .filter((job) => job.canonical_status !== "orphaned_reorg")
    .filter((job) => !canonical.bySourceHash.has(job.source_event_hash))
    .map((job) => job.job_id);
  if (targets.length === 0) return;
  const args = ["quarantine-canonical", "--queue", QUEUE, "--reason", reason];
  for (const jobId of targets) args.push("--job-id", jobId);
  const result = bridge(...args);
  appendAlert(`CANONICAL INVALIDATION ${result.invalidated_job_ids.length} job(s): ${reason}`);
}

function parseDetailJson(detail) {
  if (typeof detail !== "string" || !detail.trim().startsWith("{")) return {};
  try { return JSON.parse(detail); }
  catch { return {}; }
}

function appendAlert(message) {
  const line = `${new Date().toISOString()} ${message}`;
  console.error(`  !!! ${line}`);
  appendFileSync(ALERTS, `${line}\n`, { encoding: "utf8", mode: 0o600 });
}

async function blockFor(number) {
  if (!blockCache.has(number)) blockCache.set(number, await provider.getBlock(number));
  const block = blockCache.get(number);
  if (!block) throw new Error(`block ${number} is unavailable`);
  return block;
}

function eventJobId(event) {
  const logIndex = Number(event.index ?? event.logIndex);
  return [
    chainId,
    String(subs.target).toLowerCase(),
    String(event.blockHash).toLowerCase(),
    event.transactionHash.toLowerCase(),
    logIndex,
  ].join(":");
}

export async function recoverPayload(event, submission) {
  const solutionBytesLength = Number(event.args.solutionBytesLength ?? 0n);
  if (solutionBytesLength > 0) {
    let tx;
    try {
      tx = await provider.getTransaction(event.transactionHash);
    } catch (error) {
      return {
        daFailure: retryableDaFailure(
          "calldata_unavailable",
          `reveal transaction calldata could not be retrieved from the RPC: ${error.message}`,
        ),
        payloadSource: "transaction-calldata-rpc-unavailable",
      };
    }
    if (!tx) {
      return {
        daFailure: retryableDaFailure(
          "calldata_unavailable",
          "reveal transaction calldata is unavailable from the RPC",
        ),
        payloadSource: "transaction-calldata-unavailable",
      };
    }
    try {
      const reveal = recoverRevealCalldata(tx.data, subs.interface, {
        submissionId: event.args.submissionId,
        solutionCid: event.args.solutionCid,
        claimedScoreAtoms: event.args.claimedScoreAtoms,
        improvementAtoms: event.args.improvementAtoms,
        solutionBytesLength,
        commitDaHash: submission.commitDaHash,
      });
      return {
        blob: ethers.getBytes(reveal.solution),
        payloadSource: reveal.nested
          ? `nested-transaction-calldata@${reveal.calldataOffsetBytes}`
          : "top-level-transaction-calldata",
        calldataOffsetBytes: reveal.calldataOffsetBytes,
        transactionFrom: tx.from,
        transactionTo: tx.to,
      };
    } catch (error) {
      return {
        daFailure: { kind: "calldata_unrecoverable", error: error.message },
        payloadSource: "transaction-calldata-unrecoverable",
        transactionFrom: tx.from,
        transactionTo: tx.to,
      };
    }
  }

  if (ARWEAVE) {
    let txid;
    try {
      txid = await findTxidByCid(event.args.solutionCid, {});
    } catch (error) {
      return {
        daFailure: retryableDaFailure(
          "arweave_lookup_unavailable",
          `off-chain Arweave lookup failed: ${error.message}`,
        ),
        payloadSource: "arweave-lookup-unavailable",
      };
    }
    if (!txid) {
      return {
        daFailure: { kind: "missing", error: `off-chain payload ${event.args.solutionCid} was not found on Arweave` },
        payloadSource: "arweave-missing",
      };
    }
    try {
      return { blob: await fetchFromArweave(txid), payloadSource: `arweave:${txid}` };
    } catch (error) {
      return {
        daFailure: retryableDaFailure(
          "arweave_retrieval_unavailable",
          `off-chain Arweave retrieval failed: ${error.message}`,
        ),
        payloadSource: "arweave-retrieval-unavailable",
      };
    }
  }
  if (DA_DIR) {
    const blob = getBlob(DA_DIR, event.args.solutionCid);
    if (blob) return { blob, payloadSource: `local-content-store:${resolve(DA_DIR)}` };
    return {
      daFailure: { kind: "missing", error: `off-chain payload ${event.args.solutionCid} is absent from the configured content store` },
      payloadSource: `local-content-store-missing:${resolve(DA_DIR)}`,
    };
  }
  return {
    daFailure: { kind: "missing", error: "off-chain reveal has no configured retrievable DA source" },
    payloadSource: "offchain-store-not-configured",
  };
}

function retryEventFromClaim(claim) {
  return {
    transactionHash: claim.transaction_hash,
    args: {
      submissionId: BigInt(claim.submission_id),
      solutionCid: claim.solution_cid,
      claimedScoreAtoms: BigInt(claim.claimed_score_atoms),
      improvementAtoms: BigInt(claim.claimed_improvement_atoms),
      solutionBytesLength: BigInt(claim.solution_bytes_length),
    },
  };
}

async function refreshRetryableJobs(latest) {
  const queue = readQueue();
  for (const job of queue.jobs) {
    if (!retryableJobIsEligible(job, latest.timestamp)) continue;
    if (
      typeof job.retry_solution_path !== "string"
      || !job.retry_solution_path
      || typeof job.retry_state_path !== "string"
      || !job.retry_state_path
    ) {
      appendAlert(`RETRY STATE ${job.job_id}: retryable job has no operator-owned retry paths`);
      continue;
    }
    // A prior refresh may have recovered immutable bytes while the worker was
    // busy or memory-gated. The worker owns their anchor check; do not refetch
    // and attempt a second exclusive write on every scan.
    if (existsSync(job.retry_solution_path)) continue;
    if (retryStateHasTerminalFailure(job)) continue;

    try {
      const claim = job.chain_claim;
      const submissionId = BigInt(claim.submission_id);
      const submission = await subs.submissions(submissionId);
      if (Number(submission.status) !== 2) continue;
      const liveRevealInstanceHash = (await subs.revealInstanceHashOf(submissionId)).toLowerCase();
      if (liveRevealInstanceHash !== String(claim.reveal_instance_hash).toLowerCase()) continue;
      if (String(submission.commitDaHash).toLowerCase() !== String(claim.commit_da_hash).toLowerCase()) continue;

      const payload = await recoverPayload(retryEventFromClaim(claim), submission);
      if (payload.blob) {
        // The worker validates the anchor before any verifier runs. Persisting a
        // mismatched retrieval still turns into a terminal fail-closed candidate.
        writePayloadAtomic(job.retry_solution_path, payload.blob);
        log(`  recovered retryable payload for ${job.job_id} (${payload.payloadSource})`);
        continue;
      }
      if (!payload.daFailure) throw new Error("payload retry returned neither bytes nor a failure");
      replaceJsonAtomic(job.retry_state_path, {
        schema_version: "p42-retry-state/v1",
        job_id: job.job_id,
        da_failure: payload.daFailure,
      });
      log(`  retryable payload still unavailable for ${job.job_id}: ${payload.daFailure.kind}`);
    } catch (error) {
      appendAlert(`RETRY ${job.job_id}: ${error.shortMessage || error.message}`);
    }
  }
}

async function ingestReveal(event) {
  // Fail before any payload retrieval or queue write when the local package no
  // longer names the finalized registry source/image identity.
  const registryBinding = await currentRegistryBinding();
  const jobId = eventJobId(event);
  const paths = retryPaths(jobId);
  const submissionId = event.args.submissionId;
  const submission = await subs.submissions(submissionId);
  const revealInstanceHash = String(event.args.revealInstanceHash).toLowerCase();
  if (!ethers.isHexString(revealInstanceHash, 32) || revealInstanceHash === ethers.ZeroHash) {
    throw new Error(`reveal #${submissionId} emitted an invalid instance hash`);
  }
  const currentRevealInstanceHash = (await subs.revealInstanceHashOf(submissionId)).toLowerCase();
  if (currentRevealInstanceHash !== revealInstanceHash) {
    throw new Error(
      `reveal #${submissionId} event instance ${revealInstanceHash} does not match current on-chain instance ${currentRevealInstanceHash}`,
    );
  }
  const sourceEventHash = sourceEventHashFor(event, submission);
  const queue = readQueue();
  const existing = queue.jobs.find((job) => job.job_id === jobId || job.source_event_hash === sourceEventHash);
  if (existing) {
    const recordedBlockHash = existing.chain_claim?.block_hash;
    if (String(recordedBlockHash).toLowerCase() !== String(event.blockHash).toLowerCase()) {
      throw new Error(`reorg/collision for persisted reveal job ${existing.job_id}`);
    }
    return false;
  }

  const block = await blockFor(event.blockNumber);
  const payload = await recoverPayload(event, submission);
  const onchainDa = Number(event.args.solutionBytesLength ?? 0n) > 0;
  const expectedHash = `sha256:${submission.commitDaHash.slice(2).toLowerCase()}`;
  let solutionPath;
  let daFailure = payload.daFailure;
  if (payload.blob) {
    const observedHash = `sha256:${ethers.sha256(payload.blob).slice(2)}`;
    if (observedHash !== expectedHash) {
      daFailure = {
        kind: "hash_mismatch",
        error: `retrieved payload hash ${observedHash} does not match on-chain anchor ${expectedHash}`,
        observed_hash: observedHash,
      };
    } else {
      solutionPath = paths.solutionPath;
      writePayloadAtomic(solutionPath, payload.blob);
    }
  }

  const chainClaim = {
    schema_version: "p42-chain-claim/v1",
    chain_id: chainId,
    problem_id: runnerConfig.problemId,
    submission_contract: String(subs.target).toLowerCase(),
    challenge_contract: String(chal.target).toLowerCase(),
    submission_id: submissionId.toString(),
    block_number: event.blockNumber,
    block_hash: event.blockHash,
    transaction_hash: event.transactionHash,
    transaction_index: Number(event.transactionIndex ?? 0),
    log_index: Number(event.index ?? event.logIndex),
    solver: String(event.args.solver).toLowerCase(),
    solution_cid: event.args.solutionCid,
    commit_da_hash: submission.commitDaHash.toLowerCase(),
    claimed_score_atoms: event.args.claimedScoreAtoms.toString(),
    claimed_improvement_atoms: event.args.improvementAtoms.toString(),
    reveal_instance_hash: revealInstanceHash.toLowerCase(),
    challenge_ends_at: event.args.challengeEndsAt.toString(),
    solution_bytes_length: Number(event.args.solutionBytesLength ?? 0n),
    onchain_da: onchainDa,
    registry_binding: registryBinding,
    payload_source: payload.payloadSource,
    reveal_calldata_offset_bytes: payload.calldataOffsetBytes ?? null,
    transaction_from: payload.transactionFrom?.toLowerCase() ?? null,
    transaction_to: payload.transactionTo?.toLowerCase() ?? null,
  };
  const job = {
    job_id: jobId,
    status: "queued",
    required_memory_mb: runnerConfig.requiredMemoryMb,
    chain_block_number: event.blockNumber,
    chain_log_index: Number(event.index ?? event.logIndex),
    created_at_utc: new Date(Number(block.timestamp) * 1000).toISOString().replace(".000Z", "Z"),
    source_event_hash: sourceEventHash,
    problem,
    chain_claim: chainClaim,
    challenge_policy: { max_bond_wei: MAX_BOND.toString() },
  };
  if (solutionPath) job.solution = solutionPath;
  if (daFailure) {
    job.da_failure = daFailure;
    if (isExplicitRetryableDaFailure(daFailure)) {
      job.retry_solution_path = paths.solutionPath;
      job.retry_state_path = paths.statePath;
      // recoverPayload already made one retrieval attempt for this reveal. A
      // durable pause prevents a large memory-gated burst from repeatedly
      // querying the same unavailable endpoint before a worker can run.
      job.retry_not_before_utc = new Date(Date.now() + RETRY_BACKOFF_MS).toISOString();
    }
  }

  const specPath = join(JOB_SPECS, `${sourceEventHash.slice(7)}.json`);
  writeCanonicalAtomic(specPath, job);
  const result = bridge("enqueue", "--queue", QUEUE, "--job", specPath);
  log(`  queued submission #${submissionId} as ${jobId} (${payload.payloadSource}) created=${result.created}`);
  return result.created;
}

function runWorkerOnce(chainTimestamp) {
  const previous = process.env[RUNNER_CHAIN_TIMESTAMP_ENV];
  process.env[RUNNER_CHAIN_TIMESTAMP_ENV] = String(chainTimestamp);
  try {
    return bridge(
      "work-once",
      "--queue", QUEUE,
      "--transcripts", TRANSCRIPTS,
      "--reserve-memory-mb", String(RESERVE_MEMORY_MB),
      "--max-swap-used-mb", String(MAX_SWAP_USED_MB),
      "--memory-safety-factor", String(MEMORY_SAFETY_FACTOR),
    );
  } finally {
    if (previous === undefined) delete process.env[RUNNER_CHAIN_TIMESTAMP_ENV];
    else process.env[RUNNER_CHAIN_TIMESTAMP_ENV] = previous;
  }
}

function verifyTranscript(path) {
  const transcript = JSON.parse(readFileSync(path, "utf8"));
  const expected = transcript.transcript_hash;
  const unhashed = { ...transcript };
  delete unhashed.transcript_hash;
  if (sha256Canonical(unhashed) !== expected) throw new Error(`transcript self-hash mismatch: ${path}`);
  const candidate = transcript.verifier?.challenge_candidate;
  if (!candidate) return { transcript, candidate: null };
  const candidateHash = candidate.candidate_hash;
  const unsigned = { ...candidate };
  delete unsigned.candidate_hash;
  if (sha256Canonical(unsigned) !== candidateHash) throw new Error(`candidate self-hash mismatch: ${path}`);
  return { transcript, candidate };
}

function recordAction(job, candidate, status, transactionHash = null, detail = null) {
  const args = [
    "record-action", "--queue", QUEUE,
    "--job-id", job.job_id,
    "--candidate-hash", candidate.candidate_hash,
    "--status", status,
  ];
  if (transactionHash) args.push("--transaction-hash", transactionHash);
  if (detail) args.push("--detail", detail);
  return bridge(...args);
}

function signedActionPath(candidate, callPolicy) {
  return join(ACTIONS, `${candidate.candidate_hash.slice(7)}-${callPolicy.policy_hash.slice(7, 23)}.signed-tx.json`);
}

async function signedActionRecord(candidate, callPolicy, request) {
  const path = signedActionPath(candidate, callPolicy);
  if (existsSync(path)) return { path, record: JSON.parse(readFileSync(path, "utf8")) };
  const record = await buildSignedTransactionRecord({
    wallet,
    request,
    label: `challenge:${candidate.submission_id}:${candidate.candidate_hash}`,
  });
  writeCanonicalAtomic(path, record);
  return { path, record };
}

async function assertAgentWalletPolicy(callPolicy, bond, latestTimestamp) {
  if (!agentWallet) throw new Error("agent wallet is not configured");
  const selector = callPolicy.selector;
  const target = callPolicy.target;
  const [
    sessionKey,
    sessionChainId,
    sessionExpiresAt,
    revoked,
    perCallCap,
    totalCap,
    spentWei,
    allowed,
    policy,
  ] = await Promise.all([
    agentWallet.sessionKey(),
    agentWallet.sessionChainId(),
    agentWallet.sessionExpiresAt(),
    agentWallet.revoked(),
    agentWallet.perCallValueCapWei(),
    agentWallet.totalSpendCapWei(),
    agentWallet.spentWei(),
    agentWallet.allowed(target, selector),
    agentWallet.callPolicies(target, selector),
  ]);
  if (String(sessionKey).toLowerCase() !== wallet.address.toLowerCase()) {
    throw new Error("P42AgentWallet sessionKey does not match OPERATOR_PRIVATE_KEY address");
  }
  if (Number(sessionChainId) !== chainId) throw new Error("P42AgentWallet session chain mismatch");
  if (revoked) throw new Error("P42AgentWallet session key is revoked");
  if (BigInt(sessionExpiresAt) <= latestTimestamp) throw new Error("P42AgentWallet session is expired");
  if (BigInt(perCallCap) < bond) throw new Error("P42AgentWallet per-call cap is below required challenge bond");
  if (BigInt(spentWei) + bond > BigInt(totalCap)) throw new Error("P42AgentWallet total spend cap is exhausted");
  if (allowed !== true) throw new Error("P42AgentWallet target/selector is not allowlisted");
  if (policy.configured !== true) throw new Error("P42AgentWallet exact calldata policy is missing");
  if (Number(policy.chainId) !== chainId) throw new Error("P42AgentWallet call policy chain mismatch");
  if (BigInt(policy.expiresAt) < BigInt(callPolicy.expires_at)) throw new Error("P42AgentWallet call policy expires before challenge window");
  if (BigInt(policy.expiresAt) <= latestTimestamp) throw new Error("P42AgentWallet call policy is expired");
  if (Number(policy.maxCalls) !== Number(callPolicy.max_calls)) throw new Error("P42AgentWallet call policy max_calls mismatch");
  if (Number(policy.calls) !== 0) throw new Error("P42AgentWallet call policy was already consumed");
  if (String(policy.calldataHash).toLowerCase() !== callPolicy.calldata_hash.toLowerCase()) {
    throw new Error("P42AgentWallet call policy calldata hash mismatch");
  }
  if (String(policy.scopeHash).toLowerCase() !== callPolicy.scope_hash.toLowerCase()) {
    throw new Error("P42AgentWallet call policy scope hash mismatch");
  }
}

async function buildChallengeTransactionRequest(callPolicy, bond, latestTimestamp) {
  if (executionMode.mode === "direct-eoa-local-test") {
    const request = exactCallRequestFromPolicy(callPolicy, bond);
    await provider.call({ ...request, from: wallet.address });
    return wallet.populateTransaction(request);
  }
  await assertAgentWalletPolicy(callPolicy, bond, latestTimestamp);
  await agentWallet.execute.staticCall(callPolicy.target, bond, callPolicy.calldata);
  return agentWallet.execute.populateTransaction(callPolicy.target, bond, callPolicy.calldata);
}

async function candidateStillChallengeable(candidate) {
  const submissionId = BigInt(candidate.submission_id);
  const submission = await subs.submissions(submissionId);
  if (Number(submission.status) !== 2) {
    return { ok: false, reason: `submission status is ${submission.status}` };
  }
  const liveRevealInstanceHash = (await subs.revealInstanceHashOf(submissionId)).toLowerCase();
  if (liveRevealInstanceHash !== String(candidate.reveal_instance_hash).toLowerCase()) {
    return { ok: false, reason: "reveal instance changed before rebroadcast" };
  }
  const latest = await provider.getBlock("latest");
  if (!latest || BigInt(latest.timestamp) >= BigInt(candidate.challenge_ends_at)) {
    return { ok: false, reason: "challenge window closed before rebroadcast" };
  }
  return { ok: true };
}

async function reconcileBroadcast(job) {
  const action = job.action;
  if (!action || !action.transaction_hash) return false;
  if (["confirmed", "broadcast_reverted"].includes(action.status)) return true;
  if (!["signed", "broadcast", "submitted", "reorged"].includes(action.status)) return false;
  const transcript = verifyTranscript(job.transcript_path);
  if (!transcript.candidate) throw new Error(`action ${job.job_id} has no challenge candidate`);
  const detail = parseDetailJson(action.detail);
  let receipt = await provider.getTransactionReceipt(action.transaction_hash);
  if (receipt) {
    const canonicalBlock = await provider.getBlock(receipt.blockNumber);
    const receiptState = classifyReceiptFinality({
      receiptBlockNumber: receipt.blockNumber,
      receiptBlockHash: receipt.blockHash,
      canonicalBlockHash: canonicalBlock?.hash,
      latestBlockNumber: await provider.getBlockNumber(),
      confirmations: finalityConfirmations,
    });
    if (receiptState === "reorged") {
      if (action.status !== "reorged") {
        recordAction(job, transcript.candidate, "reorged", action.transaction_hash);
        appendAlert(`REORGED CHALLENGE ${job.job_id}: receipt block is no longer canonical`);
      }
      receipt = null;
    } else if (receiptState === "submitted") {
      if (action.status !== "submitted") {
        recordAction(job, transcript.candidate, "submitted", action.transaction_hash);
      }
      return true;
    } else {
      recordAction(
        job,
        transcript.candidate,
        receipt.status === 1 ? "confirmed" : "broadcast_reverted",
        action.transaction_hash,
      );
      return true;
    }
  }
  if (!receipt) {
    let pending = await provider.getTransaction(action.transaction_hash);
    if (!pending) {
      if (!detail.signed_tx_path) {
        throw new Error(`signed action ${action.transaction_hash} lacks signed_tx_path`);
      }
      if (action.status === "submitted") {
        recordAction(job, transcript.candidate, "reorged", action.transaction_hash);
        appendAlert(`REORGED CHALLENGE ${job.job_id}: receipt disappeared before finality`);
      }
      try {
        await revalidateRecordedRegistryBinding(transcript.transcript.verifier?.chain_claim?.registry_binding);
      } catch (error) {
        const reason = `registry binding rejected before rebroadcast: ${error.shortMessage || error.message}`;
        recordAction(job, transcript.candidate, "registry_binding_rejected", action.transaction_hash, reason);
        appendAlert(`REFUSED ${job.job_id}: ${reason}`);
        return true;
      }
      const current = await candidateStillChallengeable(transcript.candidate);
      if (!current.ok) {
        recordAction(job, transcript.candidate, "superseded", action.transaction_hash, current.reason);
        appendAlert(`SUPERSEDED ${job.job_id}: ${current.reason}`);
        return true;
      }
      const signed = JSON.parse(readFileSync(detail.signed_tx_path, "utf8"));
      if (signed.hash.toLowerCase() !== action.transaction_hash.toLowerCase()) {
        throw new Error(`signed action hash mismatch for ${job.job_id}`);
      }
      try {
        pending = await provider.broadcastTransaction(signed.raw_tx);
      } catch (error) {
        pending = await provider.getTransaction(action.transaction_hash);
        if (!pending) throw error;
      }
    }
    if (action.status !== "broadcast") {
      recordAction(job, transcript.candidate, "broadcast", action.transaction_hash);
    }
    receipt = await pending.wait();
  }
  const canonicalBlock = await provider.getBlock(receipt.blockNumber);
  const receiptState = classifyReceiptFinality({
    receiptBlockNumber: receipt.blockNumber,
    receiptBlockHash: receipt.blockHash,
    canonicalBlockHash: canonicalBlock?.hash,
    latestBlockNumber: await provider.getBlockNumber(),
    confirmations: finalityConfirmations,
  });
  if (receiptState === "reorged") {
    recordAction(job, transcript.candidate, "reorged", action.transaction_hash);
    appendAlert(`REORGED CHALLENGE ${job.job_id}: freshly mined receipt is not canonical`);
    return true;
  }
  if (receiptState === "submitted") {
    recordAction(job, transcript.candidate, "submitted", action.transaction_hash);
    return true;
  }
  recordAction(job, transcript.candidate, receipt.status === 1 ? "confirmed" : "broadcast_reverted", action.transaction_hash);
  return true;
}

async function consumeCandidate(job) {
  if (job.canonical_status === "orphaned_reorg") return;
  if (!job.transcript_path) return;
  if (job.action) {
    await reconcileBroadcast(job);
    return;
  }
  let checked;
  try { checked = verifyTranscript(job.transcript_path); }
  catch (error) {
    appendAlert(`QUARANTINE ${job.job_id}: ${error.message}`);
    return;
  }
  const candidate = checked.candidate;
  if (!candidate) return;
  if (candidate.action === "retry") {
    log(`  retry pending for ${job.job_id}: ${candidate.reason_code}`);
    return;
  }
  if (candidate.action === "none") {
    recordAction(job, candidate, "no_action", null, candidate.reason_code);
    return;
  }
  if (candidate.action === "quarantine") {
    recordAction(job, candidate, "quarantined", null, candidate.reason_code);
    appendAlert(`QUARANTINE ${job.job_id}: ${candidate.reason_code} (${candidate.candidate_hash})`);
    return;
  }
  if (candidate.action !== "challenge") throw new Error(`unknown candidate action: ${candidate.action}`);
  if (candidate.chain_id !== chainId) throw new Error(`candidate chain mismatch for ${job.job_id}`);
  if (candidate.problem_id !== runnerConfig.problemId) throw new Error(`candidate problem mismatch for ${job.job_id}`);
  if (candidate.submission_contract !== String(subs.target).toLowerCase()) {
    throw new Error(`candidate submission contract mismatch for ${job.job_id}`);
  }
  if (candidate.challenge_contract !== String(chal.target).toLowerCase()) {
    throw new Error(`candidate challenge contract mismatch for ${job.job_id}`);
  }
  if (candidate.source_event_hash !== job.source_event_hash) {
    throw new Error(`candidate source event mismatch for ${job.job_id}`);
  }
  try {
    await revalidateRecordedRegistryBinding(checked.transcript.verifier?.chain_claim?.registry_binding);
  } catch (error) {
    const detail = `registry binding rejected before signing: ${error.shortMessage || error.message}`;
    recordAction(job, candidate, "registry_binding_rejected", null, detail);
    appendAlert(`REFUSED ${job.job_id}: ${detail}`);
    return;
  }
  const candidateCap = BigInt(candidate.max_bond_wei || "0");
  if (candidateCap <= 0n || candidateCap > MAX_BOND) {
    recordAction(job, candidate, "invalid_spend_cap", null, `candidate cap ${candidateCap} exceeds operator cap ${MAX_BOND}`);
    appendAlert(`REFUSED ${job.job_id}: invalid candidate spend cap ${candidateCap}`);
    return;
  }

  const submissionId = BigInt(candidate.submission_id);
  const submission = await subs.submissions(submissionId);
  if (Number(submission.status) !== 2) {
    recordAction(job, candidate, "superseded", null, `submission status is ${submission.status}`);
    return;
  }
  const liveRevealInstanceHash = (await subs.revealInstanceHashOf(submissionId)).toLowerCase();
  if (liveRevealInstanceHash !== String(candidate.reveal_instance_hash).toLowerCase()) {
    recordAction(
      job,
      candidate,
      "superseded",
      null,
      `reveal instance changed from ${candidate.reveal_instance_hash} to ${liveRevealInstanceHash}`,
    );
    appendAlert(`SUPERSEDED ${job.job_id}: reveal instance changed before action consumption`);
    return;
  }
  const latest = await provider.getBlock("latest");
  if (!latest || BigInt(latest.timestamp) >= BigInt(candidate.challenge_ends_at)) {
    recordAction(job, candidate, "window_expired", null, "challenge window closed before action consumption");
    appendAlert(`MISSED WINDOW ${job.job_id}: ${candidate.reason_code}`);
    return;
  }
  const disputed = await subs.disputedEntitlementWei(submissionId);
  const bond = await chal.requiredChallengeBond(disputed);
  if (bond > candidateCap || bond > MAX_BOND) {
    recordAction(job, candidate, "bond_over_cap", null, `required ${bond}; cap ${candidateCap}`);
    appendAlert(`UNPOLICED ${job.job_id}: bond ${bond} exceeds cap ${candidateCap} (${candidate.candidate_hash})`);
    return;
  }

  const reasonHash = ethers.keccak256(
    ethers.toUtf8Bytes(`p42-challenge-candidate/v1:${candidate.candidate_hash}`),
  );
  const callPolicy = buildChallengeCallPolicy({
    challengeInterface: chal.interface,
    challengeContract: String(chal.target),
    chainId,
    problemId: runnerConfig.problemId,
    submissionId,
    revealInstanceHash: candidate.reveal_instance_hash,
    reasonHash,
    candidateHash: candidate.candidate_hash,
    sourceEventHash: candidate.source_event_hash,
    expiresAt: candidate.challenge_ends_at,
    valueWei: bond,
  });
  const policyPath = join(
    ACTIONS,
    `${candidate.candidate_hash.slice(7)}-${callPolicy.policy_hash.slice(7, 23)}.json`,
  );
  writeCanonicalAtomic(policyPath, callPolicy);
  log(`  exact session call policy: ${policyPath} (${callPolicy.policy_hash})`);
  const request = await buildChallengeTransactionRequest(
    callPolicy,
    bond,
    BigInt(latest.timestamp),
  );
  const signed = await signedActionRecord(candidate, callPolicy, request);
  const detail = canonicalJson({
    bond_wei: bond.toString(),
    call_policy_path: policyPath,
    call_policy_hash: callPolicy.policy_hash,
    calldata_hash: callPolicy.calldata_hash,
    scope_hash: callPolicy.scope_hash,
    expires_at: callPolicy.expires_at,
    max_calls: callPolicy.max_calls,
    execution_mode: executionMode.mode,
    agent_wallet: executionMode.agentWalletAddress,
    signed_tx_path: signed.path,
    signed_tx_hash: signed.record.hash,
    signed_tx_data_hash: signed.record.data_hash,
    signed_tx_nonce: signed.record.nonce,
  });
  recordAction(job, candidate, "signed", signed.record.hash, detail);
  log(`  challenge signed for #${submissionId}: ${signed.record.hash} bond=${ethers.formatEther(bond)} ETH`);
  await reconcileBroadcast({ ...job, action: { status: "signed", transaction_hash: signed.record.hash, detail } });
}

async function consumeCandidates() {
  const queue = readQueue();
  for (const job of queue.jobs) await consumeCandidate(job);
}

async function scanOnce() {
  const latest = await provider.getBlockNumber();
  const latestBlock = await provider.getBlock(latest);
  if (!latestBlock) throw new Error(`latest block ${latest} is unavailable`);
  const safeLatest = Math.max(0, latest - finalityConfirmations);
  const mismatch = await cursorAnchorMismatch(cursorState);
  if (mismatch !== null) {
    appendAlert(`REORG detected at anchored block ${mismatch}; rescanning overlap from durable cursor`);
    cursorState = buildOperatorCursor({
      binding: cursorBinding,
      nextBlock: mismatch,
      anchors: cursorState.anchors.filter((anchor) => anchor.block_number < mismatch),
      overlapBlocks: reorgOverlapBlocks,
    });
    writeJsonAtomic(CURSOR, cursorState);
  }

  const range = nextOperatorScanRange({
    cursor: cursorState,
    startBlock: START_BLOCK,
    safeLatest,
    overlapBlocks: reorgOverlapBlocks,
  });
  if (range) {
    const events = await queryChunked(subs, subs.filters.Revealed(), range.fromBlock, range.toBlock);
    const canonical = await canonicalRevealRecords(events);
    await quarantineOrphanedJobs(
      range.fromBlock,
      range.toBlock,
      canonical,
      `canonical rescan ${range.fromBlock}..${range.toBlock} did not contain the original Revealed source event`,
    );
    for (const event of events) await ingestReveal(event);
    await persistCursor(range.toBlock + 1);
  }

  await refreshRetryableJobs(latestBlock);
  for (let index = 0; index < MAX_JOBS_PER_SCAN; index += 1) {
    const result = runWorkerOnce(latestBlock.timestamp);
    if (result.schema_version === "p42-runner-transcript/v1") {
      log(`  worker completed ${result.job_id}: ${result.verifier.challenge_candidate?.action || "legacy"}`);
      continue;
    }
    if (result.reason !== "queue_empty") log(`  worker waiting: ${result.reason}`);
    break;
  }
  await consumeCandidates();
}

async function main() {
  const network = await provider.getNetwork();
  chainId = Number(network.chainId);
  validateManifestEvidence(manifest);
  if (Number(manifest.network.chainId) !== chainId) {
    throw new Error(`manifest chain ${manifest.network.chainId} does not match RPC chain ${chainId}`);
  }
  registryProblemId = String(REGISTRY_PROBLEM_ID);
  localProblem = localProblemRuntimeIdentity(problem, REPO_ROOT);
  if (localProblem.problem_slug !== runnerConfig.problemId) {
    throw new Error("problem.yaml identity changed while loading the operator runtime");
  }
  ({ confirmations: finalityConfirmations, reorgOverlapBlocks } = resolveOperatorFinality({
    manifest,
    confirmations: CONFIRMATIONS_ARG,
    reorgOverlapBlocks: REORG_OVERLAP_ARG,
    localTest: Boolean(LOCAL_TEST),
  }));
  executionMode = validateOperatorExecutionMode({
    manifest,
    chainId,
    localTest: Boolean(LOCAL_TEST),
    agentWalletAddress: AGENT_WALLET,
    operatorAddress: wallet.address,
  });
  if (executionMode.mode === "agent-wallet") {
    agentWallet = new ethers.Contract(executionMode.agentWalletAddress, abi("P42AgentWallet"), wallet);
  }
  // Fail startup before queueing or spending when the finalized registry cannot
  // attest this exact local verifier source/image identity.
  await currentRegistryBinding();
  cursorBinding = operatorCursorBinding({
    manifest,
    chainId,
    submissionContract: String(subs.target),
    challengeContract: String(chal.target),
    problemId: runnerConfig.problemId,
    registryAddress: String(registry.target),
    registryProblemId,
  });
  cursorState = loadOperatorCursor();
  writeJsonAtomic(CURSOR, cursorState);

  log(`P42 operator ${wallet.address} chain=${chainId} mode=${executionMode.mode}`);
  log(`queue=${QUEUE} cursor=${CURSOR} finality=${finalityConfirmations} overlap=${reorgOverlapBlocks}`);
  log(`sandbox=docker max_running=1 max_bond=${ethers.formatEther(MAX_BOND)} ETH`);
  await consumeCandidates();
  if (ONCE) {
    await scanOnce();
    log("[once] done");
    return;
  }
  for (;;) {
    try { await scanOnce(); }
    catch (error) { console.error(`[operator error] ${error.shortMessage || error.message}`); }
    await sleep(POLL_MS);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error("FAILED:", error.shortMessage || error.message);
    process.exit(1);
  });
}
