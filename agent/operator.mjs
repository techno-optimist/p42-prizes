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
import { fileURLToPath } from "node:url";
import {
  buildChallengeCallPolicy,
  buildOperatorCursor,
  buildSignedTransactionRecord,
  canonicalJson,
  nextOperatorScanRange,
  operatorCursorBinding,
  problemRunnerConfig,
  queryChunked,
  recoverRevealCalldata,
  resolveOperatorFinality,
  runRuntimeBridge,
  sha256Canonical,
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
const ACTIONS = join(RUNTIME, "actions");
const ALERTS = join(RUNTIME, "ALERTS.log");
const MAX_BOND = ethers.parseEther(String(arg("max-challenge-bond", "0.01")));
const MAX_JOBS_PER_SCAN = Number(arg("max-jobs-per-scan", "1"));
const POLL_MS = Number(arg("poll-ms", "12000"));
const RESERVE_MEMORY_MB = Number(arg("reserve-memory-mb", "8192"));
const MAX_SWAP_USED_MB = Number(arg("max-swap-used-mb", "1024"));
const MEMORY_SAFETY_FACTOR = Number(arg("memory-safety-factor", "2"));

if (!MANIFEST || !PROBLEM) {
  console.error("required: --manifest <path> --problem <dir>");
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
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const log = (...values) => console.log(...values);

for (const path of [RUNTIME, TRANSCRIPTS, INPUTS, JOB_SPECS, ACTIONS]) mkdirSync(path, { recursive: true });
const START_BLOCK = Number(arg("from-block", manifest.indexer?.startBlock ?? 0));
let chainId;
let finalityConfirmations;
let reorgOverlapBlocks;
let executionMode;
let agentWallet = null;
let cursorBinding;
let cursorState;
const blockCache = new Map();

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

async function recoverPayload(event, submission) {
  const solutionBytesLength = Number(event.args.solutionBytesLength ?? 0n);
  if (solutionBytesLength > 0) {
    const tx = await provider.getTransaction(event.transactionHash);
    if (!tx) {
      return {
        daFailure: { kind: "calldata_unavailable", error: "reveal transaction calldata is unavailable from the RPC" },
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
    try {
      const txid = await findTxidByCid(event.args.solutionCid, {});
      if (!txid) {
        return {
          daFailure: { kind: "missing", error: `off-chain payload ${event.args.solutionCid} was not found on Arweave` },
          payloadSource: "arweave-missing",
        };
      }
      return { blob: await fetchFromArweave(txid), payloadSource: `arweave:${txid}` };
    } catch (error) {
      return {
        daFailure: { kind: "missing", error: `off-chain Arweave retrieval failed: ${error.message}` },
        payloadSource: "arweave-retrieval-failed",
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

async function ingestReveal(event) {
  const jobId = eventJobId(event);
  const submissionId = event.args.submissionId;
  const submission = await subs.submissions(submissionId);
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
      solutionPath = join(INPUTS, `${sha256Canonical({ job_id: jobId }).slice(7)}.json`);
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
    challenge_ends_at: event.args.challengeEndsAt.toString(),
    solution_bytes_length: Number(event.args.solutionBytesLength ?? 0n),
    onchain_da: onchainDa,
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
  if (daFailure) job.da_failure = daFailure;

  const specPath = join(JOB_SPECS, `${sourceEventHash.slice(7)}.json`);
  writeCanonicalAtomic(specPath, job);
  const result = bridge("enqueue", "--queue", QUEUE, "--job", specPath);
  log(`  queued submission #${submissionId} as ${jobId} (${payload.payloadSource}) created=${result.created}`);
  return result.created;
}

function runWorkerOnce() {
  return bridge(
    "work-once",
    "--queue", QUEUE,
    "--transcripts", TRANSCRIPTS,
    "--reserve-memory-mb", String(RESERVE_MEMORY_MB),
    "--max-swap-used-mb", String(MAX_SWAP_USED_MB),
    "--memory-safety-factor", String(MEMORY_SAFETY_FACTOR),
  );
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

async function buildChallengeTransactionRequest(callPolicy, submissionId, reasonHash, bond, latestTimestamp) {
  if (executionMode.mode === "direct-eoa-local-test") {
    await chal.challenge.staticCall(submissionId, reasonHash, { value: bond });
    return chal.challenge.populateTransaction(submissionId, reasonHash, { value: bond });
  }
  await assertAgentWalletPolicy(callPolicy, bond, latestTimestamp);
  await agentWallet.execute.staticCall(callPolicy.target, bond, callPolicy.calldata);
  return agentWallet.execute.populateTransaction(callPolicy.target, bond, callPolicy.calldata);
}

async function reconcileBroadcast(job) {
  const action = job.action;
  if (!action || !["signed", "broadcast"].includes(action.status) || !action.transaction_hash) return false;
  const transcript = verifyTranscript(job.transcript_path);
  const detail = parseDetailJson(action.detail);
  let receipt = await provider.getTransactionReceipt(action.transaction_hash);
  if (!receipt) {
    let pending = await provider.getTransaction(action.transaction_hash);
    if (!pending) {
      if (!detail.signed_tx_path) {
        if (action.status === "broadcast") return true;
        throw new Error(`signed action ${action.transaction_hash} lacks signed_tx_path`);
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
  recordAction(
    job,
    transcript.candidate,
    receipt.status === 1 ? "submitted" : "broadcast_reverted",
    action.transaction_hash,
    `receipt status ${receipt.status}`,
  );
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
    submissionId,
    reasonHash,
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

  for (let index = 0; index < MAX_JOBS_PER_SCAN; index += 1) {
    const result = runWorkerOnce();
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
  cursorBinding = operatorCursorBinding({
    manifest,
    chainId,
    submissionContract: String(subs.target),
    challengeContract: String(chal.target),
    problemId: runnerConfig.problemId,
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

main().catch((error) => {
  console.error("FAILED:", error.shortMessage || error.message);
  process.exit(1);
});
