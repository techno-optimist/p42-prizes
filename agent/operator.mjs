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
  canonicalJson,
  problemRunnerConfig,
  queryChunked,
  recoverRevealCalldata,
  runRuntimeBridge,
  sha256Canonical,
} from "./lib.mjs";
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
const REPO_ROOT = resolve(arg("repo-root", resolve(HERE, "..")));
const RUNTIME = resolve(arg("runtime", join(HERE, "runtime")));
const QUEUE = resolve(arg("queue", join(RUNTIME, "runner-queue.json")));
const TRANSCRIPTS = resolve(arg("transcripts", join(RUNTIME, "transcripts")));
const INPUTS = join(RUNTIME, "inputs");
const JOB_SPECS = join(RUNTIME, "jobs");
const ACTIONS = join(RUNTIME, "actions");
const ALERTS = join(RUNTIME, "ALERTS.log");
const MAX_BOND = ethers.parseEther(String(arg("max-challenge-bond", "0.01")));
const MAX_JOBS_PER_SCAN = Number(arg("max-jobs-per-scan", "1"));
const POLL_MS = Number(arg("poll-ms", "12000"));
const CONFIRMATIONS = Number(arg("confirmations", "0"));
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
let fromBlock = Number(arg("from-block", manifest.indexer?.startBlock ?? 0));
let chainId;
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
  return `${chainId}:${String(subs.target).toLowerCase()}:${event.transactionHash.toLowerCase()}:${logIndex}`;
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
  const queue = readQueue();
  const existing = queue.jobs.find((job) => job.job_id === jobId);
  if (existing) {
    const recordedBlockHash = existing.chain_claim?.block_hash;
    if (String(recordedBlockHash).toLowerCase() !== String(event.blockHash).toLowerCase()) {
      throw new Error(`reorg/collision for persisted reveal job ${jobId}`);
    }
    return false;
  }

  const submissionId = event.args.submissionId;
  const submission = await subs.submissions(submissionId);
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
  const sourceEventHash = sha256Canonical({
    schema_version: "p42-reveal-event/v1",
    chain_id: chainClaim.chain_id,
    problem_id: chainClaim.problem_id,
    submission_contract: chainClaim.submission_contract,
    challenge_contract: chainClaim.challenge_contract,
    submission_id: chainClaim.submission_id,
    block_number: chainClaim.block_number,
    block_hash: chainClaim.block_hash,
    transaction_hash: chainClaim.transaction_hash,
    transaction_index: chainClaim.transaction_index,
    log_index: chainClaim.log_index,
    solver: chainClaim.solver,
    solution_cid: chainClaim.solution_cid,
    commit_da_hash: chainClaim.commit_da_hash,
    claimed_score_atoms: chainClaim.claimed_score_atoms,
    claimed_improvement_atoms: chainClaim.claimed_improvement_atoms,
    challenge_ends_at: chainClaim.challenge_ends_at,
    solution_bytes_length: chainClaim.solution_bytes_length,
    onchain_da: chainClaim.onchain_da,
  });
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

async function reconcileBroadcast(job) {
  const action = job.action;
  if (action?.status !== "broadcast" || !action.transaction_hash) return false;
  const receipt = await provider.getTransactionReceipt(action.transaction_hash);
  if (!receipt) return true;
  const transcript = verifyTranscript(job.transcript_path);
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
  await chal.challenge.staticCall(submissionId, reasonHash, { value: bond });
  const tx = await chal.challenge(submissionId, reasonHash, { value: bond });
  recordAction(job, candidate, "broadcast", tx.hash, canonicalJson({
    bond_wei: bond.toString(),
    call_policy_path: policyPath,
    call_policy_hash: callPolicy.policy_hash,
    calldata_hash: callPolicy.calldata_hash,
    scope_hash: callPolicy.scope_hash,
    expires_at: callPolicy.expires_at,
    max_calls: callPolicy.max_calls,
  }));
  log(`  challenge broadcast for #${submissionId}: ${tx.hash} bond=${ethers.formatEther(bond)} ETH`);
  const receipt = await tx.wait();
  recordAction(job, candidate, receipt.status === 1 ? "submitted" : "broadcast_reverted", tx.hash, `receipt status ${receipt.status}`);
}

async function consumeCandidates() {
  const queue = readQueue();
  for (const job of queue.jobs) await consumeCandidate(job);
}

async function scanOnce() {
  const latest = await provider.getBlockNumber();
  const safeLatest = Math.max(0, latest - CONFIRMATIONS);
  if (fromBlock <= safeLatest) {
    const events = await queryChunked(subs, subs.filters.Revealed(), fromBlock, safeLatest);
    for (const event of events) await ingestReveal(event);
    fromBlock = safeLatest + 1;
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
  log(`P42 operator ${wallet.address} chain=${chainId}`);
  log(`queue=${QUEUE} sandbox=docker max_running=1 max_bond=${ethers.formatEther(MAX_BOND)} ETH`);
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
