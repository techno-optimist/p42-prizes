#!/usr/bin/env node
// P42 autonomous operator: chain reveal -> persistent FIFO job -> mandatory
// Docker/cgroup verifier -> canonical challenge candidate -> bounded tx.

import { ethers } from "ethers";
import { spawn, spawnSync } from "node:child_process";
import {
  appendFileSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
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
  runtimePythonExecutable,
  sha256Canonical,
  validateRegistryBinding,
  validateOperatorCursor,
  validateOperatorExecutionMode,
} from "./lib.mjs";
import {
  manifestProblemContracts,
  manifestProblemForRegistryId,
  validateManifestEvidence,
} from "./indexer.mjs";
import { getBlob } from "./da-local.mjs";
import { fetchFromArweave, findTxidByCid } from "./da-arweave.mjs";
import {
  assertApprovedJournalPath,
  assertSignedTransactionRecord,
} from "./signed-transaction.mjs";
import {
  P42ChallengeManager as ChallengeBondOperator,
  acquireEnvelopeLock,
  finalizeChallengeSpend,
  limitsFromProvisioning,
  releaseChallengeReservation,
  releaseEnvelopeLock,
  reserveChallengeSpend,
  runnerHealthAdmission,
  runnerHealthFinalSigningAdmission,
  runChallengeActionIntent,
  validateProvisioningArtifact,
} from "./challenge-envelope.mjs";
import { parseStrictJsonText, readStrictJsonFileSync } from "./strict-json.mjs";
import { verifyRunnerTranscript } from "./runner-transcript.mjs";
import { loadProductionValidationContext } from "./production-validation-context.mjs";

const JSON_LIMITS = Object.freeze({ maxBytes: 4 * 1024 * 1024, maxDepth: 64 });
const IMMUTABLE_JSON_LIMITS = Object.freeze({ ...JSON_LIMITS, canonicalBytes: true, trailingNewline: "require" });
function privateAuthorizationLimits() { return { ...IMMUTABLE_JSON_LIMITS, privateFile: true, trustedRoot: RUNTIME }; }

const HERE = dirname(fileURLToPath(import.meta.url));
function arg(name, def = undefined) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return def;
  const value = process.argv[i + 1];
  return value && !value.startsWith("--") ? value : true;
}

const RPC = arg("rpc", "https://sepolia.base.org");
const NONCE_RPC_SECONDARY = arg("nonce-rpc-secondary", null);
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
const COORDINATION_ROOT_ARG = arg("coordination-root", null);
const COORDINATION_ROOT = resolve(COORDINATION_ROOT_ARG ?? join(RUNTIME, "coordination"));
const CURSOR = resolve(arg("cursor", join(RUNTIME, "operator-cursor.json")));
const QUEUE = resolve(arg("queue", join(RUNTIME, "runner-queue.json")));
const TRANSCRIPTS = resolve(arg("transcripts", join(RUNTIME, "transcripts")));
const INPUTS = join(RUNTIME, "inputs");
const JOB_SPECS = join(RUNTIME, "jobs");
const RETRY_STATE = join(RUNTIME, "retry-state");
const ACTIONS = join(RUNTIME, "actions");
const CHALLENGE_EXPIRED_BACKFILL = join(RUNTIME, "challenge-expired-backfill.json");
const ALERTS = join(RUNTIME, "ALERTS.log");
const ENVELOPE = resolve(arg("challenge-envelope", join(RUNTIME, "challenge-envelope.json")));
const RUNNER_HEALTH = resolve(arg("runner-health", join(RUNTIME, "runner-health.json")));
const RUNNER_HEALTH_PRIOR = resolve(arg("runner-health-prior", join(RUNTIME, "runner-health-prior.json")));
const REQUIRE_HEALTH_V2 = !LOCAL_TEST;
const RUNNER_HEALTH_PUBLIC_KEY = arg("runner-health-public-key", null);
const RUNNER_RECOVERY_PUBLIC_KEY = arg("runner-recovery-public-key", null);
const RUNNER_HOST_ID = arg("runner-host-id", null);
const RUNNER_BOOT_ID = arg("runner-boot-id", null);
const RUNNER_QUEUE_ID = arg("runner-queue-id", null);
const CHALLENGE_PROVISIONING = resolve(arg("challenge-provisioning", join(RUNTIME, "challenge-provisioning.json")));
const AUTO_CLAIM_BOND = arg("auto-claim-bond", true) !== "false";
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
if (!LOCAL_TEST && (!RUNNER_HEALTH_PUBLIC_KEY || !RUNNER_RECOVERY_PUBLIC_KEY || !RUNNER_HOST_ID || !RUNNER_BOOT_ID || !RUNNER_QUEUE_ID)) {
  console.error("production runner-health v2 requires signer, host, boot, and queue identity bindings");
  process.exit(2);
}
if (!LOCAL_TEST && !COORDINATION_ROOT_ARG) {
  console.error("production operator requires --coordination-root shared by every runtime using this chain and signer");
  process.exit(2);
}
if (!LOCAL_TEST && !NONCE_RPC_SECONDARY) {
  console.error("production operator requires --nonce-rpc-secondary from an independent RPC host");
  process.exit(2);
}
if (NONCE_RPC_SECONDARY && new URL(NONCE_RPC_SECONDARY).host === new URL(RPC).host) {
  console.error("primary and secondary nonce RPCs must use different hosts");
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
const manifest = readStrictJsonFileSync(resolve(MANIFEST), JSON_LIMITS);
const selectedManifestProblem = Array.isArray(manifest.problems)
  ? manifestProblemForRegistryId(manifest, REGISTRY_PROBLEM_ID)
  : null;
const selectedBoardContracts = selectedManifestProblem
  ? manifestProblemContracts(manifest, selectedManifestProblem)
  : manifest.contracts;
const problem = resolve(PROBLEM);
const runnerConfig = problemRunnerConfig(problem);
const provider = new ethers.JsonRpcProvider(RPC);
const secondaryNonceProvider = NONCE_RPC_SECONDARY ? new ethers.JsonRpcProvider(NONCE_RPC_SECONDARY) : null;
const nonceProviders = secondaryNonceProvider ? [provider, secondaryNonceProvider] : [provider];
const wallet = new ethers.Wallet(KEY, provider);
const subs = new ethers.Contract(selectedBoardContracts.submissions.address, abi("P42SubmissionManager"), wallet);
const chal = new ethers.Contract(selectedBoardContracts.challenges.address, abi("P42ChallengeManager"), wallet);
const registry = new ethers.Contract(manifest.contracts.registry.address, abi("P42ProblemRegistry"), wallet);
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const log = (...values) => console.log(...values);

for (const path of [RUNTIME, TRANSCRIPTS, INPUTS, JOB_SPECS, RETRY_STATE, ACTIONS]) mkdirSync(path, { recursive: true });
mkdirSync(COORDINATION_ROOT, { recursive: true, mode: 0o700 });
const coordinationMetadata = lstatSync(COORDINATION_ROOT);
if (!coordinationMetadata.isDirectory() || coordinationMetadata.isSymbolicLink()
    || (coordinationMetadata.mode & 0o077) !== 0) {
  throw new Error("operator coordination root must be a private non-symlink directory");
}
const START_BLOCK = Number(arg("from-block", manifest.indexer?.startBlock ?? 0));
let chainId;
let finalityConfirmations;
let reorgOverlapBlocks;
let executionMode;
let agentWallet = null;
let challengeBondOperator = null;
let challengeProvisioning;
let challengeLimits;
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
  const env = { ...process.env, PYTHONPATH: `${REPO_ROOT}/src` };
  for (const name of Object.keys(env)) {
    if (/(PRIVATE_KEY|API_KEY|TOKEN|SECRET|PASSWORD|RPC_URL)/i.test(name)) delete env[name];
  }
  const completed = spawnSync(runtimePythonExecutable(env), [`${REPO_ROOT}/agent/runtime_bridge.py`, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (completed.error) throw completed.error;
  if (completed.status !== 0) {
    throw new Error((completed.stderr || completed.stdout || `runtime bridge exited ${completed.status}`).trim());
  }
  if (!completed.stdout.trim()) throw new Error("runtime bridge produced no JSON");
  return parseStrictJsonText(completed.stdout, {
    maxBytes: 16 * 1024 * 1024,
    maxDepth: 64,
    canonicalBytes: true,
    trailingNewline: "require",
  });
}

async function acquireRunnerAuthorizationFence() {
  const env = { ...process.env, PYTHONPATH: `${REPO_ROOT}/src` };
  for (const name of Object.keys(env)) if (/(PRIVATE_KEY|API_KEY|TOKEN|SECRET|PASSWORD|RPC_URL)/i.test(name)) delete env[name];
  const child = spawn(runtimePythonExecutable(env), [`${REPO_ROOT}/agent/runtime_bridge.py`, "authorization-fence", "--queue", QUEUE], { cwd: REPO_ROOT, env, stdio: ["pipe", "pipe", "pipe"] });
  let stderr = ""; child.stderr.setEncoding("utf8"); child.stderr.on("data", (chunk) => { stderr += chunk; });
  await new Promise((resolveReady, rejectReady) => {
    let stdout = ""; const timeout = setTimeout(() => { child.kill("SIGKILL"); rejectReady(new Error("runner authorization fence timeout")); }, 5000);
    child.stdout.setEncoding("utf8"); child.stdout.on("data", (chunk) => { stdout += chunk; if (stdout === "READY\n") { clearTimeout(timeout); resolveReady(); } else if (!"READY\n".startsWith(stdout)) { clearTimeout(timeout); child.kill("SIGKILL"); rejectReady(new Error("runner authorization fence emitted invalid readiness")); } });
    child.once("exit", (code) => { clearTimeout(timeout); rejectReady(new Error(stderr || `runner authorization fence exited ${code}`)); });
  });
  let released = false;
  return () => {
    if (released) return; released = true; child.stdin.end("R");
  };
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
  return readStrictJsonFileSync(path, JSON_LIMITS);
}

function runnerHealth() {
  if (LOCAL_TEST && !REQUIRE_HEALTH_V2) return { schema_version: "p42-runner-health/v1", observed_at_utc: new Date().toISOString(), oom_kills: 0, worker_restarts: 0, queue_corruption_events: 0, max_active_running: 1, decision: "start", swap_guard: "green", host_capacity: "green", concurrency_guard: "green" };
  const health = existsSync(RUNNER_HEALTH) ? readStrictJsonFileSync(RUNNER_HEALTH, privateAuthorizationLimits()) : null;
  if (!health || (REQUIRE_HEALTH_V2 && health.schema_version !== "p42-runner-health/v2")) return null;
  const observed = Date.parse(health.observed_at_utc);
  if (!Number.isFinite(observed) || observed > Date.now() || Date.now() - observed > 5 * 60_000) return null;
  return health;
}

function assertFreshRunnerHealthAuthorization(health, prior = null, highWater = null, reservationBinding = null) {
  const expected = { public_key: RUNNER_HEALTH_PUBLIC_KEY, recovery_public_key: RUNNER_RECOVERY_PUBLIC_KEY, recovery_cooldown_ms: 86_400_000, host_id: RUNNER_HOST_ID, boot_id: RUNNER_BOOT_ID, queue_id: RUNNER_QUEUE_ID, chain_id: chainId, contract: String(chal.target) };
  const admission = runnerHealthAdmission(health, { requireV2: REQUIRE_HEALTH_V2, expected, prior, highWater, reservationBinding });
  if (!admission.allowed) throw new Error(`runner health authorization rejected: ${admission.detail || admission.reason}`);
  if (health.schema_version === "p42-runner-health/v2") {
    const queue = existsSync(QUEUE) ? readStrictJsonFileSync(QUEUE, privateAuthorizationLimits()) : null;
    if (!queue) throw new Error("runner queue is absent during health authorization");
    const queueHash = `sha256:${ethers.sha256(ethers.toUtf8Bytes(`${canonicalJson(queue)}\n`)).slice(2)}`;
    if (queueHash !== health.queue.queue_hash) throw new Error("runner queue changed after health authorization");
  }
  return health;
}

async function assertCanonicalRunnerHealthBlock(health, authorizationStartedAt = Date.now()) {
  if (health?.schema_version !== "p42-runner-health/v2") {
    if (REQUIRE_HEALTH_V2) throw new Error("runner health v2 is required");
    return;
  }
  const block = await provider.getBlock(health.chain.block_number);
  const latest = await provider.getBlock("latest");
  const incident = health.counter_acknowledgement.recovery_authorization?.incident_artifact;
  const incidentBlock = incident ? await provider.getBlock(incident.block_number) : null;
  const admission = runnerHealthFinalSigningAdmission(health, { healthBlock: block, latestBlock: latest, incidentBlock, confirmations: finalityConfirmations, authorizationStartedAt });
  if (!admission.allowed) throw new Error(`runner health final signing evidence rejected: ${admission.detail}`);
}

async function finalSigningAuthorizationFence(highWater, reservationBinding) {
  const release = await acquireRunnerAuthorizationFence();
  try {
    const health = runnerHealth();
    const prior = existsSync(RUNNER_HEALTH_PRIOR) ? readStrictJsonFileSync(RUNNER_HEALTH_PRIOR, privateAuthorizationLimits()) : null;
    assertFreshRunnerHealthAuthorization(health, prior, highWater, reservationBinding);
    await assertCanonicalRunnerHealthBlock(health);
    return { health, acquiredAt: Date.now(), release };
  } catch (error) { release(); throw error; }
}

async function canonicalOpenEvidence() {
  const latest = await provider.getBlockNumber();
  const finalizedThrough = latest - finalityConfirmations;
  if (finalizedThrough < START_BLOCK) throw new Error("canonical open evidence has no finalized range");
  const events = await queryChunked(chal, chal.filters.Challenged(), START_BLOCK, finalizedThrough);
  const ids = [...new Set(events.map((event) => event.args.submissionId.toString()))];
  const openChallenges = [];
  for (const submissionId of ids) {
    const [current, instanceHash] = await Promise.all([
      chal.challenges(BigInt(submissionId), { blockTag: finalizedThrough }),
      chal.challengeInstanceHashOf(BigInt(submissionId), { blockTag: finalizedThrough }),
    ]);
    if (String(current.challenger).toLowerCase() !== ethers.ZeroAddress && current.resolved !== true) {
      if (!ethers.isHexString(instanceHash, 32) || instanceHash === ethers.ZeroHash) throw new Error("finalized open challenge has no instance hash");
      openChallenges.push({ submission_id: submissionId, challenge_instance_hash: instanceHash.toLowerCase() });
    }
  }
  return {
    schema_version: "p42-canonical-open-evidence/v1", chain_id: chainId,
    challenge_manager: String(chal.target).toLowerCase(), finalized_through_block: finalizedThrough,
    observed_at_utc: new Date().toISOString(), complete: true, open_challenges: openChallenges,
  };
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
  try {
    if (BigInt(claim.challenge_ends_at) <= BigInt(latestTimestamp)) return true;
  } catch {
    return false;
  }
  if (job.retry_not_before_utc !== undefined) {
    if (typeof job.retry_not_before_utc !== "string") return false;
    const retryNotBeforeMs = Date.parse(job.retry_not_before_utc);
    if (!Number.isFinite(retryNotBeforeMs) || retryNotBeforeMs > nowMs) return false;
  }
  return true;
}

function sourceEventHashFor(event, submission) {
  if (event.rechallengeGeneration) return event.rechallengeGeneration.source_event_hash;
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

function logIdentity(event) {
  return {
    block_number: event.blockNumber,
    block_hash: String(event.blockHash).toLowerCase(),
    transaction_hash: String(event.transactionHash).toLowerCase(),
    transaction_index: Number(event.transactionIndex ?? 0),
    log_index: Number(event.index ?? event.logIndex),
  };
}

export function buildRechallengeGenerationEvent({
  chainId: boundChainId,
  problemId,
  submissionContract,
  challengeContract,
  expirationEvent,
  revealEvent,
  submission,
  revealInstanceHash,
  expirationBlock,
}) {
  const submissionId = expirationEvent.args.submissionId.toString();
  if (revealEvent.args.submissionId.toString() !== submissionId) {
    throw new Error("rechallenge generation reveal submission mismatch");
  }
  const revealHash = String(revealInstanceHash).toLowerCase();
  if (!ethers.isHexString(revealHash, 32) || revealHash === ethers.ZeroHash) {
    throw new Error("rechallenge generation has an invalid reveal instance hash");
  }
  if (String(revealEvent.args.revealInstanceHash).toLowerCase() !== revealHash) {
    throw new Error("rechallenge generation reveal instance mismatch");
  }
  if (Number(submission.status) !== 2) {
    throw new Error(`rechallenge generation submission status is ${submission.status}`);
  }
  const challengeEndsAt = BigInt(submission.challengeEndsAt);
  if (challengeEndsAt <= BigInt(expirationBlock.timestamp)) {
    throw new Error("rechallenge generation has no fresh challenge window");
  }
  const expiredChallengeInstanceHash = String(expirationEvent.args.challengeInstanceHash).toLowerCase();
  if (!ethers.isHexString(expiredChallengeInstanceHash, 32) || expiredChallengeInstanceHash === ethers.ZeroHash) {
    throw new Error("rechallenge generation has an invalid expired challenge instance hash");
  }
  const revealSource = {
    ...logIdentity(revealEvent),
    reveal_instance_hash: revealHash,
  };
  const generationBinding = {
    schema_version: "p42-rechallenge-generation/v1",
    chain_id: Number(boundChainId),
    problem_id: problemId,
    submission_contract: String(submissionContract).toLowerCase(),
    challenge_contract: String(challengeContract).toLowerCase(),
    submission_id: submissionId,
    generation_event: {
      event_name: "ChallengeExpired",
      ...logIdentity(expirationEvent),
      challenge_instance_hash: expiredChallengeInstanceHash,
    },
    reveal_source: revealSource,
    challenge_ends_at: challengeEndsAt.toString(),
  };
  const sourceEventHash = sha256Canonical(generationBinding);
  return {
    ...revealEvent,
    blockNumber: expirationEvent.blockNumber,
    blockHash: expirationEvent.blockHash,
    transactionHash: expirationEvent.transactionHash,
    transactionIndex: expirationEvent.transactionIndex ?? 0,
    index: expirationEvent.index ?? expirationEvent.logIndex,
    logIndex: expirationEvent.index ?? expirationEvent.logIndex,
    args: {
      submissionId: revealEvent.args.submissionId,
      solver: revealEvent.args.solver,
      solutionCid: revealEvent.args.solutionCid,
      improvementAtoms: revealEvent.args.improvementAtoms,
      claimedScoreAtoms: revealEvent.args.claimedScoreAtoms,
      challengeEndsAt,
      solutionBytesLength: revealEvent.args.solutionBytesLength,
      revealInstanceHash: revealEvent.args.revealInstanceHash,
    },
    rechallengeGeneration: {
      binding: generationBinding,
      source_event_hash: sourceEventHash,
      reveal_transaction_hash: revealEvent.transactionHash,
    },
  };
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

async function canonicalRechallengeRecords(events) {
  const records = [];
  for (const expirationEvent of events) {
    const submissionId = expirationEvent.args.submissionId;
    const [submission, revealInstanceHash, expirationBlock, revealEvents] = await Promise.all([
      subs.submissions(submissionId, { blockTag: expirationEvent.blockNumber }),
      subs.revealInstanceHashOf(submissionId, { blockTag: expirationEvent.blockNumber }),
      provider.getBlock(expirationEvent.blockNumber),
      queryChunked(subs, subs.filters.Revealed(submissionId), START_BLOCK, expirationEvent.blockNumber),
    ]);
    if (!expirationBlock?.hash
      || expirationBlock.hash.toLowerCase() !== String(expirationEvent.blockHash).toLowerCase()) {
      throw new Error(`expired challenge #${submissionId} moved during canonical reconstruction`);
    }
    blockCache.set(expirationEvent.blockNumber, expirationBlock);
    if (Number(submission.status) !== 2 || BigInt(submission.challengeEndsAt) <= BigInt(expirationBlock.timestamp)) {
      continue;
    }
    const revealHash = String(revealInstanceHash).toLowerCase();
    const matching = revealEvents.filter(
      (event) => String(event.args.revealInstanceHash).toLowerCase() === revealHash,
    );
    if (matching.length !== 1) {
      throw new Error(`expired challenge #${submissionId} has ${matching.length} canonical reveal sources`);
    }
    records.push(buildRechallengeGenerationEvent({
      chainId,
      problemId: runnerConfig.problemId,
      submissionContract: String(subs.target),
      challengeContract: String(chal.target),
      expirationEvent,
      revealEvent: matching[0],
      submission,
      revealInstanceHash,
      expirationBlock,
    }));
  }
  return records;
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

function challengeExpiredBackfillBinding() {
  return {
    schema_version: "p42-challenge-expired-backfill-binding/v1",
    cursor_binding_hash: sha256Canonical(cursorBinding),
    chain_id: chainId,
    challenge_contract: String(chal.target).toLowerCase(),
    start_block: START_BLOCK,
  };
}

export function buildChallengeExpiredBackfillMarker({ binding, throughBlock }) {
  if (!binding || binding.schema_version !== "p42-challenge-expired-backfill-binding/v1") {
    throw new Error("challenge-expired backfill binding is invalid");
  }
  if (!Number.isSafeInteger(throughBlock) || throughBlock < Number(binding.start_block)) {
    throw new Error("challenge-expired backfill through block is invalid");
  }
  const marker = {
    schema_version: "p42-challenge-expired-backfill/v1",
    binding,
    through_block: throughBlock,
  };
  return { ...marker, marker_hash: sha256Canonical(marker) };
}

export function validateChallengeExpiredBackfillMarker(marker, expectedBinding) {
  if (!marker || marker.schema_version !== "p42-challenge-expired-backfill/v1") {
    throw new Error("challenge-expired backfill marker schema is invalid");
  }
  if (canonicalJson(marker.binding) !== canonicalJson(expectedBinding)) {
    throw new Error("challenge-expired backfill marker identity mismatch");
  }
  if (!Number.isSafeInteger(marker.through_block) || marker.through_block < Number(expectedBinding.start_block)) {
    throw new Error("challenge-expired backfill marker range is invalid");
  }
  const { marker_hash: markerHash, ...unsigned } = marker;
  if (markerHash !== sha256Canonical(unsigned)) {
    throw new Error("challenge-expired backfill marker hash mismatch");
  }
  return marker;
}

export function challengeExpiredBackfillNeeded(marker, expectedBinding) {
  if (marker === null) return true;
  validateChallengeExpiredBackfillMarker(marker, expectedBinding);
  return false;
}

async function backfillChallengeExpiredOnce(safeLatest, chainTimestamp) {
  const binding = challengeExpiredBackfillBinding();
  const existing = readJsonOrNull(CHALLENGE_EXPIRED_BACKFILL);
  if (!challengeExpiredBackfillNeeded(existing, binding)) return false;
  if (safeLatest < START_BLOCK) return false;
  const expirationEvents = await queryChunked(
    chal,
    chal.filters.ChallengeExpired(),
    START_BLOCK,
    safeLatest,
  );
  const rechallengeEvents = await canonicalRechallengeRecords(expirationEvents);
  for (const event of rechallengeEvents) await ingestReveal(event, chainTimestamp);
  writeJsonAtomic(CHALLENGE_EXPIRED_BACKFILL, buildChallengeExpiredBackfillMarker({
    binding,
    throughBlock: safeLatest,
  }));
  log(`  ChallengeExpired backfill complete: ${START_BLOCK}..${safeLatest}`);
  return true;
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
  bridge(...args);
}

function parseDetailJson(detail) {
  if (typeof detail !== "string" || !detail.trim().startsWith("{")) return {};
  try { return parseStrictJsonText(detail, { maxBytes: 64 * 1024, maxDepth: 32 }); }
  catch { return {}; }
}

function appendAlert(message) {
  const line = `${new Date().toISOString()} ${message}`;
  console.error(`  !!! ${line}`);
  appendFileSync(ALERTS, `${line}\n`, { encoding: "utf8", mode: 0o600 });
}

function terminalAlertRecord(alert) {
  if (alert.schema_version === "p42-runner-action-alert/v1") {
    return {
      schema_version: alert.schema_version,
      job_id: alert.job_id,
      source_event_hash: alert.source_event_hash,
      candidate_hash: alert.candidate_hash,
      action_status: alert.action_status,
      action_hash: alert.action_hash,
      message: alert.message,
      created_at_utc: alert.created_at_utc,
      alert_id: alert.alert_id,
    };
  }
  return {
    schema_version: alert.schema_version,
    job_id: alert.job_id,
    disposition_hash: alert.disposition_hash,
    message: alert.message,
    created_at_utc: alert.created_at_utc,
    alert_id: alert.alert_id,
  };
}

function reconcileTerminalAlertOnce(job, alert) {
  const result = bridge(
    "reconcile-terminal-alert",
    "--queue", QUEUE,
    "--alerts", ALERTS,
    "--job-id", job.job_id,
  );
  const expectedRecord = canonicalJson(terminalAlertRecord(alert));
  if (
    result.alert_id !== alert.alert_id
    || result.record !== expectedRecord
    || result.alert?.status !== "delivered"
  ) {
    throw new Error(`terminal alert reconciliation for ${job.job_id} is not disposition-bound`);
  }
  if (result.created) console.error(`  !!! ${expectedRecord}`);
  return result.created;
}

export async function reconcileTerminalAlerts({ afterAppend = null } = {}) {
  const queue = readQueue();
  for (const job of queue.jobs) {
    const alert = job.terminal_alert ?? job.action_alert;
    if (!alert) continue;
    if (typeof alert !== "object") {
      throw new Error(`terminal disposition ${job.job_id} has no durable alert record`);
    }
    if (!["pending", "delivered"].includes(alert.status)) {
      throw new Error(`terminal alert ${alert.alert_id || job.job_id} has invalid status`);
    }
    const appended = reconcileTerminalAlertOnce(job, alert);
    if (appended && afterAppend) await afterAppend(job, alert);
  }
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
    transactionHash: claim.reveal_transaction_hash ?? claim.transaction_hash,
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

async function ingestReveal(event, chainTimestamp) {
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
  const payloadEvent = event.rechallengeGeneration
    ? { ...event, transactionHash: event.rechallengeGeneration.reveal_transaction_hash }
    : event;
  const payload = await recoverPayload(payloadEvent, submission);
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
  if (event.rechallengeGeneration) {
    chainClaim.rechallenge_generation = event.rechallengeGeneration.binding;
    chainClaim.reveal_transaction_hash = event.rechallengeGeneration.reveal_transaction_hash.toLowerCase();
  }
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
      const remainingChallengeMs = Math.max(
        0, (Number(chainClaim.challenge_ends_at) - Number(chainTimestamp)) * 1000,
      );
      job.retry_not_before_utc = new Date(
        Date.now() + Math.min(RETRY_BACKOFF_MS, remainingChallengeMs),
      ).toISOString();
    }
  }

  const specPath = join(JOB_SPECS, `${sourceEventHash.slice(7)}.json`);
  writeCanonicalAtomic(specPath, job);
  const result = bridge(
    "enqueue",
    "--queue", QUEUE,
    "--job", specPath,
    "--chain-now-utc", new Date(Number(chainTimestamp) * 1000).toISOString().replace(".000Z", "Z"),
  );
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

function recordAction(
  job,
  candidate,
  status,
  transactionHash = null,
  detail = null,
  alertMessage = null,
) {
  const args = [
    "record-action", "--queue", QUEUE,
    "--job-id", job.job_id,
    "--candidate-hash", candidate.candidate_hash,
    "--status", status,
  ];
  if (transactionHash) args.push("--transaction-hash", transactionHash);
  if (detail) args.push("--detail", detail);
  if (alertMessage) args.push("--alert-message", alertMessage);
  return bridge(...args);
}

function recordLocalDisposition(job, reasonCode, detail = null) {
  const args = [
    "terminalize-local", "--queue", QUEUE,
    "--job-id", job.job_id,
    "--reason-code", reasonCode,
  ];
  if (detail) args.push("--detail", String(detail).slice(0, 512));
  return bridge(...args);
}

function signedActionPath(candidate, callPolicy) {
  return join(ACTIONS, `${candidate.candidate_hash.slice(7)}-${callPolicy.policy_hash.slice(7, 23)}.signed-tx.json`);
}

function walletNonceActionId(candidate, callPolicy) {
  return sha256Canonical({
    schema_version: "p42-wallet-nonce-action/v1",
    candidate_hash: candidate.candidate_hash,
    call_policy_hash: callPolicy.policy_hash,
  });
}

export function walletActionLockPath({ coordinationRoot, boundChainId, signer }) {
  if (!Number.isSafeInteger(boundChainId) || boundChainId <= 0) {
    throw new Error("wallet action lock chain id must be a positive safe integer");
  }
  const lockId = sha256Canonical({
    schema_version: "p42-wallet-action-lock/v1",
    chain_id: boundChainId,
    signer: ethers.getAddress(signer).toLowerCase(),
  });
  if (!coordinationRoot) throw new Error("wallet action lock coordination root is required");
  return join(resolve(coordinationRoot), `${lockId.slice(7)}.wallet.lock`);
}

export function walletNonceAllocatorPath({ coordinationRoot, boundChainId, signer }) {
  return walletActionLockPath({ coordinationRoot, boundChainId, signer }).replace(/\.wallet\.lock$/, ".nonce-allocator.json");
}

function walletNonceBinding(boundChainId, signer) {
  return {
    schema_version: "p42-wallet-nonce-binding/v1",
    chain_id: boundChainId,
    signer: ethers.getAddress(signer).toLowerCase(),
  };
}

function durableReplaceCanonical(path, value) {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(fd, `${canonicalJson(value)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, path);
  const directoryFd = openSync(dirname(path), "r");
  try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
}

function validateWalletNonceAllocator(journal, binding) {
  if (!journal || journal.schema_version !== "p42-wallet-nonce-allocator/v1") {
    throw new Error("wallet nonce allocator journal schema is invalid");
  }
  if (canonicalJson(journal.binding) !== canonicalJson(binding)) {
    throw new Error("wallet nonce allocator journal chain or signer binding mismatch");
  }
  if (!Number.isSafeInteger(journal.next_nonce) || journal.next_nonce < 0
      || !Number.isSafeInteger(journal.observed_finalized_nonce) || journal.observed_finalized_nonce < 0
      || !Number.isSafeInteger(journal.observed_pending_nonce) || journal.observed_pending_nonce < 0
      || !Array.isArray(journal.allocations)) {
    throw new Error("wallet nonce allocator journal counters are invalid");
  }
  const nonces = new Set();
  for (const allocation of journal.allocations) {
    if (typeof allocation.action_id !== "string" || allocation.action_id.length < 1
        || !Number.isSafeInteger(allocation.nonce) || allocation.nonce < 0
        || !["reserved", "signed", "broadcast", "fenced"].includes(allocation.state)
        || (allocation.transaction_hash !== null && !ethers.isHexString(allocation.transaction_hash, 32))) {
      throw new Error("wallet nonce allocator allocation is invalid");
    }
    if (nonces.has(allocation.nonce)) throw new Error("wallet nonce allocator reused a nonce");
    nonces.add(allocation.nonce);
  }
  const floor = journal.allocations.reduce((highest, allocation) => Math.max(highest, allocation.nonce + 1), 0);
  if (journal.next_nonce < floor || journal.observed_pending_nonce < journal.observed_finalized_nonce) {
    throw new Error("wallet nonce allocator journal regressed");
  }
  return journal;
}

function readWalletNonceAllocator(path, binding) {
  if (!existsSync(path)) return {
    schema_version: "p42-wallet-nonce-allocator/v1",
    binding,
    next_nonce: 0,
    observed_finalized_nonce: 0,
    observed_pending_nonce: 0,
    allocations: [],
  };
  return validateWalletNonceAllocator(
    readStrictJsonFileSync(path, { ...IMMUTABLE_JSON_LIMITS, privateFile: true, trustedRoot: dirname(path) }),
    binding,
  );
}

async function walletNonceObservation(rpcProviders, signer) {
  if (!Array.isArray(rpcProviders) || rpcProviders.length < 1) throw new Error("wallet nonce RPC set is empty");
  const observations = await Promise.all(rpcProviders.map(async (rpcProvider) => {
    const [finalizedNonce, pendingNonce] = await Promise.all([
      rpcProvider.getTransactionCount(signer, "finalized"),
      rpcProvider.getTransactionCount(signer, "pending"),
    ]);
    return { finalizedNonce, pendingNonce };
  }));
  const finalizedNonce = Math.max(...observations.map((value) => value.finalizedNonce));
  const pendingNonce = Math.max(...observations.map((value) => value.pendingNonce));
  if (!Number.isSafeInteger(finalizedNonce) || finalizedNonce < 0
      || !Number.isSafeInteger(pendingNonce) || pendingNonce < finalizedNonce) {
    throw new Error("RPC returned invalid finalized or pending wallet nonce evidence");
  }
  return { finalizedNonce, pendingNonce };
}

function persistWalletNonceObservation(journal, observation) {
  journal.observed_finalized_nonce = Math.max(journal.observed_finalized_nonce, observation.finalizedNonce);
  journal.observed_pending_nonce = Math.max(
    journal.observed_pending_nonce,
    journal.observed_finalized_nonce,
    observation.pendingNonce,
  );
}

function assertAllocatorSignedRecord(record, binding) {
  if (!record || record.schema_version !== "p42-signed-transaction/v1" || !ethers.isHexString(record.raw_tx)) {
    throw new Error("wallet nonce allocator signed record is invalid");
  }
  const transaction = ethers.Transaction.from(record.raw_tx);
  if (!transaction.from || transaction.from.toLowerCase() !== binding.signer
      || Number(transaction.chainId) !== binding.chain_id
      || transaction.nonce !== Number(record.nonce)
      || ethers.keccak256(record.raw_tx).toLowerCase() !== String(record.hash).toLowerCase()) {
    throw new Error("wallet nonce allocator signed record identity mismatch");
  }
  return transaction;
}

export async function reserveWalletNonceLocked({
  rpcProvider, rpcProviders = null, coordinationRoot, boundChainId, signer, actionId, existingSignedRecord = null,
}) {
  if (typeof actionId !== "string" || actionId.length < 1) throw new Error("wallet nonce allocation action id is required");
  const binding = walletNonceBinding(boundChainId, signer);
  const path = walletNonceAllocatorPath({ coordinationRoot, boundChainId, signer });
  const journal = readWalletNonceAllocator(path, binding);
  const observation = await walletNonceObservation(rpcProviders ?? [rpcProvider], binding.signer);
  persistWalletNonceObservation(journal, observation);

  if (existingSignedRecord) {
    const transaction = assertAllocatorSignedRecord(existingSignedRecord, binding);
    const conflicting = journal.allocations.find(
      (allocation) => allocation.nonce === transaction.nonce && allocation.action_id !== actionId,
    );
    if (conflicting) throw new Error(`wallet nonce ${transaction.nonce} belongs to another action`);
    let allocation = journal.allocations.find(
      (candidate) => candidate.action_id === actionId && candidate.nonce === transaction.nonce,
    );
    if (!allocation) {
      allocation = { action_id: actionId, nonce: transaction.nonce, state: "signed", transaction_hash: existingSignedRecord.hash.toLowerCase() };
      journal.allocations.push(allocation);
    } else if (allocation.transaction_hash && allocation.transaction_hash !== existingSignedRecord.hash.toLowerCase()) {
      throw new Error("wallet nonce allocation is bound to a different signed transaction");
    } else {
      allocation.transaction_hash = existingSignedRecord.hash.toLowerCase();
      if (allocation.state === "reserved") allocation.state = "signed";
    }
    journal.next_nonce = Math.max(journal.next_nonce, transaction.nonce + 1);
    durableReplaceCanonical(path, validateWalletNonceAllocator(journal, binding));
    return { path, nonce: transaction.nonce, recovered: true };
  }

  const prior = [...journal.allocations].reverse().find(
    (allocation) => allocation.action_id === actionId && allocation.state === "reserved",
  );
  if (prior && prior.nonce >= observation.finalizedNonce && prior.nonce >= observation.pendingNonce) {
    durableReplaceCanonical(path, validateWalletNonceAllocator(journal, binding));
    return { path, nonce: prior.nonce, recovered: true };
  }
  if (prior) prior.state = "fenced";
  const nonce = Math.max(journal.next_nonce, observation.finalizedNonce, observation.pendingNonce);
  journal.allocations.push({ action_id: actionId, nonce, state: "reserved", transaction_hash: null });
  journal.next_nonce = nonce + 1;
  durableReplaceCanonical(path, validateWalletNonceAllocator(journal, binding));
  return { path, nonce, recovered: false };
}

export function recordWalletNonceSignedLocked({ coordinationRoot, boundChainId, signer, actionId, signedRecord }) {
  const binding = walletNonceBinding(boundChainId, signer);
  const transaction = assertAllocatorSignedRecord(signedRecord, binding);
  const path = walletNonceAllocatorPath({ coordinationRoot, boundChainId, signer });
  const journal = readWalletNonceAllocator(path, binding);
  const allocation = journal.allocations.find(
    (candidate) => candidate.action_id === actionId && candidate.nonce === transaction.nonce,
  );
  if (!allocation || allocation.state === "fenced") throw new Error("signed transaction lacks an active durable wallet nonce reservation");
  if (allocation.transaction_hash && allocation.transaction_hash !== signedRecord.hash.toLowerCase()) {
    throw new Error("wallet nonce reservation already names another transaction");
  }
  allocation.transaction_hash = signedRecord.hash.toLowerCase();
  allocation.state = allocation.state === "broadcast" ? "broadcast" : "signed";
  durableReplaceCanonical(path, validateWalletNonceAllocator(journal, binding));
  return { path, nonce: transaction.nonce };
}

export function recordWalletNonceBroadcastLocked(args) {
  const signed = recordWalletNonceSignedLocked(args);
  const binding = walletNonceBinding(args.boundChainId, args.signer);
  const path = walletNonceAllocatorPath(args);
  const journal = readWalletNonceAllocator(path, binding);
  const allocation = journal.allocations.find(
    (candidate) => candidate.action_id === args.actionId && candidate.nonce === signed.nonce,
  );
  allocation.state = "broadcast";
  durableReplaceCanonical(path, validateWalletNonceAllocator(journal, binding));
  return signed;
}

export async function walletNonceBroadcastDecisionLocked({
  rpcProvider, rpcProviders = null, coordinationRoot, boundChainId, signer, actionId, signedRecord,
}) {
  recordWalletNonceSignedLocked({ coordinationRoot, boundChainId, signer, actionId, signedRecord });
  const binding = walletNonceBinding(boundChainId, signer);
  const transaction = assertAllocatorSignedRecord(signedRecord, binding);
  const path = walletNonceAllocatorPath({ coordinationRoot, boundChainId, signer });
  const journal = readWalletNonceAllocator(path, binding);
  const allocation = journal.allocations.find(
    (candidate) => candidate.action_id === actionId && candidate.nonce === transaction.nonce,
  );
  const known = await rpcProvider.getTransaction(signedRecord.hash);
  if (known) {
    if (String(known.hash).toLowerCase() !== signedRecord.hash.toLowerCase()
        || Number(known.nonce) !== transaction.nonce
        || String(known.from).toLowerCase() !== binding.signer) {
      throw new Error("RPC transaction identity disagrees with wallet nonce allocation");
    }
    allocation.state = "broadcast";
    durableReplaceCanonical(path, validateWalletNonceAllocator(journal, binding));
    return { broadcast: false, known: true, nonce: transaction.nonce, transaction: known };
  }
  const observation = await walletNonceObservation(rpcProviders ?? [rpcProvider], binding.signer);
  persistWalletNonceObservation(journal, observation);
  if (observation.finalizedNonce > transaction.nonce || observation.pendingNonce > transaction.nonce) {
    allocation.state = "fenced";
    durableReplaceCanonical(path, validateWalletNonceAllocator(journal, binding));
    return {
      broadcast: false,
      known: false,
      nonce: transaction.nonce,
      reason: `chain nonce advanced beyond allocated nonce ${transaction.nonce}; refusing replacement transaction`,
    };
  }
  durableReplaceCanonical(path, validateWalletNonceAllocator(journal, binding));
  return { broadcast: true, known: false, nonce: transaction.nonce };
}

export async function withWalletActionLock({ coordinationRoot, boundChainId, signer, timeoutMs = 30_000 }, operation) {
  if (typeof operation !== "function") throw new Error("wallet action lock operation is required");
  const lockPath = walletActionLockPath({ coordinationRoot, boundChainId, signer });
  const owner = acquireEnvelopeLock(lockPath, { timeoutMs });
  try {
    return await operation();
  } finally {
    releaseEnvelopeLock(lockPath, owner);
  }
}

function withOperatorWalletActionLock(operation) {
  return withWalletActionLock({
    coordinationRoot: COORDINATION_ROOT,
    boundChainId: chainId,
    signer: wallet.address,
  }, operation);
}

export function submissionActionLockPath({ coordinationRoot, boundChainId, challengeContract, submissionId }) {
  if (!coordinationRoot) throw new Error("submission action lock coordination root is required");
  if (!Number.isSafeInteger(boundChainId) || boundChainId <= 0) {
    throw new Error("submission action lock chain id must be a positive safe integer");
  }
  const lockId = sha256Canonical({
    schema_version: "p42-submission-challenge-lock/v1",
    chain_id: boundChainId,
    challenge_contract: ethers.getAddress(challengeContract).toLowerCase(),
    submission_id: BigInt(submissionId).toString(),
  });
  return join(resolve(coordinationRoot), `${lockId.slice(7)}.submission.lock`);
}

async function signedActionRecord(candidate, callPolicy, request, authorization = null) {
  const path = signedActionPath(candidate, callPolicy);
  if (existsSync(path)) return { path, record: readStrictJsonFileSync(assertApprovedJournalPath(path, ACTIONS, path), IMMUTABLE_JSON_LIMITS) };
  if (!authorization || Date.now() - authorization.acquiredAt > 5000) throw new Error("runner signing authorization fence is missing or too old");
  await assertCanonicalRunnerHealthBlock(authorization.health, authorization.acquiredAt);
  if (Date.now() - authorization.acquiredAt > 5000) throw new Error("runner signing authorization aged out during canonical recheck");
  const record = await buildSignedTransactionRecord({
    wallet,
    request,
    label: `challenge:${candidate.submission_id}:${candidate.candidate_hash}`,
  });
  writeCanonicalAtomic(path, record);
  return { path, record };
}

function assertOperatorSignedRecord(record, candidate, callPolicy, action = null, detail = null) {
  const expectedRequest = executionMode.mode === "direct-eoa-local-test"
    ? exactCallRequestFromPolicy(callPolicy)
    : {
      to: executionMode.agentWalletAddress,
      value: 0n,
      data: agentWallet.interface.encodeFunctionData("execute", [
        callPolicy.target,
        callPolicy.call_value_wei,
        callPolicy.calldata,
      ]),
    };
  const expectedLabel = `challenge:${candidate.submission_id}:${candidate.candidate_hash}`;
  const checked = assertSignedTransactionRecord(record, {
    signer: wallet.address,
    chainId,
    ...expectedRequest,
    hashes: [action?.transaction_hash, detail?.signed_tx_hash],
    nonce: detail?.signed_tx_nonce,
    label: expectedLabel,
  });
  if (detail) {
    if (detail.call_policy_hash !== callPolicy.policy_hash
      || detail.calldata_hash !== callPolicy.calldata_hash
      || detail.scope_hash !== callPolicy.scope_hash
      || detail.signed_tx_data_hash !== record.data_hash) {
      throw new Error("signed transaction journal disagrees with declared policy or journal hashes");
    }
  }
  return checked.record;
}

function assertPersistedChallengePolicy(candidate, detail) {
  const reasonHash = ethers.keccak256(
    ethers.toUtf8Bytes(`p42-challenge-candidate/v1:${candidate.candidate_hash}`),
  );
  const expected = buildChallengeCallPolicy({
    challengeInterface: chal.interface,
    challengeContract: String(chal.target),
    chainId,
    problemId: runnerConfig.problemId,
    submissionId: BigInt(candidate.submission_id),
    revealInstanceHash: candidate.reveal_instance_hash,
    reasonHash,
    candidateHash: candidate.candidate_hash,
    sourceEventHash: candidate.source_event_hash,
    expiresAt: candidate.challenge_ends_at,
    valueWei: BigInt(detail.bond_wei),
  });
  const expectedPath = join(
    ACTIONS,
    `${candidate.candidate_hash.slice(7)}-${expected.policy_hash.slice(7, 23)}.json`,
  );
  const policyPath = assertApprovedJournalPath(detail.call_policy_path, ACTIONS, expectedPath);
  const persisted = readStrictJsonFileSync(policyPath, IMMUTABLE_JSON_LIMITS);
  if (canonicalJson(persisted) !== canonicalJson(expected)) {
    throw new Error("persisted challenge call policy does not match the candidate binding");
  }
  return expected;
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

export async function broadcastTransactionNonblocking({ rpcProvider, transactionHash, rawTransaction }) {
  let pending = await rpcProvider.getTransaction(transactionHash);
  if (pending) return pending;
  try {
    pending = await rpcProvider.broadcastTransaction(rawTransaction);
  } catch (error) {
    pending = await rpcProvider.getTransaction(transactionHash);
    if (!pending) throw error;
  }
  return pending;
}

async function reconcileBroadcast(job) {
  const action = job.action;
  if (!action || !action.transaction_hash) return false;
  if (["confirmed", "broadcast_reverted"].includes(action.status)) return true;
  if (!["signed", "broadcast", "submitted", "reorged"].includes(action.status)) return false;
  const transcript = verifyRunnerTranscript(job.transcript_path, job.transcript_hash);
  if (!transcript.candidate) throw new Error(`action ${job.job_id} has no challenge candidate`);
  const detail = parseDetailJson(action.detail);
  const callPolicy = assertPersistedChallengePolicy(transcript.candidate, detail);
  const expectedPath = signedActionPath(transcript.candidate, callPolicy);
  const journalPath = assertApprovedJournalPath(detail.signed_tx_path, ACTIONS, expectedPath);
  const signedRecord = assertOperatorSignedRecord(
    readStrictJsonFileSync(journalPath, IMMUTABLE_JSON_LIMITS), transcript.candidate, callPolicy, action, detail,
  );
  const nonceActionId = detail.wallet_nonce_action_id
    ?? walletNonceActionId(transcript.candidate, callPolicy);
  await reserveWalletNonceLocked({
    rpcProvider: provider,
    rpcProviders: nonceProviders,
    coordinationRoot: COORDINATION_ROOT,
    boundChainId: chainId,
    signer: wallet.address,
    actionId: nonceActionId,
    existingSignedRecord: signedRecord,
  });
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
      if (receipt.status === 1) finalizeChallengeSpend(ENVELOPE, transcript.candidate.candidate_hash, { finalizedReceipt: { canonical: true, transaction_hash: action.transaction_hash, block_number: receipt.blockNumber, block_hash: receipt.blockHash } });
      else releaseChallengeReservation(ENVELOPE, transcript.candidate.candidate_hash);
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
    if (pending) {
      recordWalletNonceBroadcastLocked({
        coordinationRoot: COORDINATION_ROOT,
        boundChainId: chainId,
        signer: wallet.address,
        actionId: nonceActionId,
        signedRecord,
      });
    }
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
        recordAction(
          job,
          transcript.candidate,
          "registry_binding_rejected",
          action.transaction_hash,
          reason,
          `REFUSED ${job.job_id}: ${reason}`,
        );
        return true;
      }
      const current = await candidateStillChallengeable(transcript.candidate);
      if (!current.ok) {
        recordAction(
          job,
          transcript.candidate,
          "superseded",
          action.transaction_hash,
          current.reason,
          `SUPERSEDED ${job.job_id}: ${current.reason}`,
        );
        return true;
      }
      const nonceDecision = await walletNonceBroadcastDecisionLocked({
        rpcProvider: provider,
        rpcProviders: nonceProviders,
        coordinationRoot: COORDINATION_ROOT,
        boundChainId: chainId,
        signer: wallet.address,
        actionId: nonceActionId,
        signedRecord,
      });
      if (!nonceDecision.broadcast) {
        if (nonceDecision.known) pending = nonceDecision.transaction;
        else {
          recordAction(
            job,
            transcript.candidate,
            "superseded",
            action.transaction_hash,
            nonceDecision.reason,
            `NONCE FENCED ${job.job_id}: ${nonceDecision.reason}`,
          );
          return true;
        }
      } else {
        pending = await broadcastTransactionNonblocking({
          rpcProvider: provider,
          transactionHash: action.transaction_hash,
          rawTransaction: signedRecord.raw_tx,
        });
        recordWalletNonceBroadcastLocked({
          coordinationRoot: COORDINATION_ROOT,
          boundChainId: chainId,
          signer: wallet.address,
          actionId: nonceActionId,
          signedRecord,
        });
      }
    }
    if (action.status !== "broadcast") {
      recordAction(job, transcript.candidate, "broadcast", action.transaction_hash);
    }
    // Receipt reconciliation is deliberately polling-only. A transaction may
    // remain pending forever, so no wallet or submission lock may await mining.
    return true;
  }
}

export async function consumeCandidate(job) {
  if (job.canonical_status === "orphaned_reorg") return;
  if (job.terminal_disposition) return;
  if (job.action) {
    await withOperatorWalletActionLock(() => reconcileBroadcast(job));
    return;
  }
  if (!job.transcript_path) {
    if (["failed", "succeeded"].includes(job.status)) {
      recordLocalDisposition(
        job,
        "transcript_missing",
        job.failure_reason || "terminal runner job has no transcript",
      );
    }
    return;
  }
  let checked;
  try { checked = verifyRunnerTranscript(job.transcript_path, job.transcript_hash); }
  catch (error) {
    recordLocalDisposition(job, "transcript_invalid", error.message);
    return;
  }
  const candidate = checked.candidate;
  if (!candidate) return;
  if (candidate.action === "retry") {
    if (job.status === "failed" && job.failure_reason === "retry_window_expired") {
      recordLocalDisposition(
        job,
        "retry_window_expired",
        candidate.reason_code,
      );
      return;
    }
    log(`  retry pending for ${job.job_id}: ${candidate.reason_code}`);
    return;
  }
  if (candidate.action === "none") {
    recordAction(job, candidate, "no_action", null, candidate.reason_code);
    return;
  }
  if (candidate.action === "quarantine") {
    recordAction(
      job,
      candidate,
      "quarantined",
      null,
      candidate.reason_code,
      `QUARANTINE ${job.job_id}: ${candidate.reason_code} (${candidate.candidate_hash})`,
    );
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
  const candidateLockPath = submissionActionLockPath({
    coordinationRoot: COORDINATION_ROOT,
    boundChainId: chainId,
    challengeContract: String(chal.target),
    submissionId: candidate.submission_id,
  });
  const candidateLockOwner = acquireEnvelopeLock(candidateLockPath, { timeoutMs: 30_000 });
  try {
    const durableJob = readQueue().jobs.find((entry) => entry.job_id === job.job_id);
    if (!durableJob) throw new Error(`candidate job disappeared before consumption: ${job.job_id}`);
    if (durableJob.action) {
      await withOperatorWalletActionLock(() => reconcileBroadcast(durableJob));
      return;
    }
  try {
    await revalidateRecordedRegistryBinding(checked.transcript.verifier?.chain_claim?.registry_binding);
  } catch (error) {
    const detail = `registry binding rejected before signing: ${error.shortMessage || error.message}`;
    recordAction(
      job,
      candidate,
      "registry_binding_rejected",
      null,
      detail,
      `REFUSED ${job.job_id}: ${detail}`,
    );
    return;
  }
  const candidateCap = BigInt(candidate.max_bond_wei || "0");
  if (candidateCap <= 0n || candidateCap > challengeLimits.perChallengeWei) {
    const detail = `candidate cap ${candidateCap} exceeds provisioned cap ${challengeLimits.perChallengeWei}`;
    recordAction(
      job,
      candidate,
      "invalid_spend_cap",
      null,
      detail,
      `REFUSED ${job.job_id}: invalid candidate spend cap ${candidateCap}`,
    );
    return;
  }

  const submissionId = BigInt(candidate.submission_id);
  const submission = await subs.submissions(submissionId);
  if (Number(submission.status) !== 2) {
    recordAction(
      job,
      candidate,
      "superseded",
      null,
      `submission status is ${submission.status}`,
      `SUPERSEDED ${job.job_id}: submission status is ${submission.status}`,
    );
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
      `SUPERSEDED ${job.job_id}: reveal instance changed before action consumption`,
    );
    return;
  }
  const latest = await provider.getBlock("latest");
  if (!latest || BigInt(latest.timestamp) >= BigInt(candidate.challenge_ends_at)) {
    recordAction(
      job,
      candidate,
      "window_expired",
      null,
      "challenge window closed before action consumption",
      `MISSED WINDOW ${job.job_id}: ${candidate.reason_code}`,
    );
    return;
  }
  const disputed = await subs.disputedEntitlementWei(submissionId);
  const bond = await chal.requiredChallengeBond(disputed);
  if (bond > candidateCap || bond > challengeLimits.perChallengeWei) {
    recordAction(
      job,
      candidate,
      "bond_over_cap",
      null,
      `required ${bond}; cap ${candidateCap}`,
      `UNPOLICED ${job.job_id}: bond ${bond} exceeds cap ${candidateCap} (${candidate.candidate_hash})`,
    );
    return;
  }

  let health;
  let priorHealth;
  try {
    const openEvidence = await canonicalOpenEvidence();
    health = runnerHealth();
    priorHealth = existsSync(RUNNER_HEALTH_PRIOR) ? readStrictJsonFileSync(RUNNER_HEALTH_PRIOR, privateAuthorizationLimits()) : null;
    await assertCanonicalRunnerHealthBlock(health);
    reserveChallengeSpend(ENVELOPE, {
      id: candidate.candidate_hash,
      problemId: runnerConfig.problemId,
      amountWei: bond,
      provisioning: challengeProvisioning,
      health,
      canonicalOpenEvidence: openEvidence,
      canonicalEvidenceExpected: {
        chainId,
        challengeManager: String(chal.target),
        finalizedThroughBlock: openEvidence.finalized_through_block,
      },
    }, { trustedRoot: RUNTIME, requireHealthV2: REQUIRE_HEALTH_V2, expectedHealth: { public_key: RUNNER_HEALTH_PUBLIC_KEY, recovery_public_key: RUNNER_RECOVERY_PUBLIC_KEY, recovery_cooldown_ms: 86_400_000, host_id: RUNNER_HOST_ID, boot_id: RUNNER_BOOT_ID, queue_id: RUNNER_QUEUE_ID, chain_id: chainId, contract: String(chal.target) }, priorHealth });
  } catch (error) {
    appendAlert(`AUTO-FILE DISABLED ${job.job_id}: ${error.message}`);
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
  let signingAuthorization = null;
  await withOperatorWalletActionLock(async () => {
    await runChallengeActionIntent(ENVELOPE, candidate.candidate_hash, async ({ markJournalDurable }) => {
      log(`  exact session call policy: ${policyPath} (${callPolicy.policy_hash})`);
      const nonceActionId = walletNonceActionId(candidate, callPolicy);
      const existingSignedPath = signedActionPath(candidate, callPolicy);
      const existingSignedRecord = existsSync(existingSignedPath)
        ? readStrictJsonFileSync(assertApprovedJournalPath(existingSignedPath, ACTIONS, existingSignedPath), IMMUTABLE_JSON_LIMITS)
        : null;
      const nonceAllocation = await reserveWalletNonceLocked({
        rpcProvider: provider,
        rpcProviders: nonceProviders,
        coordinationRoot: COORDINATION_ROOT,
        boundChainId: chainId,
        signer: wallet.address,
        actionId: nonceActionId,
        existingSignedRecord,
      });
      const populatedRequest = await buildChallengeTransactionRequest(callPolicy, bond, BigInt(latest.timestamp));
      const request = { ...populatedRequest, nonce: nonceAllocation.nonce };
      const signed = await signedActionRecord(candidate, callPolicy, request, signingAuthorization);
      recordWalletNonceSignedLocked({
        coordinationRoot: COORDINATION_ROOT,
        boundChainId: chainId,
        signer: wallet.address,
        actionId: nonceActionId,
        signedRecord: signed.record,
      });
      markJournalDurable({ journalPath: signed.path, signedTransactionHash: signed.record.hash });
      assertOperatorSignedRecord(signed.record, candidate, callPolicy);
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
        wallet_nonce_action_id: nonceActionId,
        wallet_nonce_allocator_path: nonceAllocation.path,
      });
      recordAction(job, candidate, "signed", signed.record.hash, detail);
      log(`  challenge signed for #${submissionId}: ${signed.record.hash} bond=${ethers.formatEther(bond)} ETH`);
      await reconcileBroadcast({ ...job, action: { status: "signed", transaction_hash: signed.record.hash, detail } });
    }, { trustedRoot: RUNTIME, preflight: async (highWater, reservationBinding) => {
      signingAuthorization = await finalSigningAuthorizationFence(highWater, reservationBinding);
      return signingAuthorization.release;
    } });
  });
  } finally {
    releaseEnvelopeLock(candidateLockPath, candidateLockOwner);
  }
}

async function consumeCandidates() {
  const queue = readQueue();
  for (const job of queue.jobs) await consumeCandidate(job);
}

async function scanOnce() {
  const latest = await provider.getBlockNumber();
  const safeLatest = Math.max(0, latest - finalityConfirmations);
  const finalizedBlock = await provider.getBlock(safeLatest);
  if (!finalizedBlock) throw new Error(`finalized runner block ${safeLatest} is unavailable`);
  await backfillChallengeExpiredOnce(safeLatest, finalizedBlock.timestamp);
  const mismatch = await cursorAnchorMismatch(cursorState);
  if (mismatch !== null) {
    appendAlert(`REORG detected at anchored block ${mismatch}; rescanning overlap from durable cursor`);
    blockCache.clear();
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
    const [events, expirationEvents] = await Promise.all([
      queryChunked(subs, subs.filters.Revealed(), range.fromBlock, range.toBlock),
      queryChunked(chal, chal.filters.ChallengeExpired(), range.fromBlock, range.toBlock),
    ]);
    const [canonical, rechallengeEvents] = await Promise.all([
      canonicalRevealRecords(events),
      canonicalRechallengeRecords(expirationEvents),
    ]);
    for (const event of rechallengeEvents) {
      canonical.byJobId.set(eventJobId(event), event.rechallengeGeneration.source_event_hash);
      canonical.bySourceHash.add(event.rechallengeGeneration.source_event_hash);
    }
    await quarantineOrphanedJobs(
      range.fromBlock,
      range.toBlock,
      canonical,
      `canonical rescan ${range.fromBlock}..${range.toBlock} did not contain the job's source event`,
    );
    for (const event of events) await ingestReveal(event, finalizedBlock.timestamp);
    for (const event of rechallengeEvents) await ingestReveal(event, finalizedBlock.timestamp);
    await persistCursor(range.toBlock + 1);
  }

  await refreshRetryableJobs(finalizedBlock);
  for (let index = 0; index < MAX_JOBS_PER_SCAN; index += 1) {
    const result = runWorkerOnce(finalizedBlock.timestamp);
    if (result.terminal_disposition) continue;
    if (result.schema_version === "p42-runner-transcript/v1") {
      log(`  worker completed ${result.job_id}: ${result.verifier.challenge_candidate?.action || "legacy"}`);
      continue;
    }

    if (result.reason !== "queue_empty") log(`  worker waiting: ${result.reason}`);
    break;
  }
  await reconcileTerminalAlerts();
  await consumeCandidates();
  await reconcileTerminalAlerts();
  if (challengeBondOperator && AUTO_CLAIM_BOND) {
    try {
      const claim = await challengeBondOperator.claimBond();
      if (claim.status !== "nothing_claimable") log(`  claimBond ${claim.status}: recovered=${claim.recovered_wei} wei`);
    } catch (error) {
      appendAlert(`CLAIM BOND REFUSED: ${error.shortMessage || error.message}`);
    }
  }
}

async function main() {
  const network = await provider.getNetwork();
  chainId = Number(network.chainId);
  if (secondaryNonceProvider) {
    const secondaryNetwork = await secondaryNonceProvider.getNetwork();
    if (Number(secondaryNetwork.chainId) !== chainId) {
      throw new Error("secondary nonce RPC chain does not match the primary RPC");
    }
  }
  validateManifestEvidence(manifest, await loadProductionValidationContext(manifest, { provider }));
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
    challengeBondOperator = new ChallengeBondOperator({
      provider,
      wallet,
      agentWallet,
      challenge: chal,
      chainId,
      journalPath: join(ACTIONS, "claim-bond.signed-tx.json"),
      confirmations: finalityConfirmations,
    });
  }
  challengeProvisioning = validateProvisioningArtifact(
    readStrictJsonFileSync(CHALLENGE_PROVISIONING, IMMUTABLE_JSON_LIMITS),
    {
      chainId,
      challengeManager: String(chal.target),
      agentWallet: executionMode.agentWalletAddress,
      operator: wallet.address,
    },
  );
  challengeLimits = limitsFromProvisioning(challengeProvisioning);
  await canonicalOpenEvidence();
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
  log(`sandbox=docker max_running=1 max_bond=${ethers.formatEther(challengeLimits.perChallengeWei)} ETH`);
  await reconcileTerminalAlerts();
  await consumeCandidates();
  await reconcileTerminalAlerts();
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
