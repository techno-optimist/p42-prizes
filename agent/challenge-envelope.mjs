import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, readdirSync, renameSync, rmSync, writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import { hostname } from "node:os";
import Ajv2020 from "ajv/dist/2020.js";
import { ethers } from "ethers";
import { assertSignedTransactionRecord } from "./signed-transaction.mjs";
import { readStrictJsonFileSync, writeTrustedFileSync } from "./strict-json.mjs";

const JSON_LIMITS = Object.freeze({ maxBytes: 2 * 1024 * 1024, maxDepth: 48 });
const JOURNAL_LIMITS = Object.freeze({ ...JSON_LIMITS, canonicalBytes: true, trailingNewline: "require" });
const DEFAULTS = Object.freeze({
  perChallengeWei: ethers.parseEther("0.05"), perProblemDayWei: ethers.parseEther("0.10"),
  globalDayWei: ethers.parseEther("0.30"), maxCanonicalOpen: 3, maxPendingProvisioned: 1,
});
let validateProvisioningSchema;
let validateRunnerHealthV2Schema;

function provisioningSchemaValidator() {
  if (!validateProvisioningSchema) {
    const schema = readStrictJsonFileSync(new URL("../schemas/challenge-provisioning.schema.json", import.meta.url), JSON_LIMITS);
    validateProvisioningSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  }
  return validateProvisioningSchema;
}

function runnerHealthV2SchemaValidator() {
  if (!validateRunnerHealthV2Schema) {
    const schema = readStrictJsonFileSync(new URL("../schemas/runner-health-v2.schema.json", import.meta.url), JSON_LIMITS);
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    ajv.addFormat("date-time", { type: "string", validate: (value) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value) && Number.isFinite(Date.parse(value)) });
    validateRunnerHealthV2Schema = ajv.compile(schema);
  }
  return validateRunnerHealthV2Schema;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export function utcDay(timestamp = Date.now()) {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) throw new Error("challenge envelope timestamp is invalid");
  return date.toISOString().slice(0, 10);
}

function emptyState() { return { schema_version: "p42-challenge-envelope-state/v2", days: {} }; }
function dayBucket(state, day) {
  state.days[day] ??= { reservations: {}, spends: {} };
  return state.days[day];
}

function atomicWrite(path, value, trustedRoot = dirname(path)) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeTrustedFileSync(path, trustedRoot, `${canonicalJson(value)}\n`);
}

function readState(path, trustedRoot = dirname(path)) {
  if (!existsSync(path)) return emptyState();
  const state = readStrictJsonFileSync(path, { ...JOURNAL_LIMITS, privateFile: true, trustedRoot });
  if (state.schema_version !== "p42-challenge-envelope-state/v2" || !state.days || typeof state.days !== "object") {
    throw new Error("unsupported or incomplete challenge envelope state");
  }
  return state;
}

function writeLockOwner(path, owner) {
  const fd = openSync(path, "wx", 0o600);
  try { writeFileSync(fd, `${canonicalJson(owner)}\n`); fsyncSync(fd); } finally { closeSync(fd); }
}

function readLockOwner(lockPath) {
  const owner = readStrictJsonFileSync(join(lockPath, "owner.json"), JOURNAL_LIMITS);
  if (owner?.schema_version !== "p42-envelope-lock-owner/v1" || !Number.isSafeInteger(owner.pid) || owner.pid < 1
    || !/^[a-f0-9]{64}$/.test(owner.token ?? "") || typeof owner.host !== "string"
    || typeof owner.process_started_at_utc !== "string" || typeof owner.lock_created_at_utc !== "string") {
    throw new Error("challenge envelope lock owner record is invalid");
  }
  return owner;
}

function ownerIsDeadOnThisHost(owner) {
  if (owner.host !== hostname()) return false;
  try { process.kill(owner.pid, 0); return false; }
  catch (error) {
    if (error.code === "ESRCH") return true;
    if (error.code === "EPERM") return false;
    throw error;
  }
}

function reclaimDeadOwner(lockPath, observed) {
  const reclaimPath = `${lockPath}.reclaim`;
  try { mkdirSync(reclaimPath, { mode: 0o700 }); }
  catch (error) { if (error.code === "EEXIST") return false; throw error; }
  try {
    const current = readLockOwner(lockPath);
    if (canonicalJson(current) !== canonicalJson(observed) || !ownerIsDeadOnThisHost(current)) return false;
    const tombstone = `${lockPath}.dead.${current.token}`;
    renameSync(lockPath, tombstone);
    const moved = readLockOwner(tombstone);
    if (moved.token !== current.token) {
      if (!existsSync(lockPath)) renameSync(tombstone, lockPath);
      throw new Error("challenge envelope lock changed during reclaim");
    }
    rmSync(tombstone, { recursive: true });
    return true;
  } finally { rmSync(reclaimPath, { recursive: true, force: true }); }
}

export function acquireEnvelopeLock(lockPath, { timeoutMs = 5000, now = Date.now } = {}) {
  const started = Date.now();
  for (;;) {
    if (existsSync(`${lockPath}.reclaim`)) {
      if (Date.now() - started >= timeoutMs) throw new Error("challenge envelope lock timeout");
      continue;
    }
    const owner = {
      schema_version: "p42-envelope-lock-owner/v1", pid: process.pid, token: randomBytes(32).toString("hex"),
      host: hostname(), process_started_at_utc: new Date(Date.now() - Math.floor(process.uptime() * 1000)).toISOString(),
      lock_created_at_utc: new Date(now()).toISOString(),
    };
    let created = false;
    try {
      mkdirSync(lockPath, { mode: 0o700 }); created = true;
      writeLockOwner(join(lockPath, "owner.json"), owner);
      return owner;
    }
    catch (error) {
      if (created) { rmSync(lockPath, { recursive: true, force: true }); throw error; }
      if (error.code !== "EEXIST") throw error;
      let observed;
      try { observed = readLockOwner(lockPath); }
      catch (readError) {
        if (readError.code === "ENOENT") continue;
        throw new Error(`challenge envelope lock is incomplete; refusing reclaim: ${readError.message}`);
      }
      if (ownerIsDeadOnThisHost(observed) && reclaimDeadOwner(lockPath, observed)) continue;
      if (Date.now() - started >= timeoutMs) throw new Error("challenge envelope lock timeout");
    }
  }
}

export function releaseEnvelopeLock(lockPath, owner) {
  const current = readLockOwner(lockPath);
  if (current.token !== owner?.token || current.pid !== owner?.pid || current.host !== owner?.host) {
    throw new Error("challenge envelope lock release token mismatch");
  }
  const tombstone = `${lockPath}.release.${owner.token}`;
  renameSync(lockPath, tombstone);
  const moved = readLockOwner(tombstone);
  if (moved.token !== owner.token || moved.pid !== owner.pid || moved.host !== owner.host) {
    if (!existsSync(lockPath)) renameSync(tombstone, lockPath);
    throw new Error("challenge envelope lock changed during release");
  }
  rmSync(tombstone, { recursive: true });
}

export function withEnvelopeLock(statePath, operation, { now = Date.now(), timeoutMs = 5000, trustedRoot = dirname(resolve(statePath)) } = {}) {
  const path = resolve(statePath); const lock = `${path}.lock`;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); const owner = acquireEnvelopeLock(lock, { timeoutMs, now: () => now });
  try { const state = readState(path, trustedRoot); const result = operation(state, utcDay(now)); atomicWrite(path, state, trustedRoot); return result; }
  finally { releaseEnvelopeLock(lock, owner); }
}

function artifactPreimage(value) {
  const copy = structuredClone(value); delete copy.artifact_hash; delete copy.signature;
  return canonicalJson(copy);
}

export function validateProvisioningArtifact(value, expected = {}) {
  const validateSchema = provisioningSchemaValidator();
  if (!validateSchema(value)) {
    const detail = validateSchema.errors.map((error) => `${error.instancePath || "/"} ${error.message}`).join("; ");
    throw new Error(`provisioning schema validation failed: ${detail}`);
  }
  if (!Number.isSafeInteger(value.chain_id) || value.chain_id < 1) throw new Error("provisioning chain_id is invalid");
  for (const field of ["challenge_manager", "agent_wallet", "operator"]) {
    if (!ethers.isAddress(value[field]) || value[field] === ethers.ZeroAddress) throw new Error(`provisioning ${field} is invalid`);
  }
  if (expected.chainId !== undefined && value.chain_id !== Number(expected.chainId)) throw new Error("provisioning chain mismatch");
  if (expected.challengeManager && ethers.getAddress(value.challenge_manager) !== ethers.getAddress(expected.challengeManager)) throw new Error("provisioning challenge manager mismatch");
  if (expected.agentWallet && ethers.getAddress(value.agent_wallet) !== ethers.getAddress(expected.agentWallet)) throw new Error("provisioning agent wallet mismatch");
  if (expected.operator && ethers.getAddress(value.operator) !== ethers.getAddress(expected.operator)) throw new Error("provisioning operator mismatch");
  const exact = [
    ["per_challenge_wei", DEFAULTS.perChallengeWei], ["per_problem_day_wei", DEFAULTS.perProblemDayWei],
    ["global_day_wei", DEFAULTS.globalDayWei], ["max_canonical_open", 3n], ["max_pending_provisioned", 1n],
  ];
  for (const [field, wanted] of exact) { try { if (BigInt(value[field]) !== wanted) throw new Error(); } catch { throw new Error(`provisioning ${field} default mismatch`); } }
  if (value.rehearsal?.health_gate_verified !== true || value.rehearsal?.restart_recovery_verified !== true || value.rehearsal?.deep_reorg_verified !== true) throw new Error("rehearsal evidence incomplete");
  if (!/^sha256:[a-f0-9]{64}$/.test(value.rehearsal?.artifact_hash ?? "")) throw new Error("rehearsal artifact hash is invalid");
  const digest = `sha256:${ethers.sha256(ethers.toUtf8Bytes(artifactPreimage(value))).slice(2)}`;
  if (value.artifact_hash !== digest) throw new Error("provisioning artifact hash mismatch");
  if (value.signature?.scheme !== "eip191" || !ethers.isAddress(value.signature.signer) || !ethers.isHexString(value.signature.signature, 65)) throw new Error("provisioning signature is invalid");
  let recovered;
  try { recovered = ethers.verifyMessage(value.artifact_hash, value.signature.signature); }
  catch { throw new Error("provisioning signature verification failed"); }
  if (recovered !== ethers.getAddress(value.signature.signer)) throw new Error("provisioning signature verification failed");
  if (ethers.getAddress(value.signature.signer) !== ethers.getAddress(value.operator)) throw new Error("provisioning signature signer is not operator");
  return value;
}

export function limitsFromProvisioning(provisioning, tightened = {}) {
  validateProvisioningArtifact(provisioning);
  const base = {
    perChallengeWei: BigInt(provisioning.per_challenge_wei), perProblemDayWei: BigInt(provisioning.per_problem_day_wei),
    globalDayWei: BigInt(provisioning.global_day_wei), maxCanonicalOpen: Number(provisioning.max_canonical_open),
    maxPendingProvisioned: Number(provisioning.max_pending_provisioned),
  };
  const result = { ...base };
  for (const [key, raw] of Object.entries(tightened)) {
    if (!(key in base)) throw new Error(`unknown tightened challenge limit ${key}`);
    const value = typeof base[key] === "bigint" ? BigInt(raw) : Number(raw);
    if (value <= 0 || value > base[key]) throw new Error(`challenge limit ${key} may only tighten provisioning`);
    result[key] = value;
  }
  return Object.freeze(result);
}

export function runnerHealthAdmission(health, { now = Date.now(), maxAgeMs = 300_000, requireV2 = false, expected = {}, prior = null, highWater = null, reservationBinding = null, permitUnanchoredSequence = false } = {}) {
  const observed = Date.parse(health?.observed_at_utc);
  if (health?.schema_version === "p42-runner-health/v1" && !requireV2) {
    const complete = Number.isFinite(observed)
    && observed <= now && now - observed <= maxAgeMs && health.oom_kills === 0 && health.worker_restarts === 0
    && health.queue_corruption_events === 0 && health.max_active_running === 1 && health.decision === "start"
    && health.swap_guard === "green" && health.host_capacity === "green" && health.concurrency_guard === "green";
    return { allowed: complete, reason: complete ? "green_v1_rollout" : "runner_health_fail_closed" };
  }
  try {
    validateRunnerHealthAuthenticity(health, expected);
    if (!Number.isFinite(observed) || observed > now || now - observed > maxAgeMs || observed !== health.chain.block_time * 1000) throw new Error("stale time");
    if ((health.sequence === 1) !== (health.prior_artifact_hash === null)) throw new Error("sequence root");
    if (health.sequence === 1 && health.boot_transition !== null) throw new Error("root cannot be a boot transition");
    if (health.sequence > 1 && !prior && !highWater && !permitUnanchoredSequence) throw new Error("sequence predecessor missing");
    if (prior) {
      validateRunnerHealthPredecessor(prior, health, expected);
    }
    if (highWater) {
      if (reservationBinding && (health.sequence !== reservationBinding.sequence || health.artifact_hash !== reservationBinding.artifact_hash)) throw new Error("health generation differs from reservation authorization");
      if (health.sequence === highWater.sequence && health.artifact_hash === highWater.artifact_hash) {
        if (reservationBinding?.sequence !== health.sequence || reservationBinding?.artifact_hash !== health.artifact_hash) throw new Error("accepted health generation is not bound to this reservation");
      } else if (health.sequence === highWater.sequence + 1 && health.prior_artifact_hash === highWater.artifact_hash) {
        const recoveryHash = health.counter_acknowledgement.recovery_authorization?.authorization_hash;
        if (recoveryHash && (highWater.consumed_recovery_authorization_hashes ?? []).includes(recoveryHash)) throw new Error("counter recovery authorization already consumed");
        for (const key of ["oom_kills", "worker_restarts", "queue_corruption_events"]) if (health.counters[key] < highWater.counters[key]) throw new Error("counter high-water rollback");
        validateCounterAcknowledgement(highWater, health, expected);
        if (health.producer.host_id !== highWater.host_id || health.producer.queue_id !== highWater.queue_id) throw new Error("health host or queue identity changed");
        if (health.producer.boot_id !== highWater.boot_id) {
          const transition = health.boot_transition;
          if (!transition || transition.previous_boot_id !== highWater.boot_id || transition.new_boot_id !== health.producer.boot_id || transition.transition_block_number !== health.chain.block_number || transition.transition_block_hash !== health.chain.block_hash) throw new Error("invalid signed boot transition");
        } else if (health.boot_transition !== null) throw new Error("spurious boot transition");
      } else throw new Error("health chain fork, replay, or sequence gap");
    } else if (!prior && health.sequence !== 1 && !permitUnanchoredSequence) throw new Error("health chain must begin at sequence one");
    const q = health.queue; const byteLimit = 4 * 1024 * 1024 - 64 * 1024;
    if (q.queue_bytes + q.canonical_byte_headroom !== byteLimit || q.ordinary_admission_headroom !== Math.max(0, 896 - q.active_job_count) || q.urgent_admission_headroom !== Math.max(0, 960 - q.active_job_count)) throw new Error("headroom algebra");
    if (q.queued_job_count > q.active_job_count || q.tombstone_count !== q.archive_record_count * 2 || q.warning_slack_seconds !== 3600 || q.critical_slack_seconds !== 900) throw new Error("metric consistency");
    if ((q.earliest_live_deadline === null) !== (q.minimum_challenge_slack_seconds === null) || (q.earliest_live_deadline !== null && q.earliest_live_deadline - health.chain.block_time !== q.minimum_challenge_slack_seconds)) throw new Error("deadline algebra");
    if (q.archive_fault_history) {
      const history = q.archive_fault_history;
      if (`sha256:${ethers.sha256(ethers.toUtf8Bytes(history.reason)).slice(2)}` !== history.reason_hash || (history.status === "active") !== (q.archive_fault !== null) || (history.status === "recovered") !== (history.recovered_at_utc !== null)) throw new Error("archive fault history consistency");
    } else if (q.archive_fault !== null) throw new Error("archive fault lacks history");
    if (q.archive_fault !== null || q.canonical_byte_headroom === 0 || q.ordinary_admission_headroom === 0 || q.urgent_admission_headroom === 0 || q.expired_deadline_critical_count !== 0 || (q.minimum_challenge_slack_seconds !== null && q.minimum_challenge_slack_seconds <= q.critical_slack_seconds)) throw new Error("critical queue health");
    if (!highWater && !prior) validateCounterAcknowledgement(null, health, expected);
    for (const key of ["oom_kills", "worker_restarts", "queue_corruption_events"]) if (health.counters[key] !== health.counter_acknowledgement.baseline[key]) throw new Error("unacknowledged host counter delta");
    if (q.runner_plan.max_active_running !== 1 || q.runner_plan.decision !== "start" || [q.runner_plan.swap_guard, q.runner_plan.host_capacity, q.runner_plan.concurrency_guard].some((v) => v !== "green")) throw new Error("runner plan");
    return { allowed: true, reason: q.minimum_challenge_slack_seconds !== null && q.minimum_challenge_slack_seconds <= q.warning_slack_seconds ? "green_warning_slack" : "green_v2" };
  } catch (error) {
    return { allowed: false, reason: "runner_health_fail_closed", detail: error.message };
  }
}

function validateRunnerHealthAuthenticity(health, expected = {}) {
  if (health?.schema_version !== "p42-runner-health/v2" || !runnerHealthV2SchemaValidator()(health)) throw new Error("v2 schema");
  for (const [key, value] of Object.entries(expected)) {
    if (["recovery_public_key", "recovery_cooldown_ms", "remediation_artifact_hash", "rehearsal_artifact_hash"].includes(key)) continue;
    if (key === "public_key") { if (health.signature.public_key !== value) throw new Error("binding public_key"); continue; }
    const actual = key in health.producer ? health.producer[key] : health.chain[key];
    if (String(actual).toLowerCase() !== String(value).toLowerCase()) throw new Error(`binding ${key}`);
  }
  const unsigned = Object.fromEntries(Object.entries(health).filter(([key]) => !["artifact_hash", "signature"].includes(key)));
  const artifactHash = `sha256:${ethers.sha256(ethers.toUtf8Bytes(canonicalJson(unsigned))).slice(2)}`;
  if (artifactHash !== health.artifact_hash) throw new Error("artifact hash");
  const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(health.signature.public_key.slice(8), "hex")]), format: "der", type: "spki" });
  const message = Buffer.concat([Buffer.from("P42-RUNNER-HEALTH-V2\0"), Buffer.from(artifactHash.slice(7), "hex")]);
  if (!verifySignature(null, message, publicKey, Buffer.from(health.signature.signature.slice(8), "hex"))) throw new Error("signature");
  return health;
}

export function validateRunnerHealthPredecessor(prior, current, expected = {}) {
  const previousBoot = current?.boot_transition?.previous_boot_id ?? current?.producer?.boot_id;
  validateRunnerHealthAuthenticity(prior, { ...expected, boot_id: previousBoot });
  if (current.sequence !== prior.sequence + 1 || current.prior_artifact_hash !== prior.artifact_hash) throw new Error("predecessor sequence linkage invalid");
  for (const key of ["oom_kills", "worker_restarts", "queue_corruption_events"]) if (current.counters[key] < prior.counters[key]) throw new Error("predecessor counter rollback");
  validateCounterAcknowledgement(prior, current, expected);
  if (current.producer.host_id !== prior.producer.host_id || current.producer.queue_id !== prior.producer.queue_id) throw new Error("predecessor producer identity fork");
  if (current.producer.boot_id !== prior.producer.boot_id) {
    const transition = current.boot_transition;
    if (!transition || transition.previous_boot_id !== prior.producer.boot_id || transition.new_boot_id !== current.producer.boot_id || transition.transition_block_number !== current.chain.block_number || transition.transition_block_hash !== current.chain.block_hash) throw new Error("predecessor boot transition invalid");
  } else if (current.boot_transition !== null) throw new Error("spurious predecessor boot transition");
  return prior;
}

function validateCounterAcknowledgement(previousHealth, current, expected = {}) {
  const acknowledgement = current.counter_acknowledgement;
  for (const key of ["oom_kills", "worker_restarts", "queue_corruption_events"]) {
    if (acknowledgement.baseline[key] > current.counters[key]) throw new Error("counter acknowledgement exceeds lifetime counter");
  }
  const previous = previousHealth?.counter_acknowledgement ?? null;
  const zero = { oom_kills: 0, worker_restarts: 0, queue_corruption_events: 0 };
  if (!previous) {
    if (canonicalJson(current.counters) === canonicalJson(zero) && acknowledgement.recovery_authorization === null && canonicalJson(acknowledgement.baseline) === canonicalJson(zero)) return;
    validateCounterRecoveryAuthorization(null, current, expected);
    return;
  }
  if (acknowledgement.generation === previous.generation) {
    if (canonicalJson(acknowledgement) !== canonicalJson(previous)) throw new Error("counter baseline changed without recovery generation");
  } else if (acknowledgement.generation === previous.generation + 1) {
    for (const key of ["oom_kills", "worker_restarts", "queue_corruption_events"]) if (acknowledgement.baseline[key] < previous.baseline[key]) throw new Error("counter acknowledgement baseline rolled back");
    if (acknowledgement.acknowledged_block_number !== current.chain.block_number || acknowledgement.acknowledged_block_hash !== current.chain.block_hash) throw new Error("counter recovery is not bound to current canonical block");
    validateCounterRecoveryAuthorization(previousHealth, current, expected);
  } else throw new Error("counter recovery generation gap");
}

function validateCounterRecoveryAuthorization(previous, current, expected) {
  const authorization = current.counter_acknowledgement.recovery_authorization;
  if (!authorization) throw new Error("independent counter recovery authorization is required");
  if (!expected.recovery_public_key || authorization.signature.public_key !== expected.recovery_public_key) throw new Error("counter recovery authority mismatch");
  if (authorization.signature.public_key === current.signature.public_key) throw new Error("counter recovery authority must differ from health signer");
  if (expected.remediation_artifact_hash && authorization.remediation_artifact_hash !== expected.remediation_artifact_hash) throw new Error("counter recovery remediation mismatch");
  if (expected.rehearsal_artifact_hash && authorization.rehearsal_artifact_hash !== expected.rehearsal_artifact_hash) throw new Error("counter recovery rehearsal mismatch");
  const unsigned = Object.fromEntries(Object.entries(authorization).filter(([key]) => !["authorization_hash", "signature"].includes(key)));
  const hash = `sha256:${ethers.sha256(ethers.toUtf8Bytes(canonicalJson(unsigned))).slice(2)}`;
  if (hash !== authorization.authorization_hash) throw new Error("counter recovery authorization hash mismatch");
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(authorization.signature.public_key.slice(8), "hex")]), format: "der", type: "spki" });
  const message = Buffer.concat([Buffer.from("P42-RUNNER-COUNTER-RECOVERY-V1\0"), Buffer.from(hash.slice(7), "hex")]);
  if (!verifySignature(null, message, key, Buffer.from(authorization.signature.signature.slice(8), "hex"))) throw new Error("counter recovery signature invalid");
  const priorCounters = previous?.counters ?? { oom_kills: 0, worker_restarts: 0, queue_corruption_events: 0 };
  if (authorization.generation !== current.counter_acknowledgement.generation || canonicalJson(authorization.prior_counters) !== canonicalJson(priorCounters) || canonicalJson(authorization.current_counters) !== canonicalJson(current.counters) || canonicalJson(authorization.baseline) !== canonicalJson(current.counter_acknowledgement.baseline)) throw new Error("counter recovery transition mismatch");
  const scope = authorization.scope;
  if (scope.health_public_key !== current.signature.public_key || scope.host_id !== current.producer.host_id || scope.boot_id !== current.producer.boot_id || scope.queue_id !== current.producer.queue_id || scope.chain_id !== current.chain.chain_id || scope.contract !== current.chain.contract || scope.target_sequence !== current.sequence || scope.prior_artifact_hash !== current.prior_artifact_hash || scope.target_block_number !== current.chain.block_number || scope.target_block_hash !== current.chain.block_hash || scope.acknowledgement_block_number !== current.counter_acknowledgement.acknowledged_block_number || scope.acknowledgement_block_hash !== current.counter_acknowledgement.acknowledged_block_hash) throw new Error("counter recovery scope mismatch");
  const incident = authorization.incident_artifact;
  if (!incident || authorization.incident_artifact_hash !== incident.artifact_hash || incident.generation !== authorization.generation || canonicalJson(incident.counters) !== canonicalJson(current.counters)) throw new Error("counter incident linkage mismatch");
  const incidentUnsigned = Object.fromEntries(Object.entries(incident).filter(([key]) => !["artifact_hash", "signature"].includes(key)));
  const incidentHash = `sha256:${ethers.sha256(ethers.toUtf8Bytes(canonicalJson(incidentUnsigned))).slice(2)}`;
  if (incidentHash !== incident.artifact_hash || incident.signature.public_key !== expected.recovery_public_key) throw new Error("counter incident authority or hash mismatch");
  const incidentKey = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(incident.signature.public_key.slice(8), "hex")]), format: "der", type: "spki" });
  const incidentMessage = Buffer.concat([Buffer.from("P42-RUNNER-COUNTER-INCIDENT-V1\0"), Buffer.from(incidentHash.slice(7), "hex")]);
  if (!verifySignature(null, incidentMessage, incidentKey, Buffer.from(incident.signature.signature.slice(8), "hex"))) throw new Error("counter incident signature invalid");
  const incidentScope = incident.scope;
  if (incidentScope.health_public_key !== current.signature.public_key || incidentScope.host_id !== current.producer.host_id || incidentScope.boot_id !== current.producer.boot_id || incidentScope.queue_id !== current.producer.queue_id || incidentScope.chain_id !== current.chain.chain_id || incidentScope.contract !== current.chain.contract) throw new Error("counter incident scope mismatch");
  const cooldownSeconds = Math.ceil((expected.recovery_cooldown_ms ?? 86_400_000) / 1000);
  if (incident.block_number > current.chain.block_number || incident.block_time > current.chain.block_time || current.chain.block_time - incident.block_time < cooldownSeconds) throw new Error("counter recovery canonical cooldown incomplete");
}

export function reauthorizeChallengeReservation(statePath, id, health, options = {}) {
  return withEnvelopeLock(statePath, (state) => {
    let reservation = null;
    for (const bucket of Object.values(state.days)) if (bucket.reservations?.[id]) { reservation = bucket.reservations[id]; break; }
    if (!reservation) throw new Error("challenge reservation not found for health reauthorization");
    const admission = runnerHealthAdmission(health, { now: options.now ?? Date.now(), requireV2: true, expected: options.expectedHealth ?? {}, highWater: state.runner_health_high_water ?? null });
    if (!admission.allowed) throw new Error("runner health reauthorization did not strictly advance high-water");
    reservation.runner_health_authorization = { schema_version: "p42-runner-health-reservation-binding/v1", sequence: health.sequence, artifact_hash: health.artifact_hash };
    state.runner_health_high_water = healthHighWater(health, state.runner_health_high_water ?? null);
    return { reauthorized: true, sequence: health.sequence, artifact_hash: health.artifact_hash };
  }, options);
}

export function runnerHealthFinalSigningAdmission(health, { healthBlock, latestBlock, incidentBlock = null, confirmations, authorizationStartedAt, now = Date.now(), maxSigningAgeMs = 5000 } = {}) {
  try {
    if (health?.schema_version !== "p42-runner-health/v2" || !healthBlock || !latestBlock) throw new Error("missing v2 chain evidence");
    if (String(healthBlock.hash).toLowerCase() !== health.chain.block_hash || Number(healthBlock.timestamp) !== health.chain.block_time || Number(healthBlock.number) !== health.chain.block_number) throw new Error("health block reorg or mismatch");
    if (!Number.isSafeInteger(confirmations) || confirmations < 1 || health.chain.block_number > Number(latestBlock.number) - confirmations) throw new Error("health block is not finalized");
    const incident = health.counter_acknowledgement.recovery_authorization?.incident_artifact;
    if (incident && (!incidentBlock || Number(incidentBlock.number) !== incident.block_number || String(incidentBlock.hash).toLowerCase() !== incident.block_hash || Number(incidentBlock.timestamp) !== incident.block_time)) throw new Error("counter incident start block is not canonical");
    if (health.queue.earliest_live_deadline !== null && health.queue.earliest_live_deadline - Number(latestBlock.timestamp) <= health.queue.critical_slack_seconds) throw new Error("critical deadline slack");
    if (!Number.isFinite(authorizationStartedAt) || now < authorizationStartedAt || now - authorizationStartedAt > maxSigningAgeMs) throw new Error("signing authorization age");
    return { allowed: true, reason: "final_signing_green" };
  } catch (error) { return { allowed: false, reason: "final_signing_fail_closed", detail: error.message }; }
}

export function validateCanonicalOpenEvidence(evidence, { chainId, challengeManager, finalizedThroughBlock, maxAgeMs = 300_000, now = Date.now() } = {}) {
  const observed = Date.parse(evidence?.observed_at_utc);
  if (evidence?.schema_version !== "p42-canonical-open-evidence/v1" || evidence.complete !== true || !Number.isFinite(observed) || observed > now || now - observed > maxAgeMs) throw new Error("canonical open evidence is missing, stale, future, or incomplete");
  if (Number(evidence.chain_id) !== Number(chainId) || ethers.getAddress(evidence.challenge_manager) !== ethers.getAddress(challengeManager)) throw new Error("canonical open evidence binding mismatch");
  if (!Number.isSafeInteger(evidence.finalized_through_block) || evidence.finalized_through_block < Number(finalizedThroughBlock)) throw new Error("canonical open evidence is not finalized through required block");
  if (!Array.isArray(evidence.open_challenges) || evidence.open_challenges.some((row) => !/^[1-9][0-9]*$/.test(row.submission_id) || !ethers.isHexString(row.challenge_instance_hash, 32))) throw new Error("canonical open evidence rows are invalid");
  if (new Set(evidence.open_challenges.map((row) => row.submission_id)).size !== evidence.open_challenges.length) throw new Error("canonical open evidence contains duplicates");
  return evidence;
}

export function reserveChallengeSpend(statePath, input, options = {}) {
  if (input.limits !== undefined) throw new Error("public challenge limit overrides are forbidden");
  const limits = limitsFromProvisioning(input.provisioning, input.tightenedLimits);
  const amount = BigInt(input.amountWei);
  if (!input.id || !input.problemId) throw new Error("challenge reservation identity is required");
  if (!runnerHealthAdmission(input.health, { now: options.now ?? Date.now(), requireV2: options.requireHealthV2 ?? false, expected: options.expectedHealth ?? {}, prior: options.priorHealth ?? null }).allowed) throw new Error("auto-file disabled: runner health is not green");
  const evidence = validateCanonicalOpenEvidence(input.canonicalOpenEvidence, input.canonicalEvidenceExpected);
  if (evidence.open_challenges.length >= limits.maxCanonicalOpen) throw new Error("canonical open challenge cap reached");
  if (amount <= 0n || amount > limits.perChallengeWei) throw new Error("per-challenge spend cap exceeded");
  return withEnvelopeLock(statePath, (state, day) => {
    const admission = runnerHealthAdmission(input.health, { now: options.now ?? Date.now(), requireV2: options.requireHealthV2 ?? false, expected: options.expectedHealth ?? {}, prior: options.priorHealth ?? null, highWater: state.runner_health_high_water ?? null });
    if (!admission.allowed) throw new Error("auto-file disabled: runner health high-water rejected");
    if (input.health.schema_version === "p42-runner-health/v2") state.runner_health_high_water = healthHighWater(input.health, state.runner_health_high_water ?? null);
    for (const [bucketDay, bucket] of Object.entries(state.days)) {
      if (bucket.reservations?.[input.id] || bucket.spends?.[input.id]) return { reserved: false, idempotent: true, day: bucketDay };
    }
    const pending = Object.values(state.days).flatMap((bucket) => Object.values(bucket.reservations ?? {}));
    if (pending.length >= limits.maxPendingProvisioned) throw new Error("one exact challenge policy is already pending");
    const bucket = dayBucket(state, day); const rows = [...Object.values(bucket.reservations), ...Object.values(bucket.spends)];
    const global = rows.reduce((sum, row) => sum + BigInt(row.amount_wei), 0n);
    const problem = rows.filter((row) => row.problem_id === input.problemId).reduce((sum, row) => sum + BigInt(row.amount_wei), 0n);
    if (problem + amount > limits.perProblemDayWei) throw new Error("per-problem UTC-day spend cap exceeded");
    if (global + amount > limits.globalDayWei) throw new Error("global UTC-day spend cap exceeded");
    bucket.reservations[input.id] = {
      problem_id: input.problemId,
      amount_wei: amount.toString(),
      reserved_at_utc: new Date(options.now ?? Date.now()).toISOString(),
      action_intent: { schema_version: "p42-challenge-action-intent/v1", intent_id: input.id, status: "reserved" },
      runner_health_authorization: input.health.schema_version === "p42-runner-health/v2" ? { schema_version: "p42-runner-health-reservation-binding/v1", sequence: input.health.sequence, artifact_hash: input.health.artifact_hash } : null,
    };
    return { reserved: true, idempotent: false, day };
  }, options);
}

function healthHighWater(health, previous = null) {
  const consumed = [...(previous?.consumed_recovery_authorization_hashes ?? [])];
  const recoveryHash = health.counter_acknowledgement.recovery_authorization?.authorization_hash;
  if (recoveryHash && !consumed.includes(recoveryHash)) consumed.push(recoveryHash);
  return {
    schema_version: "p42-runner-health-high-water/v1", sequence: health.sequence,
    artifact_hash: health.artifact_hash, prior_artifact_hash: health.prior_artifact_hash,
    host_id: health.producer.host_id, boot_id: health.producer.boot_id, queue_id: health.producer.queue_id,
    counters: structuredClone(health.counters), accepted_at_utc: new Date().toISOString(),
    counter_acknowledgement: structuredClone(health.counter_acknowledgement),
    consumed_recovery_authorization_hashes: consumed,
  };
}

export function finalizeChallengeSpend(statePath, id, { finalizedReceipt, ...options } = {}) {
  if (!finalizedReceipt?.canonical || !Number.isSafeInteger(finalizedReceipt.block_number) || !ethers.isHexString(finalizedReceipt.block_hash, 32)) throw new Error("finalized canonical challenge receipt evidence is required");
  return withEnvelopeLock(statePath, (state) => {
    for (const bucket of Object.values(state.days)) {
      if (bucket.spends?.[id]) return { committed: true, idempotent: true };
      const reservation = bucket.reservations?.[id];
      if (!reservation) continue;
      bucket.spends[id] = { ...reservation, transaction_hash: finalizedReceipt.transaction_hash, block_number: finalizedReceipt.block_number, block_hash: finalizedReceipt.block_hash.toLowerCase() };
      delete bucket.reservations[id]; return { committed: true, idempotent: false };
    }
    throw new Error("finalized challenge has no durable reservation");
  }, options);
}

export function releaseChallengeReservation(statePath, id, options = {}) {
  return withEnvelopeLock(statePath, (state) => {
    for (const bucket of Object.values(state.days)) if (bucket.reservations && delete bucket.reservations[id]) return { released: true };
    return { released: false };
  }, options);
}

export async function runChallengeActionIntent(statePath, id, operation, options = {}) {
  const path = resolve(statePath); const lock = `${path}.lock`;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const owner = acquireEnvelopeLock(lock, { timeoutMs: options.timeoutMs ?? 5000, now: () => options.now ?? Date.now() });
  const state = readState(path, options.trustedRoot ?? dirname(path));
  let durable = false;
  let released = false;
  let releasePreflight = null;
  const release = () => { if (!released) { releaseEnvelopeLock(lock, owner); released = true; } };
  try {
    let reservationBinding = null;
    for (const bucket of Object.values(state.days)) {
      if (bucket.reservations?.[id]) { reservationBinding = bucket.reservations[id].runner_health_authorization ?? null; break; }
    }
    if (options.preflight) releasePreflight = await options.preflight(state.runner_health_high_water ?? null, reservationBinding);
    return await operation({
      markJournalDurable: ({ journalPath, signedTransactionHash } = {}) => {
        if (typeof journalPath !== "string" || !journalPath || !ethers.isHexString(signedTransactionHash, 32)) {
          throw new Error("durable challenge journal evidence is invalid");
        }
        for (const bucket of Object.values(state.days)) {
            const reservation = bucket.reservations?.[id];
            if (!reservation) continue;
            reservation.action_intent = {
              schema_version: "p42-challenge-action-intent/v1", intent_id: id, status: "journal_durable",
              journal_path: resolve(journalPath), signed_transaction_hash: signedTransactionHash.toLowerCase(),
            };
            atomicWrite(path, state, options.trustedRoot ?? dirname(path)); durable = true;
            if (releasePreflight) { releasePreflight(); releasePreflight = null; }
            release(); return;
          }
          throw new Error("durable challenge journal has no reservation");
      },
    });
  } catch (error) {
    release();
    if (!durable) releaseChallengeReservation(statePath, id, options);
    throw error;
  } finally {
    if (releasePreflight) releasePreflight();
    release();
  }
}

export function buildClaimBondPolicy({ challengeInterface, challengeContract, chainId, claimant, expiresAt }) {
  const calldata = challengeInterface.encodeFunctionData("claimBond");
  const scope = { action: "claimBond", chain_id: Number(chainId), target: challengeContract.toLowerCase(), claimant: claimant.toLowerCase() };
  return { schema_version: "p42-session-call-policy/v1", target: challengeContract.toLowerCase(), selector: calldata.slice(0, 10), calldata, calldata_hash: ethers.keccak256(calldata), scope, scope_hash: ethers.keccak256(ethers.toUtf8Bytes(canonicalJson(scope))), call_value_wei: "0", expires_at: String(expiresAt), max_calls: 1 };
}

export function claimedBondAmountFromReceipt({ receipt, challengeInterface, challengeContract, claimant }) {
  if (receipt?.status !== 1) throw new Error("successful claim receipt required");
  const matches = [];
  for (const log of receipt.logs ?? []) {
    if (String(log.address).toLowerCase() !== String(challengeContract).toLowerCase()) continue;
    try { const parsed = challengeInterface.parseLog(log); if (parsed?.name === "BondClaimed" && String(parsed.args.claimant).toLowerCase() === String(claimant).toLowerCase()) matches.push(BigInt(parsed.args.amount)); } catch {}
  }
  if (matches.length !== 1 || matches[0] <= 0n) throw new Error("claim receipt must contain exactly one positive BondClaimed event for claimant");
  return matches[0];
}

export function reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash, latestBlockNumber, confirmations, challengeInterface, challengeContract, claimant }) {
  if (journal?.schema_version !== "p42-claim-bond-action/v1") throw new Error("invalid claim-bond journal");
  if (!receipt) return { status: "rebroadcast", recovered_wei: "0" };
  if (!canonicalBlockHash || canonicalBlockHash.toLowerCase() !== receipt.blockHash.toLowerCase()) return { status: "reorged", recovered_wei: "0" };
  if (latestBlockNumber - receipt.blockNumber + 1 < confirmations) return { status: "submitted", recovered_wei: "0" };
  if (receipt.status !== 1) return { status: "broadcast_reverted", recovered_wei: "0" };
  return { status: "confirmed", recovered_wei: claimedBondAmountFromReceipt({ receipt, challengeInterface, challengeContract, claimant }).toString() };
}

export class P42ChallengeManager {
  constructor({ provider, wallet, agentWallet, challenge, chainId, journalPath, confirmations = 1, now = () => Date.now() }) { Object.assign(this, { provider, wallet, agentWallet, challenge, chainId, journalPath, confirmations, now }); }
  async assertClaimPolicy(policy, latestTimestamp) {
    const onchain = await this.agentWallet.callPolicies(policy.target, policy.selector);
    if (await this.agentWallet.sessionKey().then((v) => v.toLowerCase()) !== this.wallet.address.toLowerCase()) throw new Error("claim policy session key mismatch");
    if (Number(await this.agentWallet.sessionChainId()) !== this.chainId || await this.agentWallet.revoked()) throw new Error("claim policy session invalid");
    if (!await this.agentWallet.allowed(policy.target, policy.selector) || !onchain.configured || Number(onchain.chainId) !== this.chainId || Number(onchain.maxCalls) !== 1 || Number(onchain.calls) !== 0) throw new Error("claimBond exact policy is unavailable");
    if (BigInt(onchain.expiresAt) <= BigInt(latestTimestamp) || String(onchain.calldataHash).toLowerCase() !== policy.calldata_hash.toLowerCase() || String(onchain.scopeHash).toLowerCase() !== policy.scope_hash.toLowerCase()) throw new Error("claimBond exact policy mismatch");
  }
  async claimBond() {
    const claimant = (await this.agentWallet.getAddress()).toLowerCase();
    const archivePrefix = `${basename(this.journalPath)}.`;
    for (const name of readdirSync(dirname(this.journalPath)).filter((entry) => entry.startsWith(archivePrefix) && entry.endsWith(".confirmed"))) {
      const path = join(dirname(this.journalPath), name);
      const archived = readStrictJsonFileSync(path, JOURNAL_LIMITS);
      const receipt = await this.provider.getTransactionReceipt(archived.signed_tx.hash);
      const canonical = receipt ? await this.provider.getBlock(receipt.blockNumber) : null;
      const audit = reconcileClaimLifecycle({ journal: archived, receipt, canonicalBlockHash: canonical?.hash, latestBlockNumber: await this.provider.getBlockNumber(), confirmations: this.confirmations, challengeInterface: this.challenge.interface, challengeContract: await this.challenge.getAddress(), claimant });
      if (audit.status !== "confirmed") {
        archived.status = audit.status; archived.recovered_wei = "0"; atomicWrite(path, archived);
        throw new Error(`archived claim journal lost canonical finality: ${name}`);
      }
    }
    let journal = existsSync(this.journalPath) ? readStrictJsonFileSync(this.journalPath, JOURNAL_LIMITS) : null;
    if (journal?.status === "confirmed") {
      const receipt = await this.provider.getTransactionReceipt(journal.signed_tx.hash);
      const canonical = receipt ? await this.provider.getBlock(receipt.blockNumber) : null;
      const audit = reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash: canonical?.hash, latestBlockNumber: await this.provider.getBlockNumber(), confirmations: this.confirmations, challengeInterface: this.challenge.interface, challengeContract: await this.challenge.getAddress(), claimant });
      if (audit.status !== "confirmed") { journal.status = audit.status; journal.recovered_wei = "0"; atomicWrite(this.journalPath, journal); return audit; }
      const next = BigInt(await this.challenge.claimableBondWei(claimant)); if (next === 0n) return { status: "nothing_claimable", recovered_wei: "0" };
      renameSync(this.journalPath, `${this.journalPath}.${journal.signed_tx.hash.slice(2, 18)}.confirmed`); journal = null;
    }
    if (!journal) {
      const claimable = BigInt(await this.challenge.claimableBondWei(claimant)); if (claimable === 0n) return { status: "nothing_claimable", recovered_wei: "0" };
      const latest = await this.provider.getBlock("latest"); const policy = buildClaimBondPolicy({ challengeInterface: this.challenge.interface, challengeContract: await this.challenge.getAddress(), chainId: this.chainId, claimant, expiresAt: BigInt(latest.timestamp) + 3600n });
      await this.assertClaimPolicy(policy, latest.timestamp); const request = await this.agentWallet.execute.populateTransaction(policy.target, 0n, policy.calldata); const populated = await this.wallet.populateTransaction(request); const signable = { ...populated }; delete signable.from; const rawTx = await this.wallet.signTransaction(signable);
      journal = { schema_version: "p42-claim-bond-action/v1", status: "signed", policy, signed_tx: { schema_version: "p42-signed-transaction/v1", label: "claimBond", signer: this.wallet.address.toLowerCase(), hash: ethers.keccak256(rawTx), raw_tx: rawTx, chain_id: this.chainId, nonce: Number(signable.nonce), to: String(signable.to).toLowerCase(), value: "0", data_hash: ethers.keccak256(signable.data), signed_at_utc: new Date(this.now()).toISOString() }, recovered_wei: "0" }; atomicWrite(this.journalPath, journal);
    }
    const expectedData = this.agentWallet.interface.encodeFunctionData("execute", [journal.policy.target, 0n, journal.policy.calldata]); assertSignedTransactionRecord(journal.signed_tx, { signer: this.wallet.address, chainId: this.chainId, to: await this.agentWallet.getAddress(), value: 0n, data: expectedData, label: "claimBond" });
    let receipt = await this.provider.getTransactionReceipt(journal.signed_tx.hash);
    if (!receipt) { let pending = await this.provider.getTransaction(journal.signed_tx.hash); if (!pending) pending = await this.provider.broadcastTransaction(journal.signed_tx.raw_tx); journal.status = "broadcast"; journal.recovered_wei = "0"; atomicWrite(this.journalPath, journal); receipt = await pending.wait(); }
    const canonical = await this.provider.getBlock(receipt.blockNumber); const result = reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash: canonical?.hash, latestBlockNumber: await this.provider.getBlockNumber(), confirmations: this.confirmations, challengeInterface: this.challenge.interface, challengeContract: await this.challenge.getAddress(), claimant });
    journal.status = result.status; journal.recovered_wei = result.recovered_wei; journal.receipt = { transaction_hash: receipt.hash ?? journal.signed_tx.hash, block_number: receipt.blockNumber, block_hash: receipt.blockHash }; atomicWrite(this.journalPath, journal); return result;
  }
}
