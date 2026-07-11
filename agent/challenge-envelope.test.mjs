import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ethers } from "ethers";
import {
  acquireEnvelopeLock, buildClaimBondPolicy, claimedBondAmountFromReceipt, finalizeChallengeSpend, limitsFromProvisioning,
  releaseEnvelopeLock,
  reconcileClaimLifecycle, releaseChallengeReservation, reserveChallengeSpend, runnerHealthAdmission,
  reauthorizeChallengeReservation,
  runnerHealthFinalSigningAdmission,
  validateRunnerHealthPredecessor,
  runChallengeActionIntent, utcDay, validateCanonicalOpenEvidence, validateProvisioningArtifact,
} from "./challenge-envelope.mjs";

const CHALLENGE = `0x${"1".repeat(40)}`;
const AGENT_WALLET = `0x${"2".repeat(40)}`;
const OPERATOR_KEY = `0x${"3".repeat(64)}`;
const operator = new ethers.Wallet(OPERATOR_KEY);
const NOW = Date.UTC(2026, 6, 10, 12);
const root = () => mkdtempSync(join(tmpdir(), "p42-envelope-v2-"));

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

async function provisioning(overrides = {}) {
  const value = {
    schema_version: "p42-challenge-provisioning/v1", chain_id: 84532, challenge_manager: CHALLENGE,
    agent_wallet: AGENT_WALLET, operator: operator.address, per_challenge_wei: "50000000000000000",
    per_problem_day_wei: "100000000000000000", global_day_wei: "300000000000000000",
    max_canonical_open: 3, max_pending_provisioned: 1,
    rehearsal: { health_gate_verified: true, restart_recovery_verified: true, deep_reorg_verified: true, artifact_hash: `sha256:${"a".repeat(64)}` },
    ...overrides,
  };
  const preimage = structuredClone(value);
  value.artifact_hash = `sha256:${ethers.sha256(ethers.toUtf8Bytes(canonical(preimage))).slice(2)}`;
  value.signature = { scheme: "eip191", signer: operator.address, signature: await operator.signMessage(value.artifact_hash) };
  return value;
}

function health(overrides = {}) {
  return { schema_version: "p42-runner-health/v1", observed_at_utc: new Date(NOW).toISOString(), oom_kills: 0, worker_restarts: 0, queue_corruption_events: 0, max_active_running: 1, decision: "start", swap_guard: "green", host_capacity: "green", concurrency_guard: "green", ...overrides };
}

const healthKeys = generateKeyPairSync("ed25519");
const healthPublic = `ed25519:${healthKeys.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex")}`;
const recoveryKeys = generateKeyPairSync("ed25519");
const recoveryPublic = `ed25519:${recoveryKeys.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex")}`;
function incidentArtifact({ generation = 1, counters = { oom_kills: 1, worker_restarts: 0, queue_corruption_events: 0 }, blockTime = NOW / 1000 - 86_400, blockNumber = 50, blockHash = `0x${"9".repeat(64)}`, scope = {}, privateKey = recoveryKeys.privateKey, publicKey = recoveryPublic, domain = "P42-RUNNER-COUNTER-INCIDENT-V1\0" } = {}) {
  const value = { schema_version: "p42-runner-counter-incident/v1", generation, counters, scope: { health_public_key: healthPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE.toLowerCase(), ...scope }, block_number: blockNumber, block_hash: blockHash, block_time: blockTime };
  const hash = `sha256:${ethers.sha256(ethers.toUtf8Bytes(canonical(value))).slice(2)}`; const message = Buffer.concat([Buffer.from(domain), Buffer.from(hash.slice(7), "hex")]);
  return { ...value, artifact_hash: hash, signature: { algorithm: "ed25519", public_key: publicKey, signature: `ed25519:${sign(null, message, privateKey).toString("hex")}` } };
}
function recoveryAuthorization({ generation = 1, prior = { oom_kills: 0, worker_restarts: 0, queue_corruption_events: 0 }, current = { oom_kills: 1, worker_restarts: 0, queue_corruption_events: 0 }, baseline = current, scope = {}, remediation = `sha256:${"c".repeat(64)}`, rehearsal = `sha256:${"d".repeat(64)}`, incident = incidentArtifact({ generation, counters: current }), privateKey = recoveryKeys.privateKey, publicKey = recoveryPublic, domain = "P42-RUNNER-COUNTER-RECOVERY-V1\0" } = {}) {
  const value = { schema_version: "p42-runner-counter-recovery/v1", generation, prior_counters: prior, current_counters: current, baseline, remediation_artifact_hash: remediation, rehearsal_artifact_hash: rehearsal, incident_artifact: incident, incident_artifact_hash: incident.artifact_hash, scope: { health_public_key: healthPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE.toLowerCase(), target_sequence: generation, prior_artifact_hash: generation === 1 ? null : `sha256:${"e".repeat(64)}`, target_block_number: 100, target_block_hash: `0x${"a".repeat(64)}`, acknowledgement_block_number: 100, acknowledgement_block_hash: `0x${"a".repeat(64)}`, ...scope } };
  const hash = `sha256:${ethers.sha256(ethers.toUtf8Bytes(canonical(value))).slice(2)}`;
  const message = Buffer.concat([Buffer.from(domain), Buffer.from(hash.slice(7), "hex")]);
  return { ...value, authorization_hash: hash, signature: { algorithm: "ed25519", public_key: publicKey, signature: `ed25519:${sign(null, message, privateKey).toString("hex")}` } };
}
function healthV2(overrides = {}) {
  const base = {
    schema_version: "p42-runner-health/v2", observed_at_utc: new Date(NOW).toISOString(), sequence: 1, prior_artifact_hash: null,
    producer: { host_id: "dgx", boot_id: "boot", queue_id: "main" }, boot_transition: null,
    chain: { chain_id: 84532, contract: CHALLENGE.toLowerCase(), block_number: 100, block_hash: `0x${"a".repeat(64)}`, block_time: NOW / 1000 },
    counters: { oom_kills: 0, worker_restarts: 0, queue_corruption_events: 0 },
    counter_acknowledgement: { generation: 1, baseline: { oom_kills: 0, worker_restarts: 0, queue_corruption_events: 0 }, acknowledged_block_number: 100, acknowledged_block_hash: `0x${"a".repeat(64)}`, recovery_authorization: null },
    queue: { queue_hash: `sha256:${"b".repeat(64)}`, queue_bytes: 100, canonical_byte_headroom: 1024 * 1024 - 64 * 1024 - 100, active_job_count: 1, queued_job_count: 1, ordinary_admission_headroom: 895, urgent_admission_headroom: 959, archive_record_count: 0, tombstone_count: 0, oldest_queued_age_seconds: 2, earliest_live_deadline: null, minimum_challenge_slack_seconds: null, expired_deadline_critical_count: 0, warning_slack_seconds: 3600, critical_slack_seconds: 900, archive_fault: null, archive_fault_history: null, runner_plan: { decision: "start", max_active_running: 1, swap_guard: "green", host_capacity: "green", concurrency_guard: "green" } },
    ...overrides,
  };
  const unsigned = structuredClone(base); const artifactHash = `sha256:${ethers.sha256(ethers.toUtf8Bytes(canonical(unsigned))).slice(2)}`;
  const message = Buffer.concat([Buffer.from("P42-RUNNER-HEALTH-V2\0"), Buffer.from(artifactHash.slice(7), "hex")]);
  return { ...base, artifact_hash: artifactHash, signature: { algorithm: "ed25519", public_key: healthPublic, signature: `ed25519:${sign(null, message, healthKeys.privateKey).toString("hex")}` } };
}

function resignHealth(value) {
  const unsigned = structuredClone(value);
  delete unsigned.artifact_hash;
  delete unsigned.signature;
  const artifactHash = `sha256:${ethers.sha256(ethers.toUtf8Bytes(canonical(unsigned))).slice(2)}`;
  const message = Buffer.concat([Buffer.from("P42-RUNNER-HEALTH-V2\0"), Buffer.from(artifactHash.slice(7), "hex")]);
  return { ...unsigned, artifact_hash: artifactHash, signature: { algorithm: "ed25519", public_key: healthPublic, signature: `ed25519:${sign(null, message, healthKeys.privateKey).toString("hex")}` } };
}

function evidence(open = [], overrides = {}) {
  return { schema_version: "p42-canonical-open-evidence/v1", chain_id: 84532, challenge_manager: CHALLENGE, finalized_through_block: 100, observed_at_utc: new Date(NOW).toISOString(), complete: true, open_challenges: open, ...overrides };
}

function reserveInput(config, overrides = {}) {
  return { id: "a", problemId: "p", amountWei: ethers.parseEther("0.05"), provisioning: config, health: health(), canonicalOpenEvidence: evidence(), canonicalEvidenceExpected: { chainId: 84532, challengeManager: CHALLENGE, finalizedThroughBlock: 100, now: NOW }, ...overrides };
}

test("pending reservation survives UTC rollover and finalized tx charges original day", async () => {
  const path = join(root(), "state.json"); const config = await provisioning();
  const atRollover = Date.UTC(2026, 6, 10, 23, 59);
  reserveChallengeSpend(path, reserveInput(config, { health: health({ observed_at_utc: new Date(atRollover).toISOString() }) }), { now: atRollover });
  finalizeChallengeSpend(path, "a", { now: Date.UTC(2026, 6, 11), finalizedReceipt: { canonical: true, transaction_hash: `0x${"4".repeat(64)}`, block_number: 101, block_hash: `0x${"5".repeat(64)}` } });
  const state = JSON.parse(readFileSync(path));
  assert.ok(state.days["2026-07-10"].spends.a);
  assert.equal(state.days["2026-07-10"].reservations.a, undefined);
  assert.equal(state.days["2026-07-11"], undefined);
  assert.equal(utcDay(Date.UTC(2026, 6, 11)), "2026-07-11");
});

test("finalized tx fails closed without durable reservation and never loses accounting row", async () => {
  const path = join(root(), "state.json"); const config = await provisioning();
  reserveChallengeSpend(path, reserveInput(config), { now: NOW });
  assert.throws(() => finalizeChallengeSpend(path, "a", { now: NOW, finalizedReceipt: { canonical: false } }), /finalized canonical/);
  assert.ok(JSON.parse(readFileSync(path)).days["2026-07-10"].reservations.a);
  assert.throws(() => finalizeChallengeSpend(join(root(), "empty.json"), "missing", { now: NOW, finalizedReceipt: { canonical: true, transaction_hash: `0x${"4".repeat(64)}`, block_number: 1, block_hash: `0x${"5".repeat(64)}` } }), /no durable reservation/);
});

test("admission uses complete finalized canonical chain evidence and rejects local or incomplete guesses", async () => {
  const config = await provisioning(); const path = join(root(), "state.json");
  for (const bad of [null, evidence([], { complete: false }), evidence([], { finalized_through_block: 99 }), evidence([], { observed_at_utc: new Date(NOW + 1).toISOString() })]) {
    assert.throws(() => reserveChallengeSpend(path, reserveInput(config, { canonicalOpenEvidence: bad }), { now: NOW }), /canonical open evidence/);
  }
  const open = [1, 2, 3].map((id) => ({ submission_id: String(id), challenge_instance_hash: `0x${String(id).repeat(64)}` }));
  assert.throws(() => reserveChallengeSpend(path, reserveInput(config, { canonicalOpenEvidence: evidence(open) }), { now: NOW }), /open challenge cap/);
  assert.doesNotThrow(() => validateCanonicalOpenEvidence(evidence(), { chainId: 84532, challengeManager: CHALLENGE, finalizedThroughBlock: 100, now: NOW }));
});

test("limits come from signed provisioning and runtime values may only tighten", async () => {
  const config = await provisioning();
  assert.equal(limitsFromProvisioning(config).perChallengeWei, ethers.parseEther("0.05"));
  assert.equal(limitsFromProvisioning(config, { perChallengeWei: ethers.parseEther("0.04") }).perChallengeWei, ethers.parseEther("0.04"));
  assert.throws(() => limitsFromProvisioning(config, { perChallengeWei: ethers.parseEther("0.06") }), /only tighten/);
  assert.throws(() => limitsFromProvisioning(config, { inventedCap: 1 }), /unknown/);
  assert.throws(() => reserveChallengeSpend(join(root(), "state.json"), reserveInput(config, { limits: { perChallengeWei: ethers.parseEther("1") } }), { now: NOW }), /overrides are forbidden/);
});

test("one pending exact policy remains global across UTC buckets and concurrent processes", async () => {
  const path = join(root(), "state.json"); const config = await provisioning();
  reserveChallengeSpend(path, reserveInput(config), { now: NOW });
  const nextDay = NOW + 86_400_000;
  assert.throws(() => reserveChallengeSpend(path, reserveInput(config, { id: "b", amountWei: 1n, health: health({ observed_at_utc: new Date(nextDay).toISOString() }), canonicalOpenEvidence: evidence([], { observed_at_utc: new Date(nextDay).toISOString() }), canonicalEvidenceExpected: { chainId: 84532, challengeManager: CHALLENGE, finalizedThroughBlock: 100, now: nextDay } }), { now: nextDay }), /one exact/);
  releaseChallengeReservation(path, "a", { now: NOW + 86_400_000 });
  const module = new URL("./challenge-envelope.mjs", import.meta.url).href;
  const encoded = Buffer.from(JSON.stringify(config)).toString("base64");
  const script = `import {reserveChallengeSpend} from '${module}'; const c=JSON.parse(Buffer.from(process.argv[3],'base64')); try { reserveChallengeSpend(process.argv[1],{id:process.argv[2],problemId:'p',amountWei:1n,provisioning:c,health:${JSON.stringify(health())},canonicalOpenEvidence:${JSON.stringify(evidence())},canonicalEvidenceExpected:{chainId:84532,challengeManager:'${CHALLENGE}',finalizedThroughBlock:100,now:${NOW}}},{now:${NOW}}); } catch { process.exit(3); }`;
  const results = ["x", "y"].map((id) => { try { execFileSync(process.execPath, ["--input-type=module", "-e", script, path, id, encoded]); return 0; } catch (error) { return error.status; } });
  assert.equal(results.filter((status) => status === 0).length, 1);
});

test("live owner cannot be stolen after an arbitrarily old lock timestamp", () => {
  const lock = join(root(), "state.lock");
  const owner = acquireEnvelopeLock(lock, { now: () => 0 });
  assert.throws(() => acquireEnvelopeLock(lock, { timeoutMs: 20 }), /lock timeout/);
  releaseEnvelopeLock(lock, owner);
});

test("stale release token cannot remove a successor lock", () => {
  const lock = join(root(), "state.lock");
  const first = acquireEnvelopeLock(lock);
  releaseEnvelopeLock(lock, first);
  const successor = acquireEnvelopeLock(lock);
  assert.throws(() => releaseEnvelopeLock(lock, first), /token mismatch/);
  assert.throws(() => acquireEnvelopeLock(lock, { timeoutMs: 20 }), /lock timeout/);
  releaseEnvelopeLock(lock, successor);
});

test("same-host lock is reclaimed only after its owner process is dead", () => {
  const lock = join(root(), "state.lock");
  const module = new URL("./challenge-envelope.mjs", import.meta.url).href;
  execFileSync(process.execPath, ["--input-type=module", "-e", `import {acquireEnvelopeLock} from '${module}'; acquireEnvelopeLock(process.argv[1]);`, lock]);
  const replacement = acquireEnvelopeLock(lock, { timeoutMs: 1000 });
  releaseEnvelopeLock(lock, replacement);
});

test("pre-journal fault releases reservation and restart can use sole pending slot", async () => {
  const path = join(root(), "state.json"); const config = await provisioning();
  reserveChallengeSpend(path, reserveInput(config), { now: NOW });
  await assert.rejects(
    runChallengeActionIntent(path, "a", async () => { throw new Error("fault-before-journal"); }, { now: NOW }),
    /fault-before-journal/,
  );
  assert.equal(JSON.parse(readFileSync(path)).days["2026-07-10"].reservations.a, undefined);
  assert.equal(reserveChallengeSpend(path, reserveInput(config, { id: "restart" }), { now: NOW }).reserved, true);
});

test("action-intent preflight runs under the envelope lock before signing and fails closed", async () => {
  const path = join(root(), "state.json"); const config = await provisioning();
  reserveChallengeSpend(path, reserveInput(config), { now: NOW });
  let operationStarted = false;
  await assert.rejects(
    runChallengeActionIntent(path, "a", async () => { operationStarted = true; }, { now: NOW, preflight: () => { throw new Error("queue hash drift"); } }),
    /queue hash drift/,
  );
  assert.equal(operationStarted, false);
  assert.equal(JSON.parse(readFileSync(path)).days["2026-07-10"].reservations.a, undefined);
});

test("action-intent keeps the envelope lock across asynchronous preflight and signer boundary", async () => {
  const path = join(root(), "state.json"); const config = await provisioning();
  reserveChallengeSpend(path, reserveInput(config), { now: NOW });
  let entered; const enteredPromise = new Promise((resolve) => { entered = resolve; });
  let continuePreflight; const gate = new Promise((resolve) => { continuePreflight = resolve; });
  const action = runChallengeActionIntent(path, "a", async ({ markJournalDurable }) => {
    markJournalDurable({ journalPath: join(root(), "signed.json"), signedTransactionHash: `0x${"a".repeat(64)}` });
  }, { now: NOW, preflight: async () => { entered(); await gate; } });
  await enteredPromise;
  assert.throws(() => acquireEnvelopeLock(`${path}.lock`, { timeoutMs: 20 }), /lock timeout/);
  continuePreflight(); await action;
  const replacement = acquireEnvelopeLock(`${path}.lock`, { timeoutMs: 100 }); releaseEnvelopeLock(`${path}.lock`, replacement);
});

test("post-journal fault preserves intent and restart resumes same reservation", async () => {
  const path = join(root(), "state.json"); const config = await provisioning();
  reserveChallengeSpend(path, reserveInput(config), { now: NOW });
  await assert.rejects(
    runChallengeActionIntent(path, "a", async ({ markJournalDurable }) => { markJournalDurable({ journalPath: join(root(), "signed.json"), signedTransactionHash: `0x${"a".repeat(64)}` }); throw new Error("fault-after-journal"); }, { now: NOW }),
    /fault-after-journal/,
  );
  assert.equal(JSON.parse(readFileSync(path)).days["2026-07-10"].reservations.a.action_intent.status, "journal_durable");
  assert.equal(reserveChallengeSpend(path, reserveInput(config), { now: NOW }).idempotent, true);
  assert.equal(await runChallengeActionIntent(path, "a", async ({ markJournalDurable }) => { markJournalDurable({ journalPath: join(root(), "signed.json"), signedTransactionHash: `0x${"a".repeat(64)}` }); return "resumed"; }, { now: NOW }), "resumed");
});

test("health requires complete explicit green fields, freshness, and no future timestamp", () => {
  assert.equal(runnerHealthAdmission(health(), { now: NOW }).allowed, true);
  for (const bad of [health({ observed_at_utc: new Date(NOW + 1).toISOString() }), health({ swap_guard: undefined }), health({ host_capacity: "red" }), health({ concurrency_guard: undefined }), health({ oom_kills: 1 }), health({ queue_corruption_events: undefined })]) assert.equal(runnerHealthAdmission(bad, { now: NOW }).allowed, false);
});

test("production health v2 verifies signature, bindings, algebra, and downgrade resistance", () => {
  const expected = { public_key: healthPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  const admission = runnerHealthAdmission(healthV2(), { now: NOW, requireV2: true, expected });
  assert.equal(admission.allowed, true, JSON.stringify(admission));
  assert.equal(runnerHealthAdmission(health(), { now: NOW, requireV2: true, expected }).allowed, false);
  for (const mutate of [
    (v) => { const fault = { schema_version: "p42-runner-archive-fault/v1", status: "active", first_observed_at_utc: new Date(NOW).toISOString(), last_observed_at_utc: new Date(NOW).toISOString(), event_count: 1, reason: "disk", reason_hash: `sha256:${ethers.sha256(ethers.toUtf8Bytes("disk")).slice(2)}`, recovery_generation: 0, recovered_at_utc: null, job_id: null, source_event_hash: null, archive_hash: null }; v.queue.archive_fault = fault; v.queue.archive_fault_history = fault; }, (v) => { v.queue.urgent_admission_headroom = 0; },
    (v) => { v.queue.expired_deadline_critical_count = 1; }, (v) => { v.queue.canonical_byte_headroom += 1; },
    (v) => { v.signature.signature = `ed25519:${"0".repeat(128)}`; },
  ]) { const bad = healthV2(); mutate(bad); assert.equal(runnerHealthAdmission(bad, { now: NOW, requireV2: true, expected }).allowed, false); }
  const legacyFourMiB = healthV2();
  legacyFourMiB.queue.canonical_byte_headroom = 4 * 1024 * 1024 - 64 * 1024 - legacyFourMiB.queue.queue_bytes;
  assert.equal(runnerHealthAdmission(resignHealth(legacyFourMiB), { now: NOW, requireV2: true, expected }).allowed, false);
});

test("health v2 enforces null deadlines, critical chain slack, and monotonic predecessor", () => {
  const expected = { public_key: healthPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  const prior = healthV2();
  const next = healthV2({ sequence: 2, prior_artifact_hash: prior.artifact_hash, counters: { oom_kills: 0, worker_restarts: 0, queue_corruption_events: 0 } });
  const admission = runnerHealthAdmission(next, { now: NOW, requireV2: true, expected, prior });
  assert.equal(admission.allowed, true, JSON.stringify(admission));
  assert.equal(runnerHealthAdmission(next, { now: NOW, requireV2: true, expected }).allowed, false);
  const critical = healthV2({ queue: { ...healthV2().queue, earliest_live_deadline: NOW / 1000 + 900, minimum_challenge_slack_seconds: 900 } });
  assert.equal(runnerHealthAdmission(critical, { now: NOW, requireV2: true, expected }).allowed, false);
  const mismatchedNull = healthV2({ queue: { ...healthV2().queue, earliest_live_deadline: NOW / 1000 + 1000, minimum_challenge_slack_seconds: null } });
  assert.equal(runnerHealthAdmission(mismatchedNull, { now: NOW, requireV2: true, expected }).allowed, false);
});

test("durable high-water rejects forks and root replay while permitting signed boot transition", () => {
  const expected = { public_key: healthPublic, host_id: "dgx", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  const rootHealth = healthV2();
  const highWater = { sequence: 1, artifact_hash: rootHealth.artifact_hash, host_id: "dgx", boot_id: "boot", queue_id: "main", counters: rootHealth.counters };
  const fork = healthV2({ sequence: 1, prior_artifact_hash: null, producer: { host_id: "dgx", boot_id: "boot", queue_id: "main" }, chain: { ...rootHealth.chain, block_number: 99, block_hash: `0x${"c".repeat(64)}` }, counters: { ...rootHealth.counters } });
  assert.equal(runnerHealthAdmission(fork, { now: NOW, requireV2: true, expected, highWater }).allowed, false);
  const transition = healthV2({
    sequence: 2, prior_artifact_hash: rootHealth.artifact_hash,
    producer: { host_id: "dgx", boot_id: "boot-2", queue_id: "main" },
    boot_transition: { previous_boot_id: "boot", new_boot_id: "boot-2", reason: "host reboot", transition_block_number: 100, transition_block_hash: `0x${"a".repeat(64)}` },
  });
  assert.equal(runnerHealthAdmission(transition, { now: NOW, requireV2: true, expected: { ...expected, boot_id: "boot-2" }, highWater }).allowed, true);
  const reset = healthV2({ producer: { host_id: "dgx", boot_id: "boot-2", queue_id: "main" } });
  assert.equal(runnerHealthAdmission(reset, { now: NOW, requireV2: true, expected: { ...expected, boot_id: "boot-2" }, highWater }).allowed, false);
});

test("consumer persists health high-water before action and rejects a fork after restart", async () => {
  const path = join(root(), "state.json"); const config = await provisioning();
  const rootHealth = healthV2();
  const expected = { public_key: healthPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  reserveChallengeSpend(path, reserveInput(config, { health: rootHealth }), { now: NOW, requireHealthV2: true, expectedHealth: expected });
  const persisted = JSON.parse(readFileSync(path));
  assert.equal(persisted.runner_health_high_water.artifact_hash, rootHealth.artifact_hash);
  assert.deepEqual(persisted.days["2026-07-10"].reservations.a.runner_health_authorization, { schema_version: "p42-runner-health-reservation-binding/v1", sequence: 1, artifact_hash: rootHealth.artifact_hash });
  releaseChallengeReservation(path, "a", { now: NOW });
  assert.throws(() => reserveChallengeSpend(path, reserveInput(config, { id: "replay", health: rootHealth }), { now: NOW, requireHealthV2: true, expectedHealth: expected }), /high-water/);
  const fork = healthV2({ chain: { ...rootHealth.chain, block_number: 99, block_hash: `0x${"d".repeat(64)}` } });
  assert.throws(() => reserveChallengeSpend(path, reserveInput(config, { id: "fork", health: fork }), { now: NOW, requireHealthV2: true, expectedHealth: expected }), /high-water/);
});

test("final signing may revalidate only the exact health generation bound to its reservation", async () => {
  const path = join(root(), "state.json"); const config = await provisioning(); const value = healthV2();
  const expected = { public_key: healthPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  reserveChallengeSpend(path, reserveInput(config, { health: value }), { now: NOW, requireHealthV2: true, expectedHealth: expected });
  let observed;
  await runChallengeActionIntent(path, "a", async ({ markJournalDurable }) => {
    markJournalDurable({ journalPath: join(root(), "bound.json"), signedTransactionHash: `0x${"e".repeat(64)}` });
  }, { now: NOW, preflight: (highWater, reservationBinding) => {
    observed = { highWater, reservationBinding };
    const admitted = runnerHealthAdmission(value, { now: NOW, requireV2: true, expected, highWater, reservationBinding });
    assert.equal(admitted.allowed, true, JSON.stringify(admitted));
  } });
  assert.equal(observed.reservationBinding.artifact_hash, value.artifact_hash);
  assert.equal(runnerHealthAdmission(value, { now: NOW, requireV2: true, expected, highWater: observed.highWater, reservationBinding: { ...observed.reservationBinding, artifact_hash: `sha256:${"0".repeat(64)}` } }).allowed, false);
});

test("seq2 current health cannot sign a seq1 reservation until atomic reauthorization", async () => {
  const path = join(root(), "state.json"); const config = await provisioning(); const first = healthV2();
  const expected = { public_key: healthPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  reserveChallengeSpend(path, reserveInput(config, { health: first }), { now: NOW, requireHealthV2: true, expectedHealth: expected });
  const second = healthV2({ sequence: 2, prior_artifact_hash: first.artifact_hash });
  const highWater = JSON.parse(readFileSync(path)).runner_health_high_water;
  const binding = JSON.parse(readFileSync(path)).days["2026-07-10"].reservations.a.runner_health_authorization;
  assert.equal(runnerHealthAdmission(second, { now: NOW, requireV2: true, expected, highWater, reservationBinding: binding }).allowed, false);
  reauthorizeChallengeReservation(path, "a", second, { now: NOW, expectedHealth: expected });
  let checked = false;
  await runChallengeActionIntent(path, "a", async ({ markJournalDurable }) => { markJournalDurable({ journalPath: join(root(), "seq2.json"), signedTransactionHash: `0x${"f".repeat(64)}` }); }, { now: NOW, preflight: (current, reserved) => { checked = runnerHealthAdmission(second, { now: NOW, requireV2: true, expected, highWater: current, reservationBinding: reserved }).allowed; } });
  assert.equal(checked, true);
});

test("final signer gate requires finalized canonical block, live slack, and bounded age", () => {
  const value = healthV2();
  const input = { healthBlock: { number: 100, hash: value.chain.block_hash, timestamp: value.chain.block_time }, latestBlock: { number: 112, timestamp: value.chain.block_time + 1 }, confirmations: 12, authorizationStartedAt: NOW - 1000, now: NOW };
  assert.equal(runnerHealthFinalSigningAdmission(value, input).allowed, true);
  assert.equal(runnerHealthFinalSigningAdmission(value, { ...input, latestBlock: { ...input.latestBlock, number: 111 } }).allowed, false);
  assert.equal(runnerHealthFinalSigningAdmission(value, { ...input, healthBlock: { ...input.healthBlock, hash: `0x${"f".repeat(64)}` } }).allowed, false);
  assert.equal(runnerHealthFinalSigningAdmission(value, { ...input, authorizationStartedAt: NOW - 5001 }).allowed, false);
  const critical = healthV2({ queue: { ...value.queue, earliest_live_deadline: value.chain.block_time + 901, minimum_challenge_slack_seconds: 901 } });
  assert.equal(runnerHealthFinalSigningAdmission(critical, input).allowed, false);
});

test("lifetime incidents require a signed monotonic acknowledgement generation", () => {
  const expected = { public_key: healthPublic, recovery_public_key: recoveryPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  const counters = { oom_kills: 2, worker_restarts: 1, queue_corruption_events: 0 };
  const authorization = recoveryAuthorization({ current: counters, baseline: counters });
  const acknowledged = healthV2({ counters, counter_acknowledgement: { generation: 1, baseline: counters, acknowledged_block_number: 100, acknowledged_block_hash: `0x${"a".repeat(64)}`, recovery_authorization: authorization } });
  const rootAdmission = runnerHealthAdmission(acknowledged, { now: NOW, requireV2: true, expected });
  assert.equal(rootAdmission.allowed, true, JSON.stringify(rootAdmission));
  const unacknowledged = healthV2({ counters: { oom_kills: 1, worker_restarts: 0, queue_corruption_events: 0 } });
  assert.equal(runnerHealthAdmission(unacknowledged, { now: NOW, requireV2: true, expected }).allowed, false);
  const nextCounters = { oom_kills: 3, worker_restarts: 1, queue_corruption_events: 0 };
  const nextAuth = recoveryAuthorization({ generation: 2, prior: counters, current: nextCounters, baseline: nextCounters, scope: { target_sequence: 2, prior_artifact_hash: acknowledged.artifact_hash } });
  const recovered = healthV2({ sequence: 2, prior_artifact_hash: acknowledged.artifact_hash, counters: nextCounters, counter_acknowledgement: { generation: 2, baseline: nextCounters, acknowledged_block_number: 100, acknowledged_block_hash: `0x${"a".repeat(64)}`, recovery_authorization: nextAuth } });
  assert.equal(runnerHealthAdmission(recovered, { now: NOW, requireV2: true, expected, prior: acknowledged }).allowed, true);
});

test("counter recovery rejects self-clear, wrong domain/key, replay, scope, and evidence mismatch", () => {
  const counters = { oom_kills: 1, worker_restarts: 0, queue_corruption_events: 0 };
  const expected = { public_key: healthPublic, recovery_public_key: recoveryPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  const artifact = (authorization) => healthV2({ counters, counter_acknowledgement: { generation: 1, baseline: counters, acknowledged_block_number: 100, acknowledged_block_hash: `0x${"a".repeat(64)}`, recovery_authorization: authorization } });
  assert.equal(runnerHealthAdmission(artifact(null), { now: NOW, requireV2: true, expected }).allowed, false);
  assert.equal(runnerHealthAdmission(artifact(recoveryAuthorization({ privateKey: healthKeys.privateKey, publicKey: healthPublic })), { now: NOW, requireV2: true, expected }).allowed, false);
  assert.equal(runnerHealthAdmission(artifact(recoveryAuthorization({ domain: "P42-RUNNER-HEALTH-V2\0" })), { now: NOW, requireV2: true, expected }).allowed, false);
  const other = generateKeyPairSync("ed25519"); const otherPublic = `ed25519:${other.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex")}`;
  assert.equal(runnerHealthAdmission(artifact(recoveryAuthorization({ privateKey: other.privateKey, publicKey: otherPublic })), { now: NOW, requireV2: true, expected }).allowed, false);
  assert.equal(runnerHealthAdmission(artifact(recoveryAuthorization({ scope: { queue_id: "other" } })), { now: NOW, requireV2: true, expected }).allowed, false);
  assert.equal(runnerHealthAdmission(artifact(recoveryAuthorization({ scope: { boot_id: "other" } })), { now: NOW, requireV2: true, expected }).allowed, false);
  assert.equal(runnerHealthAdmission(artifact(recoveryAuthorization({ scope: { target_block_number: 99 } })), { now: NOW, requireV2: true, expected }).allowed, false);
  assert.equal(runnerHealthAdmission(artifact(recoveryAuthorization({ remediation: "sha256:" + "0".repeat(64) })), { now: NOW, requireV2: true, expected: { ...expected, remediation_artifact_hash: `sha256:${"c".repeat(64)}` } }).allowed, false);
  assert.equal(runnerHealthAdmission(artifact(recoveryAuthorization({ rehearsal: "sha256:" + "0".repeat(64) })), { now: NOW, requireV2: true, expected: { ...expected, rehearsal_artifact_hash: `sha256:${"d".repeat(64)}` } }).allowed, false);
  const valid = artifact(recoveryAuthorization()); const highWater = { sequence: 1, artifact_hash: valid.artifact_hash, host_id: "dgx", boot_id: "boot", queue_id: "main", counters, counter_acknowledgement: valid.counter_acknowledgement };
  const replay = healthV2({ sequence: 2, prior_artifact_hash: valid.artifact_hash, counters, counter_acknowledgement: { ...valid.counter_acknowledgement, generation: 2 } });
  assert.equal(runnerHealthAdmission(replay, { now: NOW, requireV2: true, expected, highWater }).allowed, false);
});

test("two-phase incident cooldown uses canonical block time and exact boundary", () => {
  const counters = { oom_kills: 1, worker_restarts: 0, queue_corruption_events: 0 };
  const expected = { public_key: healthPublic, recovery_public_key: recoveryPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  const build = (incident) => { const auth = recoveryAuthorization({ current: counters, baseline: counters, incident }); return healthV2({ counters, counter_acknowledgement: { generation: 1, baseline: counters, acknowledged_block_number: 100, acknowledged_block_hash: `0x${"a".repeat(64)}`, recovery_authorization: auth } }); };
  const exactIncident = incidentArtifact({ counters, blockTime: NOW / 1000 - 86_400 }); const exact = build(exactIncident);
  assert.equal(runnerHealthAdmission(exact, { now: NOW, requireV2: true, expected }).allowed, true);
  const insufficient = build(incidentArtifact({ counters, blockTime: NOW / 1000 - 86_399 }));
  assert.equal(runnerHealthAdmission(insufficient, { now: NOW, requireV2: true, expected }).allowed, false);
  const forged = structuredClone(exactIncident); forged.signature.signature = `ed25519:${"0".repeat(128)}`;
  assert.equal(runnerHealthAdmission(build(forged), { now: NOW, requireV2: true, expected }).allowed, false);
  assert.equal(runnerHealthAdmission(build(incidentArtifact({ generation: 2, counters })), { now: NOW, requireV2: true, expected }).allowed, false);
  const finalInput = { healthBlock: { number: 100, hash: exact.chain.block_hash, timestamp: exact.chain.block_time }, latestBlock: { number: 112, timestamp: exact.chain.block_time }, incidentBlock: { number: exactIncident.block_number, hash: exactIncident.block_hash, timestamp: exactIncident.block_time + 1 }, confirmations: 12, authorizationStartedAt: NOW, now: NOW };
  assert.equal(runnerHealthFinalSigningAdmission(exact, finalInput).allowed, false);
  assert.equal(runnerHealthFinalSigningAdmission(exact, { ...finalInput, incidentBlock: { number: exactIncident.block_number, hash: exactIncident.block_hash, timestamp: exactIncident.block_time } }).allowed, true);
});

test("consumed recovery hash persists and rejects root, fork, and bootstrap reuse", async () => {
  const path = join(root(), "state.json"); const config = await provisioning(); const counters = { oom_kills: 1, worker_restarts: 0, queue_corruption_events: 0 };
  const expected = { public_key: healthPublic, recovery_public_key: recoveryPublic, host_id: "dgx", boot_id: "boot", queue_id: "main", chain_id: 84532, contract: CHALLENGE };
  const authorization = recoveryAuthorization({ current: counters, baseline: counters });
  const first = healthV2({ counters, counter_acknowledgement: { generation: 1, baseline: counters, acknowledged_block_number: 100, acknowledged_block_hash: `0x${"a".repeat(64)}`, recovery_authorization: authorization } });
  reserveChallengeSpend(path, reserveInput(config, { health: first }), { now: NOW, requireHealthV2: true, expectedHealth: expected });
  const persisted = JSON.parse(readFileSync(path)).runner_health_high_water;
  assert.deepEqual(persisted.consumed_recovery_authorization_hashes, [authorization.authorization_hash]);
  releaseChallengeReservation(path, "a", { now: NOW });
  assert.throws(() => reserveChallengeSpend(path, reserveInput(config, { id: "bootstrap", health: first }), { now: NOW, requireHealthV2: true, expectedHealth: expected }), /high-water/);
  const reusedAck = { ...first.counter_acknowledgement, generation: 2 };
  const fork = healthV2({ sequence: 2, prior_artifact_hash: first.artifact_hash, counters, counter_acknowledgement: reusedAck });
  const replayAdmission = runnerHealthAdmission(fork, { now: NOW, requireV2: true, expected, highWater: persisted });
  assert.equal(replayAdmission.allowed, false); assert.match(replayAdmission.detail, /already consumed/);
});

test("historical predecessor validator accepts stale prior boot and rejects linkage tampering", () => {
  const prior = healthV2({ observed_at_utc: "2020-01-01T00:00:00.000Z", chain: { ...healthV2().chain, block_time: 1577836800 }, queue: { ...healthV2().queue, runner_plan: { ...healthV2().queue.runner_plan, decision: "wait" } } });
  const current = healthV2({ sequence: 2, prior_artifact_hash: prior.artifact_hash, producer: { host_id: "dgx", boot_id: "boot-2", queue_id: "main" }, boot_transition: { previous_boot_id: "boot", new_boot_id: "boot-2", reason: "reboot", transition_block_number: 100, transition_block_hash: `0x${"a".repeat(64)}` } });
  assert.equal(validateRunnerHealthPredecessor(prior, current, { public_key: healthPublic, host_id: "dgx", boot_id: "boot-2", queue_id: "main", chain_id: 84532, contract: CHALLENGE }), prior);
  const tampered = healthV2({ sequence: 2, prior_artifact_hash: `sha256:${"0".repeat(64)}`, producer: { host_id: "dgx", boot_id: "boot-2", queue_id: "main" }, boot_transition: { previous_boot_id: "boot", new_boot_id: "boot-2", reason: "reboot", transition_block_number: 100, transition_block_hash: `0x${"a".repeat(64)}` } });
  assert.throws(() => validateRunnerHealthPredecessor(prior, tampered, { public_key: healthPublic, host_id: "dgx", boot_id: "boot-2", queue_id: "main" }), /linkage/);
});

test("claim recovery derives exact BondClaimed event amount and rejects ambiguity", () => {
  const iface = new ethers.Interface(["event BondClaimed(address indexed claimant,uint256 amount)", "function claimBond()"]);
  const event = iface.encodeEventLog(iface.getEvent("BondClaimed"), [AGENT_WALLET, 17n]);
  const receipt = { status: 1, blockNumber: 10, blockHash: `0x${"b".repeat(64)}`, logs: [{ address: CHALLENGE, ...event }] };
  assert.equal(claimedBondAmountFromReceipt({ receipt, challengeInterface: iface, challengeContract: CHALLENGE, claimant: AGENT_WALLET }), 17n);
  const journal = { schema_version: "p42-claim-bond-action/v1", status: "broadcast" };
  assert.deepEqual(reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash: receipt.blockHash, latestBlockNumber: 12, confirmations: 3, challengeInterface: iface, challengeContract: CHALLENGE, claimant: AGENT_WALLET }), { status: "confirmed", recovered_wei: "17" });
  assert.throws(() => claimedBondAmountFromReceipt({ receipt: { ...receipt, logs: [...receipt.logs, ...receipt.logs] }, challengeInterface: iface, challengeContract: CHALLENGE, claimant: AGENT_WALLET }), /exactly one/);
});

test("deep reorg rolls confirmed recovered amount back to zero", () => {
  const iface = new ethers.Interface(["event BondClaimed(address indexed claimant,uint256 amount)"]);
  const event = iface.encodeEventLog(iface.getEvent("BondClaimed"), [AGENT_WALLET, 19n]);
  const receipt = { status: 1, blockNumber: 20, blockHash: `0x${"c".repeat(64)}`, logs: [{ address: CHALLENGE, ...event }] };
  const journal = { schema_version: "p42-claim-bond-action/v1", status: "confirmed", recovered_wei: "19" };
  assert.deepEqual(reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash: `0x${"d".repeat(64)}`, latestBlockNumber: 30, confirmations: 3, challengeInterface: iface, challengeContract: CHALLENGE, claimant: AGENT_WALLET }), { status: "reorged", recovered_wei: "0" });
  assert.deepEqual(reconcileClaimLifecycle({ journal, receipt: null, latestBlockNumber: 30, confirmations: 3, challengeInterface: iface, challengeContract: CHALLENGE, claimant: AGENT_WALLET }), { status: "rebroadcast", recovered_wei: "0" });
});

test("provisioning validates complete bindings, hashes, rehearsal, and signature", async () => {
  const config = await provisioning();
  assert.equal(validateProvisioningArtifact(config, { chainId: 84532, challengeManager: CHALLENGE, agentWallet: AGENT_WALLET, operator: operator.address }), config);
  for (const mutate of [(v) => { v.chain_id = 1; }, (v) => { v.challenge_manager = ethers.ZeroAddress; }, (v) => { v.rehearsal.deep_reorg_verified = false; }, (v) => { v.artifact_hash = `sha256:${"0".repeat(64)}`; }, (v) => { v.signature.signature = `0x${"0".repeat(130)}`; }]) {
    const bad = structuredClone(config); mutate(bad); assert.throws(() => validateProvisioningArtifact(bad), /provisioning|rehearsal/);
  }
});

test("published provisioning schema rejects extras and exact-type violations", async () => {
  const config = await provisioning();
  const topExtra = { ...config, surprise: true };
  assert.throws(() => validateProvisioningArtifact(topExtra), /additional properties/);
  const nestedExtra = structuredClone(config); nestedExtra.rehearsal.surprise = true;
  assert.throws(() => validateProvisioningArtifact(nestedExtra), /additional properties/);
  const stringChain = structuredClone(config); stringChain.chain_id = "84532";
  assert.throws(() => validateProvisioningArtifact(stringChain), /must be integer/);
  const stringOpen = structuredClone(config); stringOpen.max_canonical_open = "3";
  assert.throws(() => validateProvisioningArtifact(stringOpen), /must be equal to constant/);
});

test("claim call policy remains an exact one-call selector policy", () => {
  const iface = new ethers.Interface(["function claimBond()"]);
  const policy = buildClaimBondPolicy({ challengeInterface: iface, challengeContract: CHALLENGE, chainId: 84532, claimant: AGENT_WALLET, expiresAt: 99 });
  assert.equal(policy.calldata, iface.encodeFunctionData("claimBond")); assert.equal(policy.max_calls, 1);
});
