import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ethers } from "ethers";
import {
  acquireEnvelopeLock, buildClaimBondPolicy, claimedBondAmountFromReceipt, finalizeChallengeSpend, limitsFromProvisioning,
  releaseEnvelopeLock,
  reconcileClaimLifecycle, releaseChallengeReservation, reserveChallengeSpend, runnerHealthAdmission,
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
