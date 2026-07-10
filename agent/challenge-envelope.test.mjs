import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ethers } from "ethers";
import {
  DEFAULT_CHALLENGE_LIMITS, buildClaimBondPolicy, closeCanonicalChallenge, finalizeChallengeSpend,
  reconcileClaimLifecycle, releaseChallengeReservation, reserveChallengeSpend, runnerHealthAdmission,
  utcDay, validateProvisioningArtifact,
} from "./challenge-envelope.mjs";

const GREEN = { oom_kills: 0, worker_restarts: 0, queue_corruption_events: 0, max_active_running: 1, decision: "start" };
const root = () => mkdtempSync(join(tmpdir(), "p42-envelope-"));

test("UTC rollover preserves open challenges but resets daily spend", () => {
  const path = join(root(), "state.json");
  reserveChallengeSpend(path, { id: "a", problemId: "p", amountWei: DEFAULT_CHALLENGE_LIMITS.perChallengeWei, health: GREEN }, { now: Date.UTC(2026, 6, 10, 23, 59) });
  finalizeChallengeSpend(path, "a", { now: Date.UTC(2026, 6, 10, 23, 59) });
  reserveChallengeSpend(path, { id: "b", problemId: "p", amountWei: DEFAULT_CHALLENGE_LIMITS.perChallengeWei, health: GREEN }, { now: Date.UTC(2026, 6, 11, 0, 0) });
  const state = JSON.parse(readFileSync(path));
  assert.equal(state.utc_day, "2026-07-11");
  assert.ok(state.open.a);
  assert.ok(state.reservations.b);
  assert.equal(utcDay(Date.UTC(2026, 6, 11)), "2026-07-11");
});

test("caps are inclusive and reservations survive restart", () => {
  const path = join(root(), "state.json");
  reserveChallengeSpend(path, { id: "a", problemId: "p", amountWei: ethers.parseEther("0.05"), health: GREEN });
  assert.throws(() => reserveChallengeSpend(path, { id: "b", problemId: "p", amountWei: 1n, health: GREEN }), /one exact/);
  releaseChallengeReservation(path, "a");
  reserveChallengeSpend(path, { id: "b", problemId: "p", amountWei: ethers.parseEther("0.05"), health: GREEN });
  finalizeChallengeSpend(path, "b");
  reserveChallengeSpend(path, { id: "c", problemId: "p", amountWei: ethers.parseEther("0.05"), health: GREEN });
  finalizeChallengeSpend(path, "c");
  assert.throws(() => reserveChallengeSpend(path, { id: "d", problemId: "p", amountWei: 1n, health: GREEN }), /per-problem/);
  closeCanonicalChallenge(path, "b");
});

test("health admission is fail closed for red, wait, malformed, and green only", () => {
  assert.equal(runnerHealthAdmission(GREEN).allowed, true);
  assert.equal(runnerHealthAdmission({ ...GREEN, oom_kills: 1 }).allowed, false);
  assert.equal(runnerHealthAdmission({ ...GREEN, decision: "wait" }).allowed, false);
  assert.equal(runnerHealthAdmission({}).allowed, false);
});

test("concurrent processes admit only one pending exact challenge policy", () => {
  const path = join(root(), "state.json");
  const module = new URL("./challenge-envelope.mjs", import.meta.url).href;
  const script = `import {reserveChallengeSpend} from '${module}'; try { reserveChallengeSpend(process.argv[1], {id:process.argv[2],problemId:'p',amountWei:1n,health:{oom_kills:0,worker_restarts:0,queue_corruption_events:0,max_active_running:1,decision:'start'}}); } catch(e) { process.exit(3); }`;
  const results = ["a", "b", "c"].map((id) => { try { execFileSync(process.execPath, ["--input-type=module", "-e", script, path, id]); return 0; } catch (e) { return e.status; } });
  assert.equal(results.filter((status) => status === 0).length, 1);
  assert.equal(Object.keys(JSON.parse(readFileSync(path)).reservations).length, 1);
});

test("claim policy is exact and receipt reconciliation handles recovery and reorg", () => {
  const iface = new ethers.Interface(["function claimBond()"]);
  const policy = buildClaimBondPolicy({ challengeInterface: iface, challengeContract: `0x${"1".repeat(40)}`, chainId: 84532, claimant: `0x${"2".repeat(40)}`, expiresAt: 99 });
  assert.equal(policy.calldata, iface.encodeFunctionData("claimBond"));
  const journal = { schema_version: "p42-claim-bond-action/v1", status: "broadcast", expected_claimable_wei: "7" };
  const receipt = { status: 1, blockNumber: 10, blockHash: `0x${"a".repeat(64)}` };
  assert.equal(reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash: receipt.blockHash, latestBlockNumber: 12, confirmations: 3 }).recovered_wei, "7");
  assert.equal(reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash: `0x${"b".repeat(64)}`, latestBlockNumber: 12, confirmations: 3 }).status, "reorged");
  assert.equal(reconcileClaimLifecycle({ journal: { ...journal, status: "confirmed" }, claimableWei: 0 }).status, "confirmed");
});

test("claim recovery resumes from a restart-persisted journal without counting before finality", () => {
  const path = join(root(), "claim-bond.signed-tx.json");
  const journal = { schema_version: "p42-claim-bond-action/v1", status: "broadcast", expected_claimable_wei: "11" };
  writeFileSync(path, `${JSON.stringify(journal)}\n`);
  const restarted = JSON.parse(readFileSync(path));
  const receipt = { status: 1, blockNumber: 20, blockHash: `0x${"c".repeat(64)}` };
  assert.deepEqual(
    reconcileClaimLifecycle({ journal: restarted, receipt, canonicalBlockHash: receipt.blockHash, latestBlockNumber: 20, confirmations: 2 }),
    { status: "submitted", recovered_wei: "0" },
  );
  assert.deepEqual(
    reconcileClaimLifecycle({ journal: restarted, receipt, canonicalBlockHash: receipt.blockHash, latestBlockNumber: 21, confirmations: 2 }),
    { status: "confirmed", recovered_wei: "11" },
  );
});

test("replacement reveal gets a disjoint reservation identity", () => {
  const path = join(root(), "state.json");
  reserveChallengeSpend(path, { id: "reveal-a", problemId: "p", amountWei: 1n, health: GREEN });
  releaseChallengeReservation(path, "reveal-a");
  assert.equal(reserveChallengeSpend(path, { id: "reveal-b", problemId: "p", amountWei: 1n, health: GREEN }).reserved, true);
});

test("provisioning validator locks documented defaults and rehearsal evidence", () => {
  assert.doesNotThrow(() => validateProvisioningArtifact({ schema_version: "p42-challenge-provisioning/v1", per_challenge_wei: "50000000000000000", per_problem_day_wei: "100000000000000000", global_day_wei: "300000000000000000", max_canonical_open: 3, max_pending_provisioned: 1, rehearsal: { health_gate_verified: true, restart_recovery_verified: true } }));
});
