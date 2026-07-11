import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { AbiCoder, keccak256 } from "ethers";

import {
  buildGovernanceOperationJournal,
  readGovernanceOperationJournal,
  recordGovernanceObservation,
  reserveGovernanceOperationJournal,
} from "../scripts/governance-operation-journal.js";

const hex = (character, bytes) => `0x${character.repeat(bytes * 2)}`;
const OP_ID = keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [hex("2", 20), "0", "0x1234", hex("3", 32)]));
const FALLBACK_ID = keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [hex("2", 20), "0", "0x1234", hex("8", 32)]));

function plan(withFallback = false, label = "board/1.pool.setLedger") {
  return buildGovernanceOperationJournal({
    chainId: 84532,
    timelock: hex("1", 20),
    deploymentConfigHash: hex("a", 32),
    releaseBindingDigest: `sha256:${"b".repeat(64)}`,
    expectedTimelockCodeHash: hex("c", 32),
    operations: [{
      sequence: 1, label, operationClass: "standard",
      target: hex("2", 20), value: "0", data: "0x1234", salt: hex("3", 32), operationId: OP_ID,
      dependsOn: [], requiredConfirmations: "2", delaySeconds: "172800",
      transactionBuilder: { schedule: { to: hex("1", 20), value: "0", data: "0xabcd" } },
      overrideFallback: withFallback ? { operationId: FALLBACK_ID, salt: hex("8", 32), transactionBuilder: { schedule: { to: hex("1", 20), value: "0", data: "0xdcba" } } } : null,
    }],
  });
}

describe("governance operation journal", () => {
  it("durably reserves an immutable plan and accepts monotonic chain observations", async () => {
    const directory = mkdtempSync(join(tmpdir(), "p42-governance-journal-"));
    const path = join(directory, "journal.json");
    try {
      const expected = plan();
      const reserved = reserveGovernanceOperationJournal(path, expected);
      assert.equal(reserved.planDigest, expected.planDigest);
      assert.equal(readFileSync(path).at(-1), 10);
      assert.equal((await import("node:fs")).statSync(path).mode & 0o777, 0o600);
      const pending = await recordGovernanceObservation(path, expected.planDigest, 0, {
        operationId: OP_ID, state: "pending", scheduleTxHash: hex("5", 32),
      });
      assert.equal(pending.operations[0].state, "pending");
      const executed = await recordGovernanceObservation(path, expected.planDigest, 0, {
        operationId: OP_ID, state: "executed", scheduleTxHash: hex("5", 32),
        executeTxHash: hex("6", 32), blockNumber: 42, blockHash: hex("7", 32),
      });
      assert.equal(executed.operations[0].state, "executed");
      await assert.rejects(recordGovernanceObservation(path, expected.planDigest, 0, { operationId: OP_ID, state: "planned" }), /regress/);
      await assert.rejects(recordGovernanceObservation(path, expected.planDigest, 0, {
        operationId: OP_ID, state: "executed", scheduleTxHash: hex("5", 32),
        executeTxHash: hex("8", 32), blockNumber: 42, blockHash: hex("7", 32),
      }), /conflicts/);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("fails closed on plan substitution, permissive files, symlinks, and byte tampering", async () => {
    const directory = mkdtempSync(join(tmpdir(), "p42-governance-journal-"));
    const path = join(directory, "journal.json");
    try {
      const expected = plan(); reserveGovernanceOperationJournal(path, expected);
      const conflicting = plan(false, "substituted");
      assert.throws(() => reserveGovernanceOperationJournal(path, conflicting), /conflicts/);
      chmodSync(path, 0o644); assert.throws(() => readGovernanceOperationJournal(path), /private/); chmodSync(path, 0o600);
      const link = join(directory, "link.json"); symlinkSync(path, link); assert.throws(() => readGovernanceOperationJournal(link), /ELOOP|regular file/);
      const bytes = JSON.parse(readFileSync(path, "utf8")); bytes.operations[0].target = hex("9", 20); writeFileSync(path, `${JSON.stringify(bytes, null, 2)}\n`, { mode: 0o600 });
      assert.throws(() => readGovernanceOperationJournal(path), /plan digest|id does not match/);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("recovers a finalized deterministic override fallback without changing the primary plan identity", async () => {
    const directory = mkdtempSync(join(tmpdir(), "p42-governance-journal-"));
    const path = join(directory, "journal.json");
    try {
      const expected = plan(true); reserveGovernanceOperationJournal(path, expected);
      const recovered = await recordGovernanceObservation(path, expected.planDigest, 0, {
        operationId: OP_ID, observedOperationId: FALLBACK_ID, state: "executed",
        scheduleTxHash: hex("5", 32), executeTxHash: hex("6", 32), blockNumber: 42, blockHash: hex("7", 32),
      });
      assert.equal(recovered.operations[0].operationId, OP_ID);
      assert.equal(recovered.operations[0].observedOperationId, FALLBACK_ID);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});
