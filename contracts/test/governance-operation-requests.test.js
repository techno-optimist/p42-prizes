import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { AbiCoder, Interface, keccak256 } from "ethers";

import { CANONICAL_BOARD_CONTRACTS, CANONICAL_SHARED_CONTRACTS } from "p42-agent/canonical-topology.mjs";
import { bindDeploymentConfigHash } from "../scripts/deployment-ceremony-helper.js";
import { buildGovernanceOperationJournal, reserveGovernanceOperationJournal } from "../scripts/governance-operation-journal.js";
import {
  buildGovernanceOperationRequests,
  buildGovernanceOperationRequestsFromJournal,
  assertProductionGovernancePolicy,
  governanceConfigHashFromManifest,
  governancePolicyView,
  reserveFinalGovernanceOperationJournal,
  validateGovernanceOperationRequests,
  writeGovernanceOperationRequests,
} from "../scripts/governance-operation-requests.js";

const TIMELOCK = new Interface([
  "function schedule(address target,uint256 value,bytes data,bytes32 salt)",
  "function scheduleOverride(address target,uint256 value,bytes data,bytes32 salt)",
  "function confirm(bytes32 operationId)",
  "function execute(address target,uint256 value,bytes data,bytes32 salt)",
]);
const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
const hash = (value) => `0x${value.toString(16).padStart(64, "0")}`;
const sha = (value) => `sha256:${value.toString(16).padStart(64, "0")}`;

function builder(timelock, operation, method) {
  const args = [operation.target, 0n, operation.data, operation.salt];
  return {
    schedule: { to: timelock, value: "0", data: TIMELOCK.encodeFunctionData(method, args) },
    confirm: { to: timelock, value: "0", data: TIMELOCK.encodeFunctionData("confirm", [operation.operationId]) },
    execute: { to: timelock, value: "0", data: TIMELOCK.encodeFunctionData("execute", args) },
  };
}

function operation(index, timelock) {
  const sequence = index + 1;
  const operationClass = index < 80 ? "standard" : "override";
  const target = address(1000 + index);
  const data = `0x${sequence.toString(16).padStart(8, "0")}`;
  const salt = hash(2000 + index);
  const operationId = keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [target, 0n, data, salt]));
  const value = {
    sequence, label: `operation-${sequence}`, operationClass, status: "pending", target, value: "0", data, salt, operationId,
    dependsOn: index === 0 ? [] : [hash(9000 + index)],
    requiredConfirmations: operationClass === "standard" ? "3" : "4",
    delaySeconds: operationClass === "standard" ? "172800" : "345600",
    transactionBuilder: null, overrideFallback: null,
    executedOperationId: null, executedOperationClass: null, txHash: null, blockNumber: null,
  };
  value.transactionBuilder = builder(timelock, value, operationClass === "standard" ? "schedule" : "scheduleOverride");
  if (operationClass === "standard") {
    const fallbackSalt = hash(4000 + index);
    const fallbackId = keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [target, 0n, data, fallbackSalt]));
    value.overrideFallback = { operationId: fallbackId, salt: fallbackSalt, requiredConfirmations: "4", delaySeconds: "345600", transactionBuilder: null };
    value.overrideFallback.transactionBuilder = builder(timelock, { ...value, operationId: fallbackId, salt: fallbackSalt }, "scheduleOverride");
  }
  return value;
}

function fixture() {
  const timelock = address(1);
  const shared = Object.fromEntries(CANONICAL_SHARED_CONTRACTS.map(({ key, name }, index) => [key, { name, address: address(index + 1), runtimeCodeHash: hash(index + 1) }]));
  const problems = Array.from({ length: 10 }, (_, board) => ({
    problemId: String(board + 1),
    contracts: Object.fromEntries(CANONICAL_BOARD_CONTRACTS.map(({ key, name }, offset) => [key, {
      name, address: address(100 + board * 4 + offset), runtimeCodeHash: hash(100 + board * 4 + offset),
    }])),
  }));
  const setupTransactions = Array.from({ length: 110 }, (_, index) => operation(index, timelock));
  // Dependencies only need to be earlier journal IDs; replace the synthetic placeholders.
  setupTransactions.forEach((entry, index) => { entry.dependsOn = index === 0 ? [] : [setupTransactions[index - 1].operationId]; });
  const manifest = {
    schema: "p42-prizes/deployment-manifest/v2", releaseMode: "production", status: "pending-governance-setup",
    deploymentCommit: "a".repeat(40), deploymentConfigHash: hash(7000), network: { chainId: 84532 },
    contracts: shared, problems,
    governance: { ownershipModel: "P42MultisigTimelock", timelock, signers: [address(50), address(51), address(52), address(54), address(55)], threshold: "3", overrideThreshold: "4", delaySeconds: "172800", overrideDelaySeconds: "345600", operationGracePeriodSeconds: "604800", guardian: address(53) },
    releaseEvidence: { configDigest: sha(7001), releaseBindingDigest: sha(8000) }, setupTransactions,
  };
  const boundManifest = bindDeploymentConfigHash(manifest);
  const journal = buildGovernanceOperationJournal({
    chainId: 84532, timelock, deploymentConfigHash: governanceConfigHashFromManifest(boundManifest),
    deploymentCommit: boundManifest.deploymentCommit, governance: governancePolicyView(boundManifest.governance),
    releaseBindingDigest: boundManifest.releaseEvidence.releaseBindingDigest,
    expectedTimelockCodeHash: boundManifest.contracts.timelock.runtimeCodeHash, operations: setupTransactions,
  });
  return { manifest: boundManifest, journal };
}

describe("governance operation request export", () => {
  it("enforces the production governance floor before ceremony requests exist", () => {
    const { manifest } = fixture();
    assert.equal(assertProductionGovernancePolicy(manifest.governance).threshold, "3");
    const short = structuredClone(manifest.governance); short.signers.pop();
    assert.throws(() => assertProductionGovernancePolicy(short), /exactly five signers/);
    const guardian = structuredClone(manifest.governance); guardian.guardian = guardian.signers[0];
    assert.throws(() => assertProductionGovernancePolicy(guardian), /guardian must be nonzero and distinct/);
    const zeroSigner = structuredClone(manifest.governance); zeroSigner.signers[0] = address(0);
    assert.throws(() => assertProductionGovernancePolicy(zeroSigner), /nonzero and distinct/);
    const zeroGuardian = structuredClone(manifest.governance); zeroGuardian.guardian = address(0);
    assert.throws(() => assertProductionGovernancePolicy(zeroGuardian), /nonzero and distinct/);
    const fast = structuredClone(manifest.governance); fast.delaySeconds = "172799";
    assert.throws(() => assertProductionGovernancePolicy(fast), /at least 48 hours/);
  });
  it("retains and verifies every exact 47-contract ceremony request without authorizing broadcast", () => {
    const { manifest, journal } = fixture();
    const requests = buildGovernanceOperationRequests(manifest, journal);
    assert.equal(requests.operationCount, 110);
    assert.equal(requests.topologyContractCount, 47);
    assert.equal(requests.broadcastAuthorized, false);
    assert.equal(requests.operations[0].transactionBuilder.schedule.data, manifest.setupTransactions[0].transactionBuilder.schedule.data);
    assert.equal(requests.operations[0].overrideFallback.transactionBuilder.execute.data, manifest.setupTransactions[0].overrideFallback.transactionBuilder.execute.data);
    assert.equal(validateGovernanceOperationRequests(manifest, journal, requests), requests);
  });

  it("exports the blocking 40-operation phase from its journal before a manifest exists", () => {
    const { manifest } = fixture();
    const operations = manifest.setupTransactions.slice(0, 40);
    const journal = buildGovernanceOperationJournal({
      chainId: manifest.network.chainId, timelock: manifest.contracts.timelock.address,
      deploymentCommit: manifest.deploymentCommit, governance: governancePolicyView(manifest.governance),
      deploymentConfigHash: manifest.deploymentConfigHash,
      releaseBindingDigest: manifest.releaseEvidence.releaseBindingDigest,
      expectedTimelockCodeHash: manifest.contracts.timelock.runtimeCodeHash, operations,
    });
    const requests = buildGovernanceOperationRequestsFromJournal(journal);
    assert.equal(requests.phase, "predeployment-40");
    assert.equal(requests.operationCount, 40);
    assert.equal(requests.topologyContractCount, null);
    assert.equal(requests.operations[39].transactionBuilder, journal.operations[39].transactionBuilder);
  });

  it("rejects calldata, journal, signer-policy, and operation-count substitution", () => {
    const { manifest, journal } = fixture();
    const calldata = structuredClone(manifest); calldata.setupTransactions[0].transactionBuilder.schedule.data = "0x1234";
    assert.throws(() => buildGovernanceOperationRequests(calldata, journal), /deploymentConfigHash mismatch|does not match the durable governance journal/);
    const binding = structuredClone(journal); binding.releaseBindingDigest = sha(9000);
    assert.throws(() => buildGovernanceOperationRequests(manifest, binding), /plan digest|does not bind/);
    const signers = structuredClone(manifest); signers.governance.signers.pop();
    assert.throws(() => buildGovernanceOperationRequests(signers, journal), /deploymentConfigHash mismatch|does not bind|exactly five signers/);
    const short = structuredClone(manifest); short.setupTransactions.pop();
    assert.throws(() => buildGovernanceOperationRequests(short, journal), /deploymentConfigHash mismatch|exactly 110/);
    const missingConfig = structuredClone(manifest); delete missingConfig.releaseEvidence.configDigest;
    assert.throws(() => buildGovernanceOperationRequests(missingConfig, journal), /deploymentConfigHash mismatch|immutable ceremony config digest/);
    const minedEvidence = structuredClone(manifest); minedEvidence.contracts.registry.runtimeCodeHash = hash(9999);
    assert.throws(() => buildGovernanceOperationRequests(minedEvidence, journal), /deploymentConfigHash mismatch/);
  });

  it("writes one private canonical artifact and refuses overwrite", async () => {
    const root = mkdtempSync(join(tmpdir(), "p42-governance-requests-"));
    const path = join(root, "requests.json");
    try {
      const { manifest, journal } = fixture();
      const requests = buildGovernanceOperationRequests(manifest, journal);
      const written = writeGovernanceOperationRequests(path, root, requests);
      assert.match(written.sha256, /^sha256:[0-9a-f]{64}$/);
      assert.equal(statSync(path).mode & 0o777, 0o600);
      assert.equal(JSON.parse(readFileSync(path, "utf8")).requestDigest, requests.requestDigest);
      assert.throws(() => writeGovernanceOperationRequests(path, root, requests), /refusing to overwrite/);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("reserves the final 110 journal from the exact production manifest shape before continuation", async () => {
    const root = mkdtempSync(join(tmpdir(), "p42-final-governance-journal-"));
    try {
      const { manifest, journal } = fixture();
      reserveGovernanceOperationJournal(join(root, "p42-prizes.json.governance-operations.json"), journal);
      const reserved = reserveFinalGovernanceOperationJournal(join(root, "p42-prizes.json"), manifest);
      assert.equal(reserved.journal.operations.length, 110);
      assert.equal(reserved.journal.governance.signers.length, 5);
      assert.match(reserved.sha256, /^sha256:[0-9a-f]{64}$/);
      assert.equal(buildGovernanceOperationRequests(manifest, reserved.journal).phase, "final-110");
      const substituted = structuredClone(manifest);
      substituted.setupTransactions[0].data = "0x1234";
      assert.throws(
        () => reserveFinalGovernanceOperationJournal(join(root, "p42-prizes.json"), substituted),
        /operation id does not match payload|plan substitution|does not match/,
      );
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("runs as an offline no-key CLI and fails closed on output collision", async () => {
    const root = mkdtempSync(join(tmpdir(), "p42-governance-cli-"));
    const journalPath = join(root, "journal.json");
    const outputPath = join(root, "requests.json");
    try {
      const { manifest } = fixture();
      const journal = buildGovernanceOperationJournal({
        chainId: manifest.network.chainId, timelock: manifest.contracts.timelock.address,
        deploymentCommit: manifest.deploymentCommit, governance: governancePolicyView(manifest.governance),
        deploymentConfigHash: manifest.deploymentConfigHash,
        releaseBindingDigest: manifest.releaseEvidence.releaseBindingDigest,
        expectedTimelockCodeHash: manifest.contracts.timelock.runtimeCodeHash,
        operations: manifest.setupTransactions.slice(0, 40),
      });
      reserveGovernanceOperationJournal(journalPath, journal);
      const script = new URL("../scripts/export-governance-operation-requests.js", import.meta.url);
      const env = {
        PATH: process.env.PATH,
        P42_RUNTIME_PYTHON: process.env.P42_RUNTIME_PYTHON ?? "python3",
        P42_GOVERNANCE_OPERATION_JOURNAL: journalPath,
        P42_GOVERNANCE_OPERATION_JOURNAL_SHA256: `sha256:${createHash("sha256").update(readFileSync(journalPath)).digest("hex")}`,
        P42_GOVERNANCE_REQUEST_OUTPUT_ROOT: root,
        P42_GOVERNANCE_REQUEST_OUTPUT: outputPath,
      };
      assert.throws(() => execFileSync(process.execPath, [script.pathname], {
        cwd: dirname(script.pathname), env: { ...env, P42_GOVERNANCE_OPERATION_JOURNAL_SHA256: sha(0) }, encoding: "utf8", stdio: "pipe",
      }), /exact-bytes digest mismatch/);
      const stdout = execFileSync(process.execPath, [script.pathname], { cwd: dirname(script.pathname), env, encoding: "utf8" });
      const result = JSON.parse(stdout);
      assert.equal(result.operationCount, 40);
      assert.equal(JSON.parse(readFileSync(outputPath, "utf8")).broadcastAuthorized, false);
      assert.throws(() => execFileSync(process.execPath, [script.pathname], { cwd: dirname(script.pathname), env, encoding: "utf8", stdio: "pipe" }), /refusing to overwrite/);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
