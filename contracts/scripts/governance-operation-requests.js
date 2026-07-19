import { createHash } from "node:crypto";
import { Interface } from "ethers";

import { CANONICAL_CONTRACT_COUNT, assertCanonicalManifestTopology } from "../../agent/canonical-topology.mjs";
import { writeTrustedFileExclusiveSync } from "../../agent/strict-json.mjs";
import { assertDeploymentConfigHash } from "./deployment-ceremony-helper.js";
import {
  assertGovernanceOperationJournal,
  buildGovernanceOperationJournal,
  governanceOperationJournalFileDigest,
  governanceOperationJournalPath,
  reserveGovernanceOperationJournal,
} from "./governance-operation-journal.js";

export const GOVERNANCE_OPERATION_REQUESTS_SCHEMA = "p42-prizes/governance-operation-requests/v1";
export const CANONICAL_GOVERNANCE_OPERATION_COUNT = 110;
export const PREDEPLOYMENT_GOVERNANCE_OPERATION_COUNT = 40;

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const TIMELOCK = new Interface([
  "function schedule(address target,uint256 value,bytes data,bytes32 salt)",
  "function scheduleOverride(address target,uint256 value,bytes data,bytes32 salt)",
  "function confirm(bytes32 operationId)",
  "function execute(address target,uint256 value,bytes data,bytes32 salt)",
]);

function canonical(value) {
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function digest(value) {
  return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonical(actual) !== canonical(expected)) throw new Error(`${label} keys mismatch`);
  return value;
}

function canonicalAddress(value, label) {
  if (!ADDRESS_RE.test(value ?? "")) throw new Error(`${label} is not an address`);
  return value.toLowerCase();
}

function positiveDecimal(value, label) {
  const text = String(value);
  if (!/^[1-9][0-9]*$/.test(text)) throw new Error(`${label} is not a positive canonical integer`);
  return text;
}

export function governancePolicyView(governance) {
  return {
    signers: [...(governance?.signers ?? [])],
    threshold: String(governance?.threshold ?? ""),
    overrideThreshold: String(governance?.overrideThreshold ?? ""),
    delaySeconds: String(governance?.delaySeconds ?? ""),
    overrideDelaySeconds: String(governance?.overrideDelaySeconds ?? ""),
    guardian: governance?.guardian,
  };
}

export function governanceConfigHashFromManifest(manifest) {
  const digest = manifest?.releaseEvidence?.configDigest;
  if (!DIGEST_RE.test(digest ?? "")) throw new Error("production manifest is missing its immutable ceremony config digest");
  return `0x${digest.slice("sha256:".length)}`;
}

function assertTransaction(builder, expected, label) {
  exactObject(builder, ["to", "value", "data"], label);
  if (canonicalAddress(builder.to, `${label}.to`) !== canonicalAddress(expected.to, `${label}.to`)
      || builder.value !== "0" || String(builder.data).toLowerCase() !== expected.data.toLowerCase()) {
    throw new Error(`${label} does not match the exact timelock request`);
  }
}

function assertBuilder(builder, operation, timelock, scheduleMethod, label) {
  exactObject(builder, ["schedule", "confirm", "execute"], label);
  const args = [operation.target, 0n, operation.data, operation.salt];
  assertTransaction(builder.schedule, { to: timelock, data: TIMELOCK.encodeFunctionData(scheduleMethod, args) }, `${label}.schedule`);
  assertTransaction(builder.confirm, { to: timelock, data: TIMELOCK.encodeFunctionData("confirm", [operation.operationId]) }, `${label}.confirm`);
  assertTransaction(builder.execute, { to: timelock, data: TIMELOCK.encodeFunctionData("execute", args) }, `${label}.execute`);
  return builder;
}

export function assertProductionGovernancePolicy(governance) {
  governance = governancePolicyView(governance);
  if (!governance || !Array.isArray(governance.signers) || governance.signers.length !== 5) {
    throw new Error("production governance request bundle requires exactly five signers");
  }
  const signers = governance.signers.map((value, index) => canonicalAddress(value, `governance.signers[${index}]`));
  if (signers.includes(ZERO_ADDRESS) || new Set(signers).size !== signers.length) throw new Error("governance signers must be nonzero and distinct");
  const threshold = BigInt(positiveDecimal(governance.threshold, "governance.threshold"));
  const overrideThreshold = BigInt(positiveDecimal(governance.overrideThreshold, "governance.overrideThreshold"));
  if (threshold < 3n || threshold * 2n <= BigInt(signers.length) || threshold > BigInt(signers.length)) throw new Error("governance threshold is not a production strict majority");
  const requiredOverride = [threshold + 1n, (2n * BigInt(signers.length) + 2n) / 3n].reduce((a, b) => a > b ? a : b);
  if (overrideThreshold !== requiredOverride || overrideThreshold > BigInt(signers.length)) throw new Error("governance override threshold does not match policy");
  const guardian = canonicalAddress(governance.guardian, "governance.guardian");
  if (guardian === ZERO_ADDRESS || signers.includes(guardian)) throw new Error("governance guardian must be nonzero and distinct from every signer");
  const delaySeconds = BigInt(positiveDecimal(governance.delaySeconds, "governance.delaySeconds"));
  const overrideDelaySeconds = BigInt(positiveDecimal(governance.overrideDelaySeconds, "governance.overrideDelaySeconds"));
  if (delaySeconds < 172800n || overrideDelaySeconds < delaySeconds * 2n) throw new Error("production governance delays must be at least 48 hours with a doubled override delay");
  return { signers: governance.signers, threshold: threshold.toString(), overrideThreshold: overrideThreshold.toString(), delaySeconds: delaySeconds.toString(), overrideDelaySeconds: overrideDelaySeconds.toString(), guardian: governance.guardian };
}

function requestFor(operation, governance, timelock, index) {
  const label = `setupTransactions[${index}]`;
  if (operation.sequence !== index + 1) throw new Error(`${label} sequence drift`);
  if (!HASH_RE.test(operation.operationId ?? "") || !HASH_RE.test(operation.salt ?? "")) throw new Error(`${label} identity is malformed`);
  const expectedConfirmations = operation.operationClass === "override" ? governance.overrideThreshold : governance.threshold;
  const expectedDelay = operation.operationClass === "override" ? governance.overrideDelaySeconds : governance.delaySeconds;
  if (operation.requiredConfirmations !== expectedConfirmations || operation.delaySeconds !== expectedDelay) throw new Error(`${label} authorization policy drift`);
  assertBuilder(operation.transactionBuilder, operation, timelock, operation.operationClass === "override" ? "scheduleOverride" : "schedule", `${label}.transactionBuilder`);
  if (digest(operation.transactionBuilder) !== operation.transactionBuilderDigest) throw new Error(`${label} transaction builder digest mismatch`);
  if (operation.overrideFallback === null) {
    if (operation.fallbackOperationId !== null || operation.overrideFallbackDigest !== null) throw new Error(`${label} fallback journal mismatch`);
  } else {
    const fallback = operation.overrideFallback;
    if (operation.operationClass !== "standard" || fallback.operationId?.toLowerCase() !== operation.fallbackOperationId?.toLowerCase()
        || fallback.requiredConfirmations !== governance.overrideThreshold || fallback.delaySeconds !== governance.overrideDelaySeconds) throw new Error(`${label} override fallback policy drift`);
    assertBuilder(fallback.transactionBuilder, { ...operation, operationId: fallback.operationId, salt: fallback.salt }, timelock, "scheduleOverride", `${label}.overrideFallback.transactionBuilder`);
    if (digest(fallback) !== operation.overrideFallbackDigest) throw new Error(`${label} override fallback digest mismatch`);
  }
  return {
    sequence: operation.sequence, label: operation.label, operationClass: operation.operationClass,
    operationId: operation.operationId, dependsOn: operation.dependsOn,
    requiredConfirmations: operation.requiredConfirmations, delaySeconds: operation.delaySeconds,
    transactionBuilder: operation.transactionBuilder, transactionBuilderDigest: operation.transactionBuilderDigest,
    overrideFallback: operation.overrideFallback, overrideFallbackDigest: operation.overrideFallbackDigest,
  };
}

function assertManifestBinding(manifest, journal) {
  if (manifest?.schema !== "p42-prizes/deployment-manifest/v2" || manifest.releaseMode !== "production"
      || manifest.status !== "pending-governance-setup" || !COMMIT_RE.test(manifest.deploymentCommit ?? "")) throw new Error("governance request export requires a pending production deployment manifest");
  assertDeploymentConfigHash(manifest);
  assertCanonicalManifestTopology(manifest);
  if (!Array.isArray(manifest.setupTransactions) || manifest.setupTransactions.length !== CANONICAL_GOVERNANCE_OPERATION_COUNT
      || journal.operations.length !== CANONICAL_GOVERNANCE_OPERATION_COUNT) throw new Error("final governance request export requires exactly 110 operations");
  if (journal.chainId !== manifest.network?.chainId || journal.deploymentCommit !== manifest.deploymentCommit
      || canonicalAddress(journal.timelock, "journal.timelock") !== canonicalAddress(manifest.contracts.timelock.address, "manifest.timelock")
      || journal.deploymentConfigHash.toLowerCase() !== governanceConfigHashFromManifest(manifest).toLowerCase()
      || journal.releaseBindingDigest !== manifest.releaseEvidence?.releaseBindingDigest
      || journal.expectedTimelockCodeHash.toLowerCase() !== manifest.contracts.timelock.runtimeCodeHash?.toLowerCase()
      || canonical(journal.governance) !== canonical(governancePolicyView(manifest.governance))) throw new Error("governance journal does not bind the deployment manifest");
  for (const [index, operation] of manifest.setupTransactions.entries()) {
    const journalOperation = journal.operations[index];
    const fields = ["sequence", "label", "operationClass", "target", "value", "data", "salt", "operationId", "dependsOn", "requiredConfirmations", "delaySeconds", "transactionBuilder", "overrideFallback"];
    if (canonical(Object.fromEntries(fields.map((field) => [field, operation[field]]))) !== canonical(Object.fromEntries(fields.map((field) => [field, journalOperation[field]])))) throw new Error(`setupTransactions[${index}] does not match the durable governance journal`);
  }
}

export function buildGovernanceOperationRequestsFromJournal(journal, { manifest = null } = {}) {
  assertGovernanceOperationJournal(journal);
  if (![PREDEPLOYMENT_GOVERNANCE_OPERATION_COUNT, CANONICAL_GOVERNANCE_OPERATION_COUNT].includes(journal.operations.length)) throw new Error("governance request export requires exactly 40 or 110 operations");
  if (manifest !== null) assertManifestBinding(manifest, journal);
  if (journal.operations.length === CANONICAL_GOVERNANCE_OPERATION_COUNT && manifest === null) throw new Error("final 110-operation request export requires the deployment manifest");
  if (!DIGEST_RE.test(journal.releaseBindingDigest)) throw new Error("journal release binding is malformed");
  const governance = assertProductionGovernancePolicy(journal.governance);
  const body = {
    schema: GOVERNANCE_OPERATION_REQUESTS_SCHEMA,
    phase: journal.operations.length === PREDEPLOYMENT_GOVERNANCE_OPERATION_COUNT ? "predeployment-40" : "final-110",
    chainId: journal.chainId,
    timelock: journal.timelock,
    deploymentCommit: journal.deploymentCommit,
    deploymentConfigHash: journal.deploymentConfigHash,
    releaseBindingDigest: journal.releaseBindingDigest,
    journalPlanDigest: journal.planDigest,
    topologyContractCount: manifest === null ? null : CANONICAL_CONTRACT_COUNT,
    governance,
    operationCount: journal.operations.length,
    operations: journal.operations.map((operation, index) => requestFor(operation, governance, journal.timelock, index)),
    broadcastAuthorized: false,
  };
  return Object.freeze({ ...body, requestDigest: digest(body) });
}

export function buildGovernanceOperationRequests(manifest, journal) {
  return buildGovernanceOperationRequestsFromJournal(journal, { manifest });
}

export function reserveFinalGovernanceOperationJournal(manifestPath, manifest) {
  assertProductionGovernancePolicy(manifest?.governance);
  const path = governanceOperationJournalPath(manifestPath);
  const journal = buildGovernanceOperationJournal({
    chainId: manifest.network?.chainId,
    timelock: manifest.contracts?.timelock?.address,
    deploymentCommit: manifest.deploymentCommit,
    governance: governancePolicyView(manifest.governance),
    deploymentConfigHash: governanceConfigHashFromManifest(manifest),
    releaseBindingDigest: manifest.releaseEvidence?.releaseBindingDigest,
    expectedTimelockCodeHash: manifest.contracts?.timelock?.runtimeCodeHash,
    operations: manifest.setupTransactions,
  });
  buildGovernanceOperationRequests(manifest, journal);
  reserveGovernanceOperationJournal(path, journal);
  return { path, journal, sha256: governanceOperationJournalFileDigest(path) };
}

export function validateGovernanceOperationRequests(manifest, journal, requests) {
  const expected = buildGovernanceOperationRequests(manifest, journal);
  if (canonical(expected) !== canonical(requests)) throw new Error("governance operation request bundle does not match the manifest and journal");
  return requests;
}

export function writeGovernanceOperationRequests(path, trustedRoot, requests) {
  const bytes = Buffer.from(`${canonical(requests)}\n`);
  if (!writeTrustedFileExclusiveSync(path, trustedRoot, bytes)) throw new Error("refusing to overwrite governance operation request bundle");
  return { path, byteLength: bytes.length, sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}` };
}
