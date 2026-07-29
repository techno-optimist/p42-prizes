#!/usr/bin/env node

import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  assertActivationRpcAuthority,
  bindActivationRpcAuthority,
  constructActivationRpcProviders,
  loadActivationRpcOperatorRegistry,
  validateActivationRpcEndpointPair,
} from "./activation-rpc-endpoints.mjs";
import {
  ReorgDetectedError,
  buildMultiBoardCheckpoint,
  collectMultiBoardFinalizedReconciliation,
  instantiateBoardContracts,
  isMultiBoardManifest,
  loadContractArtifacts,
  stableStringify,
  validateManifestEvidence,
  writeFileAtomicSync,
} from "./indexer.mjs";
import { loadProductionValidationContext } from "./production-validation-context.mjs";
import { readStrictJsonFileSyncWithBytes } from "./strict-json.mjs";

export const CHAIN_MONITOR_SCHEMA = "p42-prizes/dual-rpc-chain-monitor/v1";
export const CHAIN_MONITOR_TEST_SCHEMA = "p42-prizes/dual-rpc-chain-monitor-test/v1";
const MANIFEST_LIMITS = Object.freeze({ maxBytes: 4 * 1024 * 1024, maxDepth: 64 });
const PROVIDER_CAPABILITIES = new WeakMap();

export class ChainMonitorDivergenceError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = "ChainMonitorDivergenceError";
    this.kind = kind;
  }
}

function canonical(value) {
  return JSON.parse(stableStringify(value));
}

function same(left, right) {
  return stableStringify(left) === stableStringify(right);
}

function profileSummary(authority, role) {
  const profile = authority[role];
  return {
    operatorId: profile.operatorId,
    endpointOrigin: profile.endpointOrigin,
    endpointProfileDigest: profile.endpointProfileDigest,
  };
}

function validateProfiles(authority) {
  const checked = assertActivationRpcAuthority(authority);
  validateActivationRpcEndpointPair(
    checked.primary.endpointOrigin,
    checked.secondary.endpointOrigin,
  );
  return checked;
}

async function constructChainMonitorProviders(
  registry,
  authority,
  primaryUrl,
  secondaryUrl,
  chainId,
  transports = {},
) {
  const checkedAuthority = validateProfiles(authority);
  const bundle = await constructActivationRpcProviders(
    registry, checkedAuthority, primaryUrl, secondaryUrl, chainId, transports,
  );
  const pairCapability = Object.freeze({});
  for (const role of ["primary", "secondary"]) {
    PROVIDER_CAPABILITIES.set(bundle[role], Object.freeze({
      pairCapability,
      role,
      registryDigest: checkedAuthority.registryDigest,
      profile: Object.freeze(profileSummary(checkedAuthority, role)),
      endpointOrigin: bundle.endpoints[role].origin,
    }));
  }
  return bundle;
}

export async function testOnlyConstructChainMonitorProviders(
  registry, authority, primaryUrl, secondaryUrl, chainId, transports,
) {
  return constructChainMonitorProviders(
    registry, authority, primaryUrl, secondaryUrl, chainId, transports,
  );
}

function validateBoundProviderCapabilities({ authority, primaryProvider, secondaryProvider }) {
  const primary = PROVIDER_CAPABILITIES.get(primaryProvider);
  const secondary = PROVIDER_CAPABILITIES.get(secondaryProvider);
  if (!primary || !secondary) {
    throw new Error("chain monitor providers are not privately capability-bound by this module");
  }
  if (primary.role !== "primary" || secondary.role !== "secondary") {
    throw new Error("chain monitor provider capabilities are swapped or role-invalid");
  }
  if (primary.pairCapability !== secondary.pairCapability) {
    throw new Error("chain monitor providers do not belong to the same construction pair");
  }
  for (const [role, capability] of [["primary", primary], ["secondary", secondary]]) {
    const expected = profileSummary(authority, role);
    if (capability.registryDigest !== authority.registryDigest
        || !same(capability.profile, expected)
        || capability.endpointOrigin !== expected.endpointOrigin) {
      throw new Error(`chain monitor ${role} provider capability does not match its authority profile`);
    }
  }
}

export function testOnlyValidateProviderCapabilities(args) {
  return validateBoundProviderCapabilities(args);
}

function requiredObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ChainMonitorDivergenceError("storage", `${label} is required`);
  }
  return value;
}

function requiredNonemptyObject(value, label) {
  const checked = requiredObject(value, label);
  if (Object.keys(checked).length === 0) throw new ChainMonitorDivergenceError("storage", `${label} must not be empty`);
  return checked;
}

function requiredField(object, key, label) {
  if (!Object.hasOwn(object, key) || object[key] === undefined || object[key] === null) {
    throw new ChainMonitorDivergenceError("storage", `${label}.${key} is required`);
  }
  return object[key];
}

function requireFields(object, keys, label) {
  for (const key of keys) requiredField(object, key, label);
  return object;
}

function bigint(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new ChainMonitorDivergenceError("storage", `${label} must be a canonical nonnegative decimal string`);
  }
  return BigInt(value);
}

function decimalize(value, label = "report") {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ChainMonitorDivergenceError("storage", `${label} contains a noncanonical integer`);
    }
    return String(value);
  }
  if (typeof value === "string" && /^-?[0-9]+$/.test(value)) {
    if (!/^(?:0|[1-9][0-9]*|-[1-9][0-9]*)$/.test(value)) {
      throw new ChainMonitorDivergenceError("storage", `${label} contains a noncanonical decimal string`);
    }
    return value;
  }
  if (Array.isArray(value)) return value.map((entry, index) => decimalize(entry, `${label}[${index}]`));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, decimalize(entry, `${label}.${key}`)]));
  }
  return value;
}

function requiredBoolean(object, key, label) {
  const value = requiredField(object, key, label);
  if (typeof value !== "boolean") throw new ChainMonitorDivergenceError("storage", `${label}.${key} must be boolean`);
  return value;
}

function uintField(object, key, label) {
  const value = requiredField(object, key, label);
  bigint(value, `${label}.${key}`);
  return value;
}

function nonnegativeCounter(value, label) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new ChainMonitorDivergenceError("storage", `${label} must be a nonnegative safe integer`);
    return value;
  }
  bigint(value, label);
  return value;
}

function uintMap(value, label) {
  const map = requiredObject(value, label);
  return Object.fromEntries(Object.entries(map).map(([key, entry]) => {
    bigint(entry, `${label}.${key}`);
    return [key, entry];
  }));
}

function requiredString(object, key, label) {
  const value = requiredField(object, key, label);
  if (typeof value !== "string" || value.length === 0) throw new ChainMonitorDivergenceError("storage", `${label}.${key} must be a nonempty string`);
  return value;
}

function canonicalAddress(value, label) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{40}$/.test(value)) {
    throw new ChainMonitorDivergenceError("storage", `${label} must be a canonical lowercase address`);
  }
  return value;
}

function projectStatePool(pool, label) {
  const amountKeys = [
    "problemId", "firstFundedAt", "accountedBalance", "totalFunded", "totalClaimed",
    "totalWinningsDonated", "totalGrossClaimed", "totalFeeAccrued", "totalFeePaid",
    "accruedFeeBalance", "totalSponsorRefunded", "totalRolloverPaid", "totalForcedEthRecovered",
    "totalResidualPaid",
  ];
  const output = {
    ledger: requiredString(pool, "ledger", label),
    submissionManager: requiredString(pool, "submissionManager", label),
    registry: requiredString(pool, "registry", label),
    acceptingFunds: requiredBoolean(pool, "acceptingFunds", label),
    everFunded: requiredBoolean(pool, "everFunded", label),
    sponsorshipOf: uintMap(requiredField(pool, "sponsorshipOf", label), `${label}.sponsorshipOf`),
  };
  for (const key of amountKeys) output[key] = uintField(pool, key, label);
  const fundings = requiredField(pool, "sponsorshipFundings", label);
  const donations = requiredField(pool, "winningsDonations", label);
  if (!Array.isArray(fundings) || !Array.isArray(donations)) throw new ChainMonitorDivergenceError("storage", `${label} funding arrays are required`);
  output.sponsorshipFundings = fundings.map((entry, index) => ({
    transactionHash: requiredString(entry, "transactionHash", `${label}.sponsorshipFundings[${index}]`),
    payer: requiredString(entry, "payer", `${label}.sponsorshipFundings[${index}]`),
    sponsor: requiredString(entry, "sponsor", `${label}.sponsorshipFundings[${index}]`),
    amount: uintField(entry, "amount", `${label}.sponsorshipFundings[${index}]`),
  }));
  output.winningsDonations = donations.map((entry, index) => ({
    transactionHash: requiredString(entry, "transactionHash", `${label}.winningsDonations[${index}]`),
    solver: requiredString(entry, "solver", `${label}.winningsDonations[${index}]`),
    destinationPool: requiredString(entry, "destinationPool", `${label}.winningsDonations[${index}]`),
    grossAmount: uintField(entry, "grossAmount", `${label}.winningsDonations[${index}]`),
    donatedAmount: uintField(entry, "donatedAmount", `${label}.winningsDonations[${index}]`),
    feeAmount: uintField(entry, "feeAmount", `${label}.winningsDonations[${index}]`),
  }));
  return output;
}

function projectStateLedger(ledger, label) {
  const output = {
    pausedNewActions: requiredBoolean(ledger, "pausedNewActions", label),
    creditRecorder: requiredString(ledger, "creditRecorder", label),
    closed: requiredBoolean(ledger, "closed", label),
    feeSwept: requiredBoolean(ledger, "feeSwept", label),
    residualSwept: requiredBoolean(ledger, "residualSwept", label),
    creditAtomsOf: uintMap(requiredField(ledger, "creditAtomsOf", label), `${label}.creditAtomsOf`),
    claimedWeiOf: uintMap(requiredField(ledger, "claimedWeiOf", label), `${label}.claimedWeiOf`),
  };
  for (const key of ["closedPoolBalance", "feeReserve", "closedAt", "claimDeadline", "totalCreditAtoms", "totalGrossClaimed", "totalFeeAccrued"]) {
    output[key] = uintField(ledger, key, label);
  }
  return output;
}

function projectRolloverVault(vault, label) {
  return {
    totalReceived: uintField(vault, "totalReceived", label),
    totalFuturePoolFunded: uintField(vault, "totalFuturePoolFunded", label),
    totalAllocated: uintField(vault, "totalAllocated", label),
    allocationOf: uintMap(requiredField(vault, "allocationOf", label), `${label}.allocationOf`),
    allocationCodehashOf: requiredObject(requiredField(vault, "allocationCodehashOf", label), `${label}.allocationCodehashOf`),
  };
}

function projectResolverBonds(value, label) {
  const bonds = requiredObject(value, label);
  return Object.fromEntries(Object.entries(bonds).map(([id, bond]) => [id, {
    amountWei: uintField(requiredObject(bond, `${label}.${id}`), "amountWei", `${label}.${id}`),
    releaseAt: uintField(bond, "releaseAt", `${label}.${id}`),
    slashProofHash: requiredString(bond, "slashProofHash", `${label}.${id}`),
  }]));
}

function projectPortalPool(pool, label) {
  const output = {};
  for (const key of ["totalFundedWei", "accountedBalanceWei", "totalClaimedWei", "totalWinningsDonatedWei", "refundableWei", "totalSponsorRefundedWei", "totalFeeAccruedWei", "totalFeePaidWei", "totalResidualPaidWei"]) {
    output[key] = uintField(pool, key, label);
  }
  for (const key of ["sponsors", "sponsorshipFundings", "winningsDonations"]) {
    const entries = requiredField(pool, key, label);
    if (!Array.isArray(entries)) throw new ChainMonitorDivergenceError("storage", `${label}.${key} must be an array`);
    output[key] = entries.map((entry, index) => {
      const entryLabel = `${label}.${key}[${index}]`;
      requiredObject(entry, entryLabel);
      if (key === "sponsors") return {
        sponsor: requiredString(entry, "sponsor", entryLabel),
        principalWei: uintField(entry, "principalWei", entryLabel),
      };
      if (key === "sponsorshipFundings") return {
        transactionHash: requiredString(entry, "transactionHash", entryLabel),
        payer: requiredString(entry, "payer", entryLabel),
        sponsor: requiredString(entry, "sponsor", entryLabel),
        amountWei: uintField(entry, "amountWei", entryLabel),
      };
      return {
        transactionHash: requiredString(entry, "transactionHash", entryLabel),
        solver: requiredString(entry, "solver", entryLabel),
        destinationPool: requiredString(entry, "destinationPool", entryLabel),
        grossAmountWei: uintField(entry, "grossAmountWei", entryLabel),
        donatedAmountWei: uintField(entry, "donatedAmountWei", entryLabel),
        feeAmountWei: uintField(entry, "feeAmountWei", entryLabel),
      };
    });
  }
  return output;
}

function projectPortalFunding(funding, label) {
  return {
    acceptingFunds: requiredBoolean(funding, "acceptingFunds", label),
    fundingArmed: requiredBoolean(funding, "fundingArmed", label),
    authorizationExpiresAt: uintField(funding, "authorizationExpiresAt", label),
    ledgerPausedNewActions: requiredBoolean(funding, "ledgerPausedNewActions", label),
    submissionsPausedNewActions: requiredBoolean(funding, "submissionsPausedNewActions", label),
    submissionsPausedAll: requiredBoolean(funding, "submissionsPausedAll", label),
    challengesPausedNewActions: requiredBoolean(funding, "challengesPausedNewActions", label),
  };
}

function projectLedgerClose(close, label) {
  const output = {
    closed: requiredBoolean(close, "closed", label),
    feeSwept: requiredBoolean(close, "feeSwept", label),
    residualSwept: requiredBoolean(close, "residualSwept", label),
  };
  for (const key of ["closedPoolBalanceWei", "feeReserveWei", "closedAt", "claimDeadline", "totalCreditAtoms", "totalGrossClaimedWei", "totalFeeAccruedWei"]) {
    output[key] = uintField(close, key, label);
  }
  return output;
}

function payoutRows(board, feeBps, anchorTimestamp) {
  const projection = requiredObject(board.portalProjection, `board ${board.problemId}.portalProjection`);
  const ledgerClose = requiredObject(projection.ledgerClose, `board ${board.problemId}.portalProjection.ledgerClose`);
  if (!Array.isArray(projection.solvers)) {
    throw new ChainMonitorDivergenceError("storage", `board ${board.problemId}.portalProjection.solvers is required`);
  }
  const deadline = bigint(requiredField(ledgerClose, "claimDeadline", "ledgerClose"), "claim deadline");
  const totalCredit = bigint(requiredField(ledgerClose, "totalCreditAtoms", "ledgerClose"), "ledger total credit");
  const closedPoolBalance = bigint(requiredField(ledgerClose, "closedPoolBalanceWei", "ledgerClose"), "closed pool balance");
  if (typeof ledgerClose.closed !== "boolean") throw new ChainMonitorDivergenceError("storage", "ledgerClose.closed is required");
  const stateLedger = requiredObject(requiredObject(board.state, `board ${board.problemId}.state`).ledger, `board ${board.problemId}.state.ledger`);
  if (bigint(requiredField(stateLedger, "totalCreditAtoms", "state ledger"), "state ledger total credit") !== totalCredit
      || bigint(requiredField(stateLedger, "closedPoolBalance", "state ledger"), "state closed pool balance") !== closedPoolBalance
      || bigint(requiredField(stateLedger, "claimDeadline", "state ledger"), "state claim deadline") !== deadline) {
    throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} payout close fields disagree with replay state`);
  }
  if (ledgerClose.closed && totalCredit > 0n && deadline === 0n) {
    throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} positive-credit close requires a nonzero claim deadline`);
  }
  const stateCredits = requiredObject(stateLedger.creditAtomsOf, "state ledger credits");
  const stateClaims = requiredObject(stateLedger.claimedWeiOf, "state ledger claims");
  const creditAddresses = Object.keys(stateCredits).map((address) => canonicalAddress(address, "state ledger credit address")).sort();
  const claimAddresses = Object.keys(stateClaims).map((address) => canonicalAddress(address, "state ledger claim address")).sort();
  const solverAddresses = projection.solvers.map((solver, index) => canonicalAddress(
    requiredField(requiredObject(solver, `solver payout ${index}`), "solver", `solver payout ${index}`),
    `solver payout ${index}.solver`,
  ));
  if (new Set(solverAddresses).size !== solverAddresses.length) {
    throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} solver payout addresses must be unique`);
  }
  const orderedSolverAddresses = [...solverAddresses].sort();
  if (!same(orderedSolverAddresses, creditAddresses) || !same(orderedSolverAddresses, claimAddresses)) {
    throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} solver payout, credit, and claim address key sets disagree`);
  }
  let observedCredit = 0n;
  let observedClaimed = 0n;
  const rows = projection.solvers.map((solver, index) => {
    const solverAddress = solverAddresses[index];
    const gross = bigint(requiredField(solver, "finalEntitlementWei", "solver payout"), "gross payout");
    const claimed = bigint(requiredField(solver, "claimedWei", "solver payout"), "claimed payout");
    observedClaimed += claimed;
    const credit = bigint(requiredField(solver, "creditAtoms", "solver payout"), "solver credit");
    observedCredit += credit;
    const expectedGross = ledgerClose.closed && totalCredit > 0n
      ? closedPoolBalance * credit / totalCredit
      : 0n;
    if (gross !== expectedGross) {
      throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} solver entitlement is inconsistent with the positive-credit close`);
    }
    if (claimed !== 0n && claimed !== gross) {
      throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} claimed gross violates all-or-nothing consumeClaim semantics`);
    }
    const stateCredit = bigint(
      requiredField(stateCredits, solverAddress, "state ledger credits"),
      "state solver credit",
    );
    const stateClaimed = bigint(
      requiredField(stateClaims, solverAddress, "state ledger claims"),
      "state claimed payout",
    );
    if (stateCredit !== credit) throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} solver credit disagrees with replay state`);
    if (stateClaimed !== claimed) throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} claimed payout disagrees with replay state`);
    const claimsOpen = ledgerClose.closed && totalCredit > 0n && deadline > 0n
      && anchorTimestamp <= deadline && claimed === 0n;
    const claimable = claimsOpen ? gross : 0n;
    const fee = claimable * BigInt(feeBps) / 10_000n;
    return {
      solver: solverAddress,
      finalEntitlementGrossWei: gross.toString(),
      claimedGrossWei: claimed.toString(),
      claimableGrossWei: claimable.toString(),
      claimFeeWei: fee.toString(),
      claimableNetWei: (claimable - fee).toString(),
      claimDeadline: deadline.toString(),
      claimDeadlinePassed: ledgerClose.closed === true && deadline !== 0n && anchorTimestamp > deadline,
    };
  });
  if (ledgerClose.closed && observedCredit !== totalCredit) {
    throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} solver credits do not sum to the closed total`);
  }
  const closeClaimed = bigint(requiredField(ledgerClose, "totalGrossClaimedWei", "ledgerClose"), "ledger close total claimed");
  const stateTotalClaimed = bigint(requiredField(stateLedger, "totalGrossClaimed", "state ledger"), "state ledger total claimed");
  if (observedClaimed !== closeClaimed || observedClaimed !== stateTotalClaimed) {
    throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} claimed gross total is inconsistent`);
  }
  if (ledgerClose.closed && totalCredit === 0n && rows.some((row) => row.finalEntitlementGrossWei !== "0"
      || row.claimedGrossWei !== "0" || row.claimableGrossWei !== "0")) {
    throw new ChainMonitorDivergenceError("storage", `board ${board.problemId} zero-credit close has a nonzero payout`);
  }
  return rows;
}

export function canonicalComparisonDomains(checkpoint, manifest) {
  requiredObject(checkpoint, "checkpoint");
  const aggregateReconstruction = requiredObject(checkpoint.reconstruction, "checkpoint.reconstruction");
  requireFields(aggregateReconstruction, ["ok", "complete", "checks"], "checkpoint.reconstruction");
  if (aggregateReconstruction.ok !== true || aggregateReconstruction.complete !== true
      || !Array.isArray(aggregateReconstruction.checks)) {
    throw new ChainMonitorDivergenceError("storage", "checkpoint reconstruction is not complete and verified");
  }
  validateChecks(aggregateReconstruction.checks, "checkpoint.reconstruction");
  const range = requiredObject(checkpoint.range, "checkpoint.range");
  const anchorTimestamp = bigint(String(requiredField(range, "toBlockTimestamp", "checkpoint.range")), "anchor timestamp");
  const feeBpsText = requiredField(requiredObject(manifest.parameters, "manifest.parameters"), "feeBps", "manifest.parameters");
  const feeBps = Number(bigint(feeBpsText, "manifest feeBps"));
  if (feeBps > 250) {
    throw new ChainMonitorDivergenceError("storage", "manifest feeBps is invalid");
  }
  if (!Array.isArray(manifest.problems) || !Array.isArray(checkpoint.boards)) {
    throw new ChainMonitorDivergenceError("storage", "manifest problems and checkpoint boards are required");
  }
  const expectedIds = manifest.problems.map((problem) => String(problem.problemId));
  const observedIds = checkpoint.boards.map((board) => String(board?.problemId));
  if (expectedIds.length === 0 || !same(expectedIds, observedIds) || new Set(observedIds).size !== observedIds.length) {
    throw new ChainMonitorDivergenceError("storage", "checkpoint board count or ordered problem IDs do not match the manifest");
  }
  const boards = checkpoint.boards.map((board) => {
    const state = requiredObject(board.state, `board ${board.problemId}.state`);
    const rawPool = requireFields(requiredNonemptyObject(state.pool, `board ${board.problemId}.state.pool`), [
      "ledger", "submissionManager", "registry", "problemId", "acceptingFunds", "everFunded",
      "firstFundedAt", "accountedBalance", "totalFunded", "totalClaimed", "totalWinningsDonated",
      "totalGrossClaimed", "totalFeeAccrued", "totalFeePaid", "accruedFeeBalance",
      "totalSponsorRefunded", "totalRolloverPaid", "totalForcedEthRecovered", "totalResidualPaid",
      "sponsorshipOf", "sponsorshipFundings", "winningsDonations",
    ], `board ${board.problemId}.state.pool`);
    const rawLedger = requireFields(requiredNonemptyObject(state.ledger, `board ${board.problemId}.state.ledger`), [
      "pausedNewActions", "creditRecorder", "closed", "closedPoolBalance", "feeReserve", "closedAt",
      "claimDeadline", "totalCreditAtoms", "creditAtomsOf", "claimedWeiOf", "totalGrossClaimed",
      "totalFeeAccrued", "feeSwept", "residualSwept",
    ], `board ${board.problemId}.state.ledger`);
    const rawRolloverVault = requireFields(requiredNonemptyObject(state.rolloverVault, `board ${board.problemId}.state.rolloverVault`), [
      "totalReceived", "totalFuturePoolFunded", "totalAllocated", "allocationOf", "allocationCodehashOf",
    ], `board ${board.problemId}.state.rolloverVault`);
    const projection = requiredObject(board.portalProjection, `board ${board.problemId}.portalProjection`);
    const rawPortalPool = requireFields(requiredNonemptyObject(projection.pool, `board ${board.problemId}.portalProjection.pool`), [
      "totalFundedWei", "accountedBalanceWei", "totalClaimedWei", "totalWinningsDonatedWei", "refundableWei",
      "totalSponsorRefundedWei", "totalFeeAccruedWei", "totalFeePaidWei", "totalResidualPaidWei",
      "sponsors", "sponsorshipFundings", "winningsDonations",
    ], `board ${board.problemId}.portalProjection.pool`);
    const rawPortalFunding = requireFields(requiredNonemptyObject(projection.funding, `board ${board.problemId}.portalProjection.funding`), [
      "acceptingFunds", "fundingArmed", "authorizationExpiresAt", "ledgerPausedNewActions",
      "submissionsPausedNewActions", "submissionsPausedAll", "challengesPausedNewActions",
    ], `board ${board.problemId}.portalProjection.funding`);
    const rawLedgerClose = requireFields(requiredNonemptyObject(projection.ledgerClose, `board ${board.problemId}.portalProjection.ledgerClose`), [
      "closed", "closedPoolBalanceWei", "feeReserveWei", "closedAt", "claimDeadline", "totalCreditAtoms",
      "totalGrossClaimedWei", "totalFeeAccruedWei", "feeSwept", "residualSwept",
    ], `board ${board.problemId}.portalProjection.ledgerClose`);
    const pool = projectStatePool(rawPool, `board ${board.problemId}.state.pool`);
    const ledger = projectStateLedger(rawLedger, `board ${board.problemId}.state.ledger`);
    const rolloverVault = projectRolloverVault(rawRolloverVault, `board ${board.problemId}.state.rolloverVault`);
    const portalPool = projectPortalPool(rawPortalPool, `board ${board.problemId}.portalProjection.pool`);
    const portalFunding = projectPortalFunding(rawPortalFunding, `board ${board.problemId}.portalProjection.funding`);
    const ledgerClose = projectLedgerClose(rawLedgerClose, `board ${board.problemId}.portalProjection.ledgerClose`);
    return ({
    problemId: board.problemId,
    frontier: requiredObject(projection.frontier, `board ${board.problemId}.frontier`),
    lifecycleChallenges: {
      submissions: requiredObject(state.submissions, `board ${board.problemId}.state.submissions`),
      challenges: requiredObject(state.challenges, `board ${board.problemId}.state.challenges`),
      challengeInstances: requiredObject(state.challengeInstances, `board ${board.problemId}.state.challengeInstances`),
      lifecycleCounts: requiredObject(requiredObject(board.events, `board ${board.problemId}.events`).counts, `board ${board.problemId}.events.counts`),
    },
    bonds: {
      submissionClaimableBondWei: uintMap(requiredField(state, "submissionClaimableBondWei", `board ${board.problemId}.state`), `board ${board.problemId}.state.submissionClaimableBondWei`),
      challengeClaimableBondWei: uintMap(requiredField(state, "challengeClaimableBondWei", `board ${board.problemId}.state`), `board ${board.problemId}.state.challengeClaimableBondWei`),
      resolverBonds: projectResolverBonds(requiredField(state, "resolverBonds", `board ${board.problemId}.state`), `board ${board.problemId}.state.resolverBonds`),
    },
    fundingAccounting: {
      fundingArmed: requiredBoolean(board.state, "fundingArmed", `board ${board.problemId}.state`),
      armedAt: uintField(board.state, "armedAt", `board ${board.problemId}.state`),
      fundingAuthorizationDigest: requiredString(board.state, "fundingAuthorizationDigest", `board ${board.problemId}.state`),
      authorizedFundingDigest: requiredString(board.state, "authorizedFundingDigest", `board ${board.problemId}.state`),
      fundingAuthorizationExpiresAt: uintField(board.state, "fundingAuthorizationExpiresAt", `board ${board.problemId}.state`),
      fundingAuthorizationNonce: uintField(board.state, "fundingAuthorizationNonce", `board ${board.problemId}.state`),
      pool,
      ledger,
      portalAccounting: {
        pool: portalPool,
        funding: portalFunding,
        ledgerClose,
      },
      rolloverVault,
    },
    credits: {
      totalCreditAtoms: ledger.totalCreditAtoms,
      creditAtomsOf: ledger.creditAtomsOf,
    },
    payouts: payoutRows(board, feeBps, anchorTimestamp),
  });
  });
  for (const board of checkpoint.boards) {
    requiredField(requiredObject(board.events, `board ${board.problemId}.events`), "digest", `board ${board.problemId}.events`);
    requiredField(board.events, "total", `board ${board.problemId}.events`);
    const onchain = requiredObject(board.onchain, `board ${board.problemId}.onchain`);
    if (Object.keys(onchain).length === 0) throw new ChainMonitorDivergenceError("storage", `board ${board.problemId}.onchain is empty`);
    const reconstruction = requiredObject(board.reconstruction, `board ${board.problemId}.reconstruction`);
    for (const key of ["ok", "complete", "checks"]) requiredField(reconstruction, key, `board ${board.problemId}.reconstruction`);
    if (reconstruction.ok !== true || reconstruction.complete !== true || !Array.isArray(reconstruction.checks)) {
      throw new ChainMonitorDivergenceError("storage", `board ${board.problemId}.reconstruction is not complete and verified`);
    }
    validateChecks(reconstruction.checks, `board ${board.problemId}.reconstruction`);
    nonnegativeCounter(board.events.total, `board ${board.problemId}.events.total`);
    for (const [name, count] of Object.entries(board.events.counts)) {
      nonnegativeCounter(count, `board ${board.problemId}.events.counts.${name}`);
    }
  }
  return decimalize(canonical({
    frontier: boards.map(({ problemId, frontier }) => ({ problemId, frontier })),
    lifecycleChallenges: boards.map(({ problemId, lifecycleChallenges }) => ({ problemId, ...lifecycleChallenges })),
    bonds: boards.map(({ problemId, bonds }) => ({ problemId, ...bonds })),
    fundingAccounting: boards.map(({ problemId, fundingAccounting }) => ({ problemId, ...fundingAccounting })),
    credits: boards.map(({ problemId, credits }) => ({ problemId, ...credits })),
    payouts: boards.map(({ problemId, payouts }) => ({ problemId, payouts })),
  }));
}

function reconstructionFailureKind(error) {
  if (error instanceof ReorgDetectedError) return "reorg";
  if (error instanceof ChainMonitorDivergenceError) return error.kind;
  const message = String(error?.message ?? error);
  if (["NETWORK_ERROR", "SERVER_ERROR", "TIMEOUT", "ECONNRESET", "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN"].includes(error?.code)
      || /\b(?:RPC|network|transport|timeout|fetch|socket|connection)\b/i.test(message)) return "transport";
  if (/reorg|anchor .*changed/i.test(message)) return "reorg";
  if (/runtime|code ?hash|bytecode|ABI|artifact|factory configuration|deployment evidence/i.test(message)) return "code";
  if (/log|event|scan|topic|decode/i.test(message)) return "log";
  return "storage";
}

function failedReport(authority, identity, anchor, divergences) {
  return decimalize(canonical({
    schema: CHAIN_MONITOR_SCHEMA,
    nonAuthoritative: true,
    authorityExclusions: ["portal", "checkpoint", "settlement"],
    ok: false,
    profiles: {
      primary: profileSummary(authority, "primary"),
      secondary: profileSummary(authority, "secondary"),
    },
    identity,
    anchor,
    comparedDomains: null,
    divergences,
  }));
}

function assertProductionManifestEnvelope(manifest, manifestDigest) {
  if (manifest?.schema !== "p42-prizes/deployment-manifest/v2" || manifest.releaseMode !== "production") {
    throw new Error("chain monitor accepts only a production v2 deployment manifest");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(manifestDigest ?? "")) {
    throw new Error("chain monitor requires the exact deployment manifest byte digest");
  }
  if (!Number.isSafeInteger(manifest.network?.chainId) || manifest.network.chainId < 1
      || !/^[0-9a-f]{40}$/.test(manifest.deploymentCommit ?? "")
      || !/^0x[0-9a-fA-F]{64}$/.test(manifest.deploymentConfigHash ?? "")
      || !/^sha256:[0-9a-f]{64}$/.test(manifest.releaseEvidence?.releaseBindingDigest ?? "")) {
    throw new Error("production deployment identity is incomplete or malformed");
  }
}

function productionMonitorIdentity(manifest, manifestDigest, binding) {
  assertProductionManifestEnvelope(manifest, manifestDigest);
  requiredObject(binding, "prepared manifest binding");
  if (Object.keys(binding).length === 0) throw new Error("prepared manifest binding must not be empty");
  return decimalize(canonical({
    chainId: String(manifest.network.chainId),
    manifestByteDigest: manifestDigest,
    deploymentCommit: manifest.deploymentCommit,
    deploymentConfigHash: manifest.deploymentConfigHash.toLowerCase(),
    releaseBindingDigest: manifest.releaseEvidence.releaseBindingDigest,
    preparedManifestBinding: binding,
  }));
}

async function rpcRead(label, operation) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ChainMonitorDivergenceError) throw error;
    throw new ChainMonitorDivergenceError("transport", `${label} RPC read failed: ${error.message}`);
  }
}

function blockNumber(block, label) {
  if (!block || !Number.isSafeInteger(block.number) || block.number < 0 || !/^0x[0-9a-fA-F]{64}$/.test(block.hash ?? "")) {
    throw new ChainMonitorDivergenceError("anchor", `${label} returned an invalid finalized block`);
  }
  return block.number;
}

function canonicalBlock(block, label, expectedNumber = null) {
  const number = blockNumber(block, label);
  if (expectedNumber !== null && number !== expectedNumber) {
    throw new ChainMonitorDivergenceError("anchor", `${label} returned block ${number}, expected ${expectedNumber}`);
  }
  if (!Number.isSafeInteger(block.timestamp) || block.timestamp < 0) {
    throw new ChainMonitorDivergenceError("anchor", `${label} returned an invalid timestamp`);
  }
  return block;
}

function sameBlockIdentity(left, right) {
  return left.number === right.number
    && left.hash.toLowerCase() === right.hash.toLowerCase()
    && left.timestamp === right.timestamp;
}

async function bindFinalizedTag(provider, label) {
  const tagged = canonicalBlock(
    await rpcRead(`${label} finalized tag`, () => provider.getBlock("finalized")),
    `${label} finalized tag`,
  );
  const exact = canonicalBlock(
    await rpcRead(`${label} finalized exact-height block`, () => provider.getBlock(tagged.number)),
    `${label} finalized exact-height block`,
    tagged.number,
  );
  if (!sameBlockIdentity(tagged, exact)) {
    throw new ChainMonitorDivergenceError("anchor", `${label} finalized tag is not bound to its exact-height block`);
  }
  return exact;
}

async function descendFinalizedAncestry(provider, finalized, commonNumber, maxLag, label) {
  const distance = finalized.number - commonNumber;
  if (distance < 0 || distance > maxLag) {
    throw new ChainMonitorDivergenceError("lag", `${label} finalized ancestry distance exceeds the configured bound`);
  }
  let current = finalized;
  while (current.number > commonNumber) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(current.parentHash ?? "")) {
      throw new ChainMonitorDivergenceError("anchor", `${label} finalized ancestry lacks a canonical parent hash`);
    }
    const parent = canonicalBlock(
      await rpcRead(`${label} finalized ancestor`, () => provider.getBlock(current.number - 1)),
      `${label} finalized ancestor`,
      current.number - 1,
    );
    if (parent.hash.toLowerCase() !== current.parentHash.toLowerCase()) {
      throw new ChainMonitorDivergenceError("anchor", `${label} finalized parent-hash ancestry diverges`);
    }
    current = parent;
  }
  return current;
}

async function proveFinalizedAnchor(provider, anchor, maxLag, label) {
  const finalized = await bindFinalizedTag(provider, label);
  const common = await descendFinalizedAncestry(provider, finalized, anchor.number, maxLag, label);
  if (common.hash.toLowerCase() !== anchor.hash || String(common.timestamp) !== anchor.timestamp) {
    throw new ChainMonitorDivergenceError("reorg", `${label} no longer finalizes the selected common anchor`);
  }
}

function validHead(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function checkpointMatchesAnchor(checkpoint, anchor) {
  return checkpoint?.range?.toBlock === anchor.number
    && String(checkpoint.range.toBlockHash).toLowerCase() === anchor.hash
    && String(checkpoint.range.toBlockTimestamp) === anchor.timestamp;
}

function validateChecks(checks, label) {
  if (!Array.isArray(checks) || checks.length === 0) {
    throw new ChainMonitorDivergenceError("storage", `${label} checks must be nonempty`);
  }
  if (checks.some((check) => !check || typeof check !== "object" || check.ok !== true)) {
    throw new ChainMonitorDivergenceError("storage", `${label} contains a missing or failed check`);
  }
}

function validateCheckpointReconstruction(checkpoint, binding, label) {
  requiredObject(checkpoint, label);
  if (!same(requiredObject(checkpoint.manifestBinding, `${label}.manifestBinding`), binding)) {
    throw new ChainMonitorDivergenceError("storage", `${label} manifest binding substitution`);
  }
  const aggregate = requiredObject(checkpoint.reconstruction, `${label}.reconstruction`);
  if (aggregate.ok !== true || aggregate.complete !== true) {
    throw new ChainMonitorDivergenceError("storage", `${label} aggregate reconstruction is not complete and verified`);
  }
  validateChecks(aggregate.checks, `${label}.reconstruction`);
  if (!Array.isArray(checkpoint.boards) || checkpoint.boards.length === 0) {
    throw new ChainMonitorDivergenceError("storage", `${label}.boards is required`);
  }
  for (const board of checkpoint.boards) {
    const reconstruction = requiredObject(board?.reconstruction, `${label}.board.reconstruction`);
    if (reconstruction.ok !== true || reconstruction.complete !== true) {
      throw new ChainMonitorDivergenceError("storage", `${label} board reconstruction is not complete and verified`);
    }
    validateChecks(reconstruction.checks, `${label}.board.${board.problemId}.reconstruction`);
  }
}

async function prepareProductionBinding({ manifest, primaryProvider, secondaryProvider }) {
  const context = await loadProductionValidationContext(manifest, {
    provider: primaryProvider,
    secondaryProvider,
  });
  return validateManifestEvidence(manifest, context);
}

async function reconstructChainAtBlockCore({
  provider,
  manifest,
  binding,
  toBlock,
  artifactsLoader = loadContractArtifacts,
  instantiate = instantiateBoardContracts,
  collect = collectMultiBoardFinalizedReconciliation,
  build = buildMultiBoardCheckpoint,
}) {
  if (!isMultiBoardManifest(manifest)) {
    throw new ChainMonitorDivergenceError("storage", "chain monitor requires the current v2 multi-board deployment manifest");
  }
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
    throw new ChainMonitorDivergenceError("storage", "chain reconstruction requires the shared prepared manifest binding");
  }
  const artifacts = artifactsLoader();
  const contractsByProblem = manifest.problems.map((problem) => ({
    problem,
    contracts: instantiate(provider, manifest, problem, artifacts),
  }));
  const { anchor, boards } = await collect({
    provider,
    contractsByProblem,
    artifacts,
    manifest,
    fromBlock: manifest.indexer.startBlock,
    toBlock,
    policy: manifest.indexer.finalityPolicy,
  });
  const checkpoint = build({
    binding,
    finalityPolicy: manifest.indexer.finalityPolicy,
    fromBlock: manifest.indexer.startBlock,
    toBlock,
    toBlockHash: anchor.hash,
    toBlockTimestamp: anchor.timestamp,
    boards,
  });
  if (!checkpoint.reconstruction.ok) {
    throw new ChainMonitorDivergenceError("storage", "complete chain reconstruction failed reconciliation");
  }
  return checkpoint;
}

async function reconstructChainAtBlock({ provider, manifest, binding, toBlock }) {
  return reconstructChainAtBlockCore({ provider, manifest, binding, toBlock });
}

export async function testOnlyReconstructChainAtBlock(
  { provider, manifest, binding, toBlock },
  { artifactsLoader, instantiate, collect, build },
) {
  if (![artifactsLoader, instantiate, collect, build].every((value) => typeof value === "function")) {
    throw new Error("test-only reconstruction requires all primitive adapters");
  }
  return reconstructChainAtBlockCore({
    provider, manifest, binding, toBlock, artifactsLoader, instantiate, collect, build,
  });
}

async function monitorDualRpcChainCore({
  manifest,
  manifestDigest,
  authority,
  primaryProvider,
  secondaryProvider,
  maxFinalizedLagBlocks = 2,
  validateProviders = validateBoundProviderCapabilities,
  prepareBinding = prepareProductionBinding,
  reconstruct = reconstructChainAtBlock,
}) {
  const checkedAuthority = validateProfiles(authority);
  if (!Number.isSafeInteger(maxFinalizedLagBlocks) || maxFinalizedLagBlocks < 0 || maxFinalizedLagBlocks > 128) {
    throw new Error("maxFinalizedLagBlocks must be an integer from 0 through 128");
  }
  if (!primaryProvider || !secondaryProvider || primaryProvider === secondaryProvider) {
    throw new Error("chain monitor requires two distinct provider objects");
  }
  await validateProviders({ authority: checkedAuthority, primaryProvider, secondaryProvider });
  const binding = await prepareBinding({ manifest, primaryProvider, secondaryProvider });
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
    throw new ChainMonitorDivergenceError("storage", "production validation did not return a manifest binding");
  }
  const identity = productionMonitorIdentity(manifest, manifestDigest, binding);

  let initial;
  try {
    const [primaryFinalized, secondaryFinalized, primaryHead, secondaryHead] = await Promise.all([
      bindFinalizedTag(primaryProvider, "primary"),
      bindFinalizedTag(secondaryProvider, "secondary"),
      rpcRead("primary head", () => primaryProvider.getBlockNumber()),
      rpcRead("secondary head", () => secondaryProvider.getBlockNumber()),
    ]);
    const primaryNumber = blockNumber(primaryFinalized, "primary");
    const secondaryNumber = blockNumber(secondaryFinalized, "secondary");
    if (!validHead(primaryHead) || !validHead(secondaryHead)) {
      throw new ChainMonitorDivergenceError("lag", "RPC returned an invalid head block number");
    }
    if (primaryNumber > primaryHead || secondaryNumber > secondaryHead) {
      throw new ChainMonitorDivergenceError("lag", "RPC finalized block is above its current head");
    }
    if (Math.abs(primaryNumber - secondaryNumber) > maxFinalizedLagBlocks
        || Math.abs(primaryHead - secondaryHead) > maxFinalizedLagBlocks) {
      return failedReport(checkedAuthority, identity, null, [{ kind: "lag", message: "RPC finalized or head lag exceeds the configured bound" }]);
    }
    const commonNumber = Math.min(primaryNumber, secondaryNumber);
    if (commonNumber < manifest.indexer.startBlock) {
      return failedReport(checkedAuthority, identity, null, [{ kind: "lag", message: "common finalized block predates the deployment start block" }]);
    }
    const [primaryAnchor, secondaryAnchor] = await Promise.all([
      descendFinalizedAncestry(
        primaryProvider, primaryFinalized, commonNumber, maxFinalizedLagBlocks, "primary",
      ),
      descendFinalizedAncestry(
        secondaryProvider, secondaryFinalized, commonNumber, maxFinalizedLagBlocks, "secondary",
      ),
    ]);
    if (primaryAnchor.hash.toLowerCase() !== secondaryAnchor.hash.toLowerCase()) {
      return failedReport(checkedAuthority, identity, null, [{ kind: "anchor", message: "RPCs disagree on the common finalized block hash" }]);
    }
    if (primaryAnchor.timestamp !== secondaryAnchor.timestamp) {
      return failedReport(checkedAuthority, identity, null, [{ kind: "anchor", message: "RPCs disagree on the common finalized block timestamp" }]);
    }
    initial = { number: commonNumber, hash: primaryAnchor.hash.toLowerCase(), timestamp: String(primaryAnchor.timestamp) };
  } catch (error) {
    return failedReport(checkedAuthority, identity, null, [{ kind: error.kind ?? "anchor", message: error.message }]);
  }

  let primary;
  let secondary;
  try {
    primary = await reconstruct({ provider: primaryProvider, manifest, binding, toBlock: initial.number, role: "primary" });
    secondary = await reconstruct({ provider: secondaryProvider, manifest, binding, toBlock: initial.number, role: "secondary" });
  } catch (error) {
    return failedReport(checkedAuthority, identity, initial, [{ kind: reconstructionFailureKind(error), message: error.message }]);
  }

  const divergences = [];
  try {
    validateCheckpointReconstruction(primary, binding, "primary checkpoint");
    validateCheckpointReconstruction(secondary, binding, "secondary checkpoint");
  } catch (error) {
    divergences.push({ kind: reconstructionFailureKind(error), message: error.message });
  }
  if (!checkpointMatchesAnchor(primary, initial) || !checkpointMatchesAnchor(secondary, initial)) {
    divergences.push({ kind: "anchor", message: "one or both reconstructions are not bound to the selected finalized anchor" });
  }
  if (!primary.reconstruction?.ok || !secondary.reconstruction?.ok) {
    divergences.push({ kind: "storage", message: "one or both complete reconstructions failed" });
  }
  if (!same(primary.events ?? primary.boards.map((board) => board.events), secondary.events ?? secondary.boards.map((board) => board.events))) {
    divergences.push({ kind: "log", message: "canonical reconstructed log evidence diverges" });
  }
  if (!same(primary.boards.map((board) => board.onchain), secondary.boards.map((board) => board.onchain))) {
    divergences.push({ kind: "storage", message: "canonical on-chain storage snapshots diverge" });
  }

  let primaryDomains;
  let secondaryDomains;
  try {
    primaryDomains = canonicalComparisonDomains(primary, manifest);
    secondaryDomains = canonicalComparisonDomains(secondary, manifest);
    for (const name of Object.keys(primaryDomains)) {
      if (!same(primaryDomains[name], secondaryDomains[name])) {
        divergences.push({ kind: name, message: `canonical ${name} data diverges` });
      }
    }
  } catch (error) {
    divergences.push({ kind: reconstructionFailureKind(error), message: error.message });
  }

  try {
    await Promise.all([
      proveFinalizedAnchor(primaryProvider, initial, maxFinalizedLagBlocks, "primary final recheck"),
      proveFinalizedAnchor(secondaryProvider, initial, maxFinalizedLagBlocks, "secondary final recheck"),
    ]);
  } catch (error) {
    const classified = reconstructionFailureKind(error);
    divergences.push({
      kind: classified === "transport" ? "transport" : "reorg",
      message: `failed to recheck the common finalized anchor: ${error.message}`,
    });
  }

  return decimalize(canonical({
    schema: CHAIN_MONITOR_SCHEMA,
    nonAuthoritative: true,
    authorityExclusions: ["portal", "checkpoint", "settlement"],
    ok: divergences.length === 0,
    profiles: {
      primary: profileSummary(checkedAuthority, "primary"),
      secondary: profileSummary(checkedAuthority, "secondary"),
    },
    identity,
    anchor: initial,
    comparedDomains: divergences.length === 0 ? primaryDomains : null,
    divergences,
  }));
}

function asTestOnlyReport(report) {
  const { ok, ...rest } = report;
  return canonical({
    ...rest,
    schema: CHAIN_MONITOR_TEST_SCHEMA,
    testOnly: true,
    productionPass: false,
    testPassed: ok,
    ...(ok ? {} : { ok: false }),
  });
}

export async function runTestOnlyChainMonitor({
  manifest,
  authority,
  primaryProvider,
  secondaryProvider,
  maxFinalizedLagBlocks = 2,
  adapters,
}) {
  if (!adapters || typeof adapters !== "object" || Array.isArray(adapters)
      || typeof adapters.validateProviders !== "function"
      || typeof adapters.prepareBinding !== "function"
      || typeof adapters.reconstruct !== "function") {
    throw new Error("test-only chain monitor requires explicit validation, binding, and reconstruction adapters");
  }
  const manifestBytes = Buffer.from(`${stableStringify(manifest)}\n`, "utf8");
  const manifestDigest = `sha256:${createHash("sha256").update(manifestBytes).digest("hex")}`;
  const report = await monitorDualRpcChainCore({
    manifest,
    manifestDigest,
    authority,
    primaryProvider,
    secondaryProvider,
    maxFinalizedLagBlocks,
    validateProviders: adapters.validateProviders,
    prepareBinding: adapters.prepareBinding,
    reconstruct: adapters.reconstruct,
  });
  return asTestOnlyReport(report);
}

export async function runProductionChainMonitor({
  manifestPath,
  rpcOperatorRegistryPath,
  rpcRegistryDigest,
  rpcRegistryTrustedRoot,
  primaryRpc,
  secondaryRpc,
  primaryRpcOperatorId,
  secondaryRpcOperatorId,
  maxFinalizedLagBlocks = 2,
}) {
  const manifestFile = readStrictJsonFileSyncWithBytes(resolve(manifestPath), MANIFEST_LIMITS);
  const manifest = manifestFile.value;
  const manifestDigest = `sha256:${createHash("sha256").update(manifestFile.bytes).digest("hex")}`;
  assertProductionManifestEnvelope(manifest, manifestDigest);
  const registry = loadActivationRpcOperatorRegistry(
    resolve(rpcOperatorRegistryPath), rpcRegistryDigest, resolve(rpcRegistryTrustedRoot),
  );
  const authority = bindActivationRpcAuthority(
    registry, primaryRpc, secondaryRpc, primaryRpcOperatorId, secondaryRpcOperatorId,
  );
  const bundle = await constructChainMonitorProviders(
    registry, authority, primaryRpc, secondaryRpc, manifest.network.chainId,
  );
  try {
    return await monitorDualRpcChainCore({
      manifest,
      manifestDigest,
      authority,
      primaryProvider: bundle.primary,
      secondaryProvider: bundle.secondary,
      maxFinalizedLagBlocks,
      validateProviders: validateBoundProviderCapabilities,
      prepareBinding: prepareProductionBinding,
      reconstruct: reconstructChainAtBlock,
    });
  } finally {
    await Promise.allSettled([bundle.primary.destroy(), bundle.secondary.destroy()]);
  }
}

const CLI_OPTIONS = Object.freeze(new Set([
  "manifest", "rpc-operator-registry", "rpc-registry-digest", "rpc-registry-trusted-root",
  "primary-rpc", "secondary-rpc", "primary-rpc-operator-id", "secondary-rpc-operator-id",
  "max-finalized-lag-blocks", "out",
]));

export function parseChainMonitorArgs(argv) {
  const values = {};
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i];
    if (!key?.startsWith("--") || argv[i + 1] === undefined) throw new Error(`invalid CLI argument ${key ?? ""}`);
    const name = key.slice(2);
    if (!CLI_OPTIONS.has(name)) throw new Error(`unknown CLI option --${name}`);
    if (Object.hasOwn(values, name)) throw new Error(`duplicate CLI option --${name}`);
    values[name] = argv[i + 1];
  }
  return values;
}

export async function cli(argv = process.argv) {
  const args = parseChainMonitorArgs(argv);
  const required = [
    "manifest", "rpc-operator-registry", "rpc-registry-digest", "rpc-registry-trusted-root",
    "primary-rpc", "secondary-rpc", "primary-rpc-operator-id", "secondary-rpc-operator-id", "out",
  ];
  for (const name of required) if (!args[name]) throw new Error(`required: --${name} <value>`);
  const report = await runProductionChainMonitor({
    manifestPath: args.manifest,
    rpcOperatorRegistryPath: args["rpc-operator-registry"],
    rpcRegistryDigest: args["rpc-registry-digest"],
    rpcRegistryTrustedRoot: args["rpc-registry-trusted-root"],
    primaryRpc: args["primary-rpc"],
    secondaryRpc: args["secondary-rpc"],
    primaryRpcOperatorId: args["primary-rpc-operator-id"],
    secondaryRpcOperatorId: args["secondary-rpc-operator-id"],
    maxFinalizedLagBlocks: Number(args["max-finalized-lag-blocks"] ?? 2),
  });
  writeFileAtomicSync(resolve(args.out), `${stableStringify(report)}\n`);
  console.log(`${report.ok ? "PASS" : "FAIL"}: ${resolve(args.out)}`);
  if (!report.ok) process.exitCode = 1;
  return report;
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  cli().catch((error) => {
    console.error(`FAILED: ${error.shortMessage ?? error.message}`);
    process.exitCode = 1;
  });
}
