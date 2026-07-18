const PAUSE_TARGET_KEYS = Object.freeze(["ledger", "submissions", "challenges"]);
export const SETUP_OPERATION_FIELDS = Object.freeze([
  "sequence", "label", "operationClass", "target", "value", "data", "salt", "operationId",
  "dependsOn", "requiredConfirmations", "delaySeconds", "transactionBuilder", "overrideFallback",
]);

function canonical(value) {
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function selectedOperation(operation) {
  return Object.fromEntries(SETUP_OPERATION_FIELDS.map((field) => [field, operation[field]]));
}

export function assertExactSetupOperations(expected, proposed) {
  if (!Array.isArray(expected) || !Array.isArray(proposed) || expected.length !== proposed.length) {
    throw new Error(`setupTransactions must contain exactly ${expected?.length ?? 0} derived operations`);
  }
  for (const [index, operation] of expected.entries()) {
    if (canonical(selectedOperation(operation)) !== canonical(selectedOperation(proposed[index]))) {
      throw new Error(`setupTransactions[${index}] does not match the exact derived governance operation`);
    }
  }
  return proposed;
}

export function deriveBoardSetupOperations({
  ethers,
  chainId,
  timelockAddress,
  addresses,
  governance,
  parameters,
  problem,
  interfaces,
  problemId,
  labelPrefix = "",
  sequenceOffset = 0,
}) {
  const normalizedProblemId = BigInt(problemId);
  if (normalizedProblemId < 1n) throw new Error("problemId must be positive");
  if (!Number.isInteger(sequenceOffset) || sequenceOffset < 0) throw new Error("sequenceOffset must be a non-negative integer");
  const labelFor = (suffix) => labelPrefix ? `${labelPrefix}.${suffix}` : suffix;
  const labels = Object.freeze({
    poolSetLedger: labelFor("pool.setLedger"),
    ledgerSetCreditRecorder: labelFor("ledger.setCreditRecorder"),
    ledgerSetRolloverDestination: labelFor("ledger.setRolloverDestination"),
    poolSetSubmissionManager: labelFor("pool.setSubmissionManager"),
    submissionsSetChallengeManager: labelFor("submissions.setChallengeManager"),
    registryRegister: labelFor("registry.register"),
    poolSetRegistry: labelFor("pool.setRegistry"),
    registryFreeze: labelFor("registry.freeze"),
  });
  const registryConfig = {
    specHash: problem.specHash,
    verifierSourceHash: problem.verifierSourceHash,
    verifierImageHash: problem.verifierImageHash,
    admissionMatrixHash: problem.admissionMatrixHash,
    metadataURI: problem.metadataURI,
    pool: addresses.pool,
    ledger: addresses.ledger,
    submissionManager: addresses.submissions,
    challengeManager: addresses.challenges,
    challengeWindowSeconds: parameters.challengeWindowSeconds,
    minImprovementAtoms: problem.minImprovementAtoms,
  };
  const definitions = [
    [labels.poolSetLedger, "standard", addresses.pool, interfaces.pool.encodeFunctionData("setLedger", [addresses.ledger]), []],
    [labels.ledgerSetCreditRecorder, "standard", addresses.ledger, interfaces.ledger.encodeFunctionData("setCreditRecorder", [addresses.submissions]), []],
    [labels.poolSetSubmissionManager, "standard", addresses.pool, interfaces.pool.encodeFunctionData("setSubmissionManager", [addresses.submissions]), [labels.poolSetLedger]],
    [labels.submissionsSetChallengeManager, "standard", addresses.submissions, interfaces.submissions.encodeFunctionData("setChallengeManager", [addresses.challenges]), [labels.ledgerSetCreditRecorder]],
    [labels.registryRegister, "standard", addresses.registry, interfaces.registry.encodeFunctionData("registerExpected", [registryConfig, normalizedProblemId]), [labels.poolSetLedger, labels.ledgerSetCreditRecorder, labels.poolSetSubmissionManager, labels.submissionsSetChallengeManager]],
    [labels.poolSetRegistry, "standard", addresses.pool, interfaces.pool.encodeFunctionData("setRegistry", [addresses.registry, normalizedProblemId]), [labels.registryRegister]],
    [labels.ledgerSetRolloverDestination, "standard", addresses.ledger, interfaces.ledger.encodeFunctionData("setRolloverDestination", [addresses.rolloverVault]), [labels.poolSetRegistry]],
    [labels.registryFreeze, "standard", addresses.registry, interfaces.registry.encodeFunctionData("freeze", [normalizedProblemId]), [labels.registryRegister, labels.poolSetRegistry, labels.ledgerSetRolloverDestination]],
    ...PAUSE_TARGET_KEYS.map((key) => [labelFor(`timelock.setPauseTarget.${key}`), "override", timelockAddress, interfaces.timelock.encodeFunctionData("setPauseTarget", [addresses[key], true]), [labels.registryFreeze]]),
  ];
  const byLabel = new Map();
  return definitions.map(([label, operationClass, target, data, dependencies], index) => {
    const sequence = sequenceOffset + index + 1;
    const saltFor = (saltLabel) => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["string", "uint256", "uint256", "string", "address", "bytes32"],
      ["p42-prizes/governance-setup/v1", BigInt(chainId), BigInt(sequence), saltLabel, target, ethers.keccak256(data)],
    ));
    const idFor = (salt) => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "bytes", "bytes32"], [target, 0n, data, salt],
    ));
    const builderFor = (scheduleFunction, salt, operationId) => ({
      schedule: { to: timelockAddress, value: "0", data: interfaces.timelock.encodeFunctionData(scheduleFunction, [target, 0n, data, salt]) },
      confirm: { to: timelockAddress, value: "0", data: interfaces.timelock.encodeFunctionData("confirm", [operationId]) },
      execute: { to: timelockAddress, value: "0", data: interfaces.timelock.encodeFunctionData("execute", [target, 0n, data, salt]) },
    });
    const salt = saltFor(label);
    const operationId = idFor(salt);
    const fallbackSalt = operationClass === "standard" ? saltFor(`${label}.override-fallback`) : null;
    const fallbackId = fallbackSalt ? idFor(fallbackSalt) : null;
    const operation = {
      sequence, label, operationClass, status: "pending", target, value: "0", data, salt, operationId,
      dependsOn: dependencies.map((dependency) => byLabel.get(dependency).operationId),
      requiredConfirmations: String(operationClass === "override" ? governance.overrideThreshold : governance.threshold),
      delaySeconds: String(operationClass === "override" ? governance.overrideDelaySeconds : governance.delaySeconds),
      transactionBuilder: builderFor(operationClass === "override" ? "scheduleOverride" : "schedule", salt, operationId),
      overrideFallback: fallbackSalt ? {
        operationId: fallbackId,
        salt: fallbackSalt,
        requiredConfirmations: String(governance.overrideThreshold),
        delaySeconds: String(governance.overrideDelaySeconds),
        transactionBuilder: builderFor("scheduleOverride", fallbackSalt, fallbackId),
      } : null,
      executedOperationId: null,
      executedOperationClass: null,
      txHash: null,
      blockNumber: null,
    };
    byLabel.set(label, operation);
    return operation;
  });
}
