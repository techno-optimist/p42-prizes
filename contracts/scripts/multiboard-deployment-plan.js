import { basename, dirname, join, resolve } from "node:path";

import { assertCanonicalDeploymentPlan } from "../../agent/canonical-topology.mjs";
import {
  boardCeremonyConfig,
  challengeManagerEffectiveSalt,
  constructorArgsFor,
  constructorArgsHash,
} from "./deployment-ceremony-helper.js";
import {
  buildGovernanceOperationJournal,
  observeGovernanceOperation,
  recordGovernanceObservation,
  reserveGovernanceOperationJournal,
} from "./governance-operation-journal.js";

export const MULTIBOARD_CHAIN_ID = 84532n;
export const MULTIBOARD_PRECHALLENGE_DEPLOYMENT_COUNT = 36;

export const MULTIBOARD_CONTRACT_NAMES = Object.freeze({
  timelock: "P42MultisigTimelock",
  registry: "P42ProblemRegistry",
  rolloverVault: "P42RolloverVault",
  submissionManagerFactory: "P42SubmissionManagerFactory",
  challengeManagerFactory: "P42ChallengeManagerFactory",
  objectiveVerifier: "P42SP1VerifierGateway",
  resolverQuorum: "P42ResolverQuorum",
});

export const MULTIBOARD_BOARD_CONTRACT_NAMES = Object.freeze({
  pool: "P42BountyPool",
  ledger: "P42PayoutLedger",
  submissions: "P42SubmissionManager",
  challenges: "P42ChallengeManager",
});

export function objectivePackageHash(ethers, chainId, registryAddress, problem) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ["string", "uint256", "address", "uint256", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      "P42_OBJECTIVE_PACKAGE_V2", BigInt(chainId), registryAddress, BigInt(problem.problemId),
      problem.specHash, problem.verifierSourceHash, problem.verifierImageHash,
      problem.admissionMatrixHash, problem.objectiveGuestElfSha256, problem.objectiveProgramVKey,
    ],
  ));
}

function factoryConfigurationHash(ethers, factoryInterface, method, parameters, prefixHash = null) {
  const inputs = factoryInterface.getFunction(method).inputs;
  const tupleInput = inputs.find((input) => input.baseType === "tuple");
  if (!tupleInput) throw new Error(`${method} does not expose a configuration tuple`);
  const tupleType = tupleInput.format("sighash");
  const tupleValues = Array.isArray(parameters)
    ? parameters
    : tupleInput.components.map(({ name }) => parameters[name]);
  const types = prefixHash === null ? [tupleType] : ["bytes32", tupleType];
  const values = prefixHash === null ? [tupleValues] : [prefixHash, tupleValues];
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(types, values));
}

export function assertMultiBoardExecutionDependencyOrder(definitions, config) {
  const expected = [
    "timelock", "registry", "rolloverVault", "submissionManagerFactory", "challengeManagerFactory", "objectiveVerifier",
    ...config.problems.flatMap((problem) => [`board-${problem.problemId}-pool`, `board-${problem.problemId}-ledger`]),
    ...config.problems.map((problem) => `board-${problem.problemId}-submissions`),
    ...config.problems.map((problem) => `board-${problem.problemId}-challenges`),
    "resolverQuorum",
  ];
  const actual = definitions.map(({ id }) => id);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("multi-board executable dependency order drift");
  }
}

export async function buildCanonicalMultiBoardDeploymentDefinitions({
  ethers,
  config,
  chainId = MULTIBOARD_CHAIN_ID,
  objectiveVerifierRuntimeCodehash,
  boardSetDigest,
  releaseBindingDigest,
}) {
  for (const [label, value] of [["boardSetDigest", boardSetDigest], ["releaseBindingDigest", releaseBindingDigest]]) {
    if (!ethers.isHexString(value, 32) || value === ethers.ZeroHash) {
      throw new Error(`${label} must be a nonzero bytes32 value`);
    }
  }
  const directRoots = [
    "timelock", "registry", "rolloverVault", "submissionManagerFactory", "challengeManagerFactory", "objectiveVerifier",
  ].map((key) => ({
    id: key,
    addressKey: key,
    name: MULTIBOARD_CONTRACT_NAMES[key],
    args: (plannedAddresses) => (key.endsWith("Factory") || key === "objectiveVerifier")
      ? []
      : constructorArgsFor(MULTIBOARD_CONTRACT_NAMES[key], config, plannedAddresses),
  }));
  const poolAndLedgerDefinitions = [];
  const submissionDefinitions = [];
  const challengeDefinitions = [];
  for (const problem of config.problems) {
    const boardConfig = {
      ...boardCeremonyConfig(config, problem),
      fundingAuthorization: { boardSetDigest, releaseBindingDigest },
      roles: { ...config.roles, objectiveVerifierCodehash: objectiveVerifierRuntimeCodehash },
    };
    const boardAddressView = (plannedAddresses) => ({
      timelock: plannedAddresses.timelock,
      registry: plannedAddresses.registry,
      rolloverVault: plannedAddresses.rolloverVault,
      pool: plannedAddresses[`board-${problem.problemId}-pool`],
      ledger: plannedAddresses[`board-${problem.problemId}-ledger`],
      submissions: plannedAddresses[`board-${problem.problemId}-submissions`],
      challenges: plannedAddresses[`board-${problem.problemId}-challenges`],
      objectiveVerifier: plannedAddresses.objectiveVerifier,
    });
    for (const [key, name] of Object.entries({
      pool: MULTIBOARD_BOARD_CONTRACT_NAMES.pool,
      ledger: MULTIBOARD_BOARD_CONTRACT_NAMES.ledger,
    })) {
      poolAndLedgerDefinitions.push({
        id: `board-${problem.problemId}-${key}`,
        addressKey: `board-${problem.problemId}-${key}`,
        name,
        args: (plannedAddresses) => constructorArgsFor(name, boardConfig, boardAddressView(plannedAddresses)),
      });
    }
    const submissionId = `board-${problem.problemId}-submissions`;
    const submissionSalt = ethers.keccak256(ethers.toUtf8Bytes(`p42-prizes/base-sepolia/${submissionId}`));
    submissionDefinitions.push({
      id: submissionId,
      addressKey: submissionId,
      name: MULTIBOARD_BOARD_CONTRACT_NAMES.submissions,
      kind: "factory-call-create2",
      factoryName: MULTIBOARD_CONTRACT_NAMES.submissionManagerFactory,
      factoryAddressKey: "submissionManagerFactory",
      factoryMethod: "deploySubmissionManager",
      factoryEvent: "CanonicalSubmissionManagerDeployed",
      salt: submissionSalt,
      configurationGetter: "configurationHashOf",
      args: (plannedAddresses) => constructorArgsFor(
        MULTIBOARD_BOARD_CONTRACT_NAMES.submissions,
        boardConfig,
        boardAddressView(plannedAddresses),
      ),
      parameters: (args) => [Object.values(args[0]), Object.values(args[1])],
      factoryCallArgs: ({ salt, parameters, creationCode }) => [salt, parameters, creationCode],
      configurationHash: ({ ethers: runtimeEthers, parameters, factoryInterface }) =>
        factoryConfigurationHash(runtimeEthers, factoryInterface, "deploySubmissionManager", parameters),
    });
    const challengeId = `board-${problem.problemId}-challenges`;
    const challengeSalt = ethers.keccak256(ethers.toUtf8Bytes(`p42-prizes/base-sepolia/${challengeId}`));
    challengeDefinitions.push({
      id: challengeId,
      addressKey: challengeId,
      name: MULTIBOARD_BOARD_CONTRACT_NAMES.challenges,
      kind: "factory-call-create2",
      factoryName: MULTIBOARD_CONTRACT_NAMES.challengeManagerFactory,
      factoryAddressKey: "challengeManagerFactory",
      factoryMethod: "deployManager",
      factoryEvent: "CanonicalManagerDeployed",
      salt: challengeSalt,
      configurationGetter: "pairConfigurationHashOf",
      args: (plannedAddresses) => {
        const args = constructorArgsFor(
          MULTIBOARD_BOARD_CONTRACT_NAMES.challenges,
          boardConfig,
          boardAddressView(plannedAddresses),
        );
        args[1] = plannedAddresses.resolverQuorum;
        return args;
      },
      parameters: (args, plannedAddresses) => ({
        owner: args[0], resolver: args[1], treasury: args[2], submissionManager: args[3],
        challengeWindowSeconds: args[4], betaBps: args[5], minCounterBondWei: args[6],
        rerunCostWei: args[7], rerunCostMultiplierBps: args[8], resolverDecisionBondWei: args[9],
        resolverFraudWindowSeconds: args[10], problemRegistry: plannedAddresses.registry,
        problemId: BigInt(problem.problemId),
        objectivePackageHash: objectivePackageHash(ethers, chainId, plannedAddresses.registry, problem),
        objectiveGuestElfSha256: problem.objectiveGuestElfSha256,
        objectiveProgramVKey: problem.objectiveProgramVKey,
      }),
      effectiveSalt: ({ ethers: runtimeEthers, requestedSalt, parameters, addresses: plannedAddresses }) =>
        challengeManagerEffectiveSalt(runtimeEthers, requestedSalt, plannedAddresses.submissionManagerFactory, parameters),
      factoryCallArgs: ({ salt, parameters, addresses: plannedAddresses }) => [
        salt,
        plannedAddresses.submissionManagerFactory,
        parameters,
      ],
      configurationHash: ({ ethers: runtimeEthers, parameters, addresses: plannedAddresses, factoryInterface }) => {
        const submission = submissionDefinitions.find((entry) => entry.id === submissionId);
        const submissionArgs = submission.args(plannedAddresses);
        const submissionParameters = submission.parameters(submissionArgs, plannedAddresses);
        const submissionHash = factoryConfigurationHash(
          runtimeEthers,
          submissionFactoryInterface,
          "deploySubmissionManager",
          submissionParameters,
        );
        return factoryConfigurationHash(runtimeEthers, factoryInterface, "deployManager", parameters, submissionHash);
      },
    });
  }
  const submissionFactoryInterface = (
    await ethers.getContractFactory(MULTIBOARD_CONTRACT_NAMES.submissionManagerFactory)
  ).interface;
  const resolverQuorum = {
    id: "resolverQuorum",
    addressKey: "resolverQuorum",
    name: MULTIBOARD_CONTRACT_NAMES.resolverQuorum,
    args: (plannedAddresses) => [
      plannedAddresses.timelock,
      config.roles.treasury,
      config.parameters.resolverDecisionBondWei,
      plannedAddresses.challengeManagerFactory,
      config.governance.signers,
      config.governance.threshold,
      config.problems.map((problem) => plannedAddresses[`board-${problem.problemId}-challenges`]),
      plannedAddresses.objectiveVerifier,
      objectiveVerifierRuntimeCodehash,
    ],
  };
  const definitions = [
    ...directRoots,
    ...poolAndLedgerDefinitions,
    ...submissionDefinitions,
    ...challengeDefinitions,
    resolverQuorum,
  ];
  const canonicalDefinitions = [
    ...directRoots,
    resolverQuorum,
    ...config.problems.flatMap((problem) => [
      ...poolAndLedgerDefinitions.filter((entry) => entry.id.startsWith(`board-${problem.problemId}-`)),
      submissionDefinitions.find((entry) => entry.id === `board-${problem.problemId}-submissions`),
      challengeDefinitions.find((entry) => entry.id === `board-${problem.problemId}-challenges`),
    ]),
  ];
  assertCanonicalDeploymentPlan(canonicalDefinitions, config.problems.length);
  assertMultiBoardExecutionDependencyOrder(definitions, config);
  return { definitions, canonicalDefinitions };
}

async function materializeDeploymentSteps(ethers, definitions, addresses) {
  const result = [];
  for (const definition of definitions) {
    const factory = await ethers.getContractFactory(definition.name);
    const args = definition.args(addresses);
    const deployRequest = await factory.getDeployTransaction(...args);
    if ((definition.kind ?? "direct-create") === "direct-create") {
      result.push({
        ...definition,
        kind: "direct-create",
        factory,
        args,
        unsigned: deployRequest,
        expectedInitCode: deployRequest.data,
        constructorArgsHash: constructorArgsHash(ethers, factory, args),
      });
      continue;
    }
    const factoryContract = await ethers.getContractFactory(definition.factoryName);
    const factoryAddress = addresses[definition.factoryAddressKey];
    const requestedSalt = definition.salt;
    const parameters = definition.parameters(args, addresses);
    const salt = definition.effectiveSalt
      ? definition.effectiveSalt({ ethers, requestedSalt, parameters, addresses, factoryInterface: factoryContract.interface })
      : requestedSalt;
    const expectedCalldata = factoryContract.interface.encodeFunctionData(
      definition.factoryMethod,
      definition.factoryCallArgs({ salt: requestedSalt, parameters, addresses, creationCode: factory.bytecode }),
    );
    const configurationReadCalldata = factoryContract.interface.encodeFunctionData(
      definition.configurationGetter,
      [addresses[definition.addressKey]],
    );
    result.push({
      ...definition,
      kind: "factory-call-create2",
      factory,
      args,
      expectedInitCode: deployRequest.data,
      constructorArgsHash: constructorArgsHash(ethers, factory, args),
      factoryAddress,
      salt,
      configurationHash: definition.configurationHash({
        ethers,
        parameters,
        addresses,
        factoryInterface: factoryContract.interface,
      }),
      configurationReadCalldata,
      deploymentEventTopic: factoryContract.interface.getEvent(definition.factoryEvent).topicHash,
      expectedCalldata,
      unsigned: { to: factoryAddress, data: expectedCalldata, value: 0n },
    });
  }
  return result;
}

export async function materializeCanonicalMultiBoardDeploymentPlan(ethers, deployer, startNonce, definitions) {
  const addresses = {};
  for (const [index, definition] of definitions.entries()) {
    if ((definition.kind ?? "direct-create") === "direct-create") {
      addresses[definition.addressKey] = ethers.getCreateAddress({ from: deployer.address, nonce: startNonce + index });
    }
  }
  for (const definition of definitions) {
    if (definition.kind !== "factory-call-create2") continue;
    const targetFactory = await ethers.getContractFactory(definition.name);
    const args = definition.args(addresses);
    const initCode = (await targetFactory.getDeployTransaction(...args)).data;
    const factoryInterface = (await ethers.getContractFactory(definition.factoryName)).interface;
    const parameters = definition.parameters(args, addresses);
    const salt = definition.effectiveSalt
      ? definition.effectiveSalt({ ethers, requestedSalt: definition.salt, parameters, addresses, factoryInterface })
      : definition.salt;
    addresses[definition.addressKey] = ethers.getCreate2Address(
      addresses[definition.factoryAddressKey],
      salt,
      ethers.keccak256(initCode),
    );
  }
  return {
    startNonce,
    definitions,
    addresses,
    steps: await materializeDeploymentSteps(ethers, definitions, addresses),
  };
}

export function multiBoardPredeploymentGovernanceOperations(operations) {
  const selected = operations.filter(({ label }) => (
    label.endsWith(".pool.setLedger")
    || label.endsWith(".ledger.setCreditRecorder")
    || label.endsWith(".pool.setSubmissionManager")
    || label.endsWith(".submissions.setChallengeManager")
  ));
  if (selected.length !== 40) {
    throw new Error(`multi-board predeployment governance phase requires exactly 40 operations, got ${selected.length}`);
  }
  const selectedIds = new Set(selected.flatMap((operation) => [
    operation.operationId,
    operation.overrideFallback?.operationId,
  ].filter(Boolean).map((value) => value.toLowerCase())));
  return selected.map((operation, index) => ({
    ...operation,
    sequence: index + 1,
    dependsOn: operation.dependsOn.filter((value) => selectedIds.has(value.toLowerCase())),
  }));
}

export function predeploymentGovernanceJournalPath(manifestPath) {
  const absolute = resolve(manifestPath);
  return join(dirname(absolute), `${basename(absolute)}.predeployment-governance-operations.json`);
}

export async function verifyMultiBoardPredeploymentGovernancePhase({
  operations,
  timelock,
  secondaryTimelock,
  journalPath,
  chainId,
  timelockAddress,
  expectedTimelockCodeHash,
  deploymentConfigHash,
  releaseBindingDigest,
  fromBlock,
  toBlock,
}) {
  if (operations.length !== 40) throw new Error("predeployment governance verification requires exactly 40 operations");
  const expectedJournal = buildGovernanceOperationJournal({
    chainId,
    timelock: timelockAddress,
    deploymentConfigHash,
    releaseBindingDigest,
    expectedTimelockCodeHash,
    operations,
  });
  const journal = reserveGovernanceOperationJournal(journalPath, expectedJournal);
  const incomplete = [];
  for (const [index, operation] of operations.entries()) {
    const fallback = operation.overrideFallback;
    const candidates = [
      operation,
      ...(fallback === null ? [] : [{
        ...operation,
        operationId: fallback.operationId,
        salt: fallback.salt,
        operationClass: "override",
      }]),
    ];
    const observations = await Promise.all(candidates.map((candidate) =>
      observeGovernanceOperation(timelock, candidate, {
        chainId,
        timelockAddress,
        expectedTimelockCodeHash,
        fromBlock,
        toBlock,
        secondaryTimelock,
        requireIndependent: true,
      })
    ));
    const executed = observations.flatMap((evidence, candidateIndex) =>
      evidence.state === "executed" ? [{ evidence, candidate: candidates[candidateIndex] }] : []
    );
    if (executed.length !== 1) {
      incomplete.push({
        sequence: operation.sequence,
        label: operation.label,
        candidates: observations.map((evidence) => ({
          operationId: evidence.operationId,
          state: evidence.state,
        })),
      });
      continue;
    }
    const { evidence, candidate } = executed[0];
    await recordGovernanceObservation(journalPath, journal.planDigest, index, {
      ...evidence,
      operationId: operation.operationId,
      observedOperationId: candidate.operationId,
    });
  }
  if (incomplete.length > 0) {
    throw new Error(`pre-challenge governance phase is incomplete\n${JSON.stringify({
      journalPath,
      requiredOperationCount: operations.length,
      incomplete,
    })}`);
  }
  return reserveGovernanceOperationJournal(journalPath, expectedJournal);
}

export async function runPhasedDeploymentSteps({
  steps,
  indexes = Array.from(steps.keys()),
  beforeStep,
  executeStep,
}) {
  for (const index of indexes) {
    const definition = steps[index];
    if (!definition) throw new Error(`deployment step index ${index} is outside the signed plan`);
    if (beforeStep) await beforeStep({ index, definition, steps });
    await executeStep({ index, definition, steps });
  }
}
