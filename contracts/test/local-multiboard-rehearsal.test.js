import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { artifacts, network } from "hardhat";

import { canonicalTopologyDescriptors } from "../../agent/canonical-topology.mjs";
import {
  buildMultiBoardSetupOperations,
  createDeploymentReservationIdentity,
} from "../scripts/deployment-ceremony-helper.js";
import {
  buildTrustedRpcEvidence,
  readSignedDeploymentJournal,
  signedDeploymentJournalPath,
} from "../scripts/signed-deployment-journal.js";
import {
  boardSetDigest,
  PRODUCTION_LAUNCH_SLUGS,
  readMultiBoardCeremonyConfig,
} from "../scripts/multiboard-ceremony-helper.js";
import {
  buildGovernanceOperationJournal,
  observeGovernanceOperation,
  readGovernanceOperationJournal,
  recordGovernanceObservation,
  reserveGovernanceOperationJournal,
} from "../scripts/governance-operation-journal.js";
import {
  buildCanonicalMultiBoardDeploymentDefinitions,
  materializeCanonicalMultiBoardDeploymentPlan,
  multiBoardPredeploymentGovernanceOperations,
  verifyMultiBoardPredeploymentGovernancePhase,
  MULTIBOARD_BOARD_CONTRACT_NAMES,
  MULTIBOARD_CONTRACT_NAMES,
  MULTIBOARD_PRECHALLENGE_DEPLOYMENT_COUNT,
} from "../scripts/multiboard-deployment-plan.js";

const FIXTURE = new URL("./fixtures/multiboard-ceremony-10.json", import.meta.url);
const { ethers } = await network.create();
const deploymentLibraryImport = Symbol.for("p42-prizes.deploy-base-sepolia.library-import");
globalThis[deploymentLibraryImport] = true;
const { executeSignedDeploymentPlan } = await import("../scripts/deploy-base-sepolia.js");
delete globalThis[deploymentLibraryImport];
const DECISION_TYPES = {
  Decision: [
    { name: "chainId", type: "uint256" },
    { name: "adapter", type: "address" },
    { name: "manager", type: "address" },
    { name: "submissionId", type: "uint256" },
    { name: "challengeInstanceHash", type: "bytes32" },
    { name: "challengerWins", type: "bool" },
    { name: "transcriptHash", type: "bytes32" },
    { name: "transcriptURIHash", type: "bytes32" },
    { name: "verdictHash", type: "bytes32" },
    { name: "bondBeneficiary", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "expiry", type: "uint64" },
    { name: "signerEpoch", type: "uint64" },
  ],
};

async function interfaces() {
  return Object.fromEntries(await Promise.all(Object.entries({
    timelock: MULTIBOARD_CONTRACT_NAMES.timelock,
    registry: MULTIBOARD_CONTRACT_NAMES.registry,
    ...MULTIBOARD_BOARD_CONTRACT_NAMES,
  }).map(async ([key, name]) => [key, (await ethers.getContractFactory(name)).interface])));
}

async function advanceTo(timestamp) {
  const latest = await ethers.provider.getBlock("latest");
  if (BigInt(latest.timestamp) >= BigInt(timestamp)) return;
  await ethers.provider.send("evm_setNextBlockTimestamp", [Number(timestamp)]);
  await ethers.provider.send("evm_mine", []);
}

async function executeOperations(
  timelock,
  signers,
  operations,
  indexes,
  journalPath,
  { crashAfterExecute = Infinity } = {},
) {
  const journalIdentity = readGovernanceOperationJournal(journalPath);
  const planDigest = journalIdentity.planDigest;
  const observe = async (operation) => observeGovernanceOperation(timelock, operation, {
    chainId: journalIdentity.chainId,
    timelockAddress: journalIdentity.timelock,
    expectedTimelockCodeHash: journalIdentity.expectedTimelockCodeHash,
    toBlock: await ethers.provider.getBlockNumber(),
  });
  let executed = 0;
  for (const index of indexes) {
    const operation = operations[index];
    let evidence = await observe(operation);
    await recordGovernanceObservation(journalPath, planDigest, index, evidence);
    if (evidence.state === "executed") continue;
    const args = [operation.target, operation.value, operation.data, operation.salt];
    if (evidence.state === "planned") {
      const scheduleFunction = operation.operationClass === "override" ? "scheduleOverride" : "schedule";
      await (await timelock.connect(signers[0])[scheduleFunction](...args)).wait();
      evidence = await observe(operation);
      await recordGovernanceObservation(journalPath, planDigest, index, evidence);
    }
    for (let signerIndex = 0; signerIndex < Number(operation.requiredConfirmations); signerIndex += 1) {
      if (!await timelock.confirmedBy(operation.operationId, signers[signerIndex].address)) {
        await (await timelock.connect(signers[signerIndex]).confirm(operation.operationId)).wait();
      }
    }
    await ethers.provider.send("evm_increaseTime", [Number(operation.delaySeconds) + 1]);
    await ethers.provider.send("evm_mine", []);
    await (await timelock.connect(signers[0]).execute(...args)).wait();
    executed += 1;
    if (executed === crashAfterExecute) throw new Error("injected post-execution pre-journal crash");
    evidence = await observe(operation);
    await recordGovernanceObservation(journalPath, planDigest, index, evidence);
  }
}

async function executeGovernedCall(timelock, signers, target, data, label) {
  const salt = ethers.id(`local-lifecycle:${label}`);
  await timelock.connect(signers[0]).schedule(target, 0, data, salt);
  const operationId = await timelock.opId(target, 0, data, salt);
  await timelock.connect(signers[1]).confirm(operationId);
  await ethers.provider.send("evm_increaseTime", [Number(await timelock.delay()) + 1]);
  await ethers.provider.send("evm_mine", []);
  await timelock.connect(signers[0]).execute(target, 0, data, salt);
}

function boardContracts(deployed, problemId) {
  return Object.fromEntries(Object.keys(MULTIBOARD_BOARD_CONTRACT_NAMES).map((key) => [
    key,
    deployed[`board-${problemId}-${key}`],
  ]));
}

describe("production-shaped exact-ten local ceremony", { timeout: 900_000 }, function () {
  it("deploys the canonical 47, executes 110 governed setup operations, and keeps inactive proofs non-fundable", async function (t) {
    const input = JSON.parse(await readFile(FIXTURE, "utf8"));
    const signers = await ethers.getSigners();
    const [
      signer1, signer2, signer3, guardian, treasury, resolver, deployerFunder, sponsor, solver, challenger,
      productionLaunchAuthority, independentSecurityAuthority, governanceAuthority,
    ] = signers;
    const deployer = ethers.Wallet.createRandom().connect(ethers.provider);
    await (await deployerFunder.sendTransaction({ to: deployer.address, value: ethers.parseEther("100") })).wait();
    input.governance.signers = [signer1.address, signer2.address, signer3.address];
    input.governance.guardian = guardian.address;
    input.roles.treasury = treasury.address;
    input.roles.resolver = resolver.address;
    input.roles.productionLaunchAuthority = productionLaunchAuthority.address;
    input.roles.independentSecurityAuthority = independentSecurityAuthority.address;
    input.roles.governanceAuthority = governanceAuthority.address;
    for (const problem of input.problems) {
      problem.verifierSourceHash = ethers.keccak256(ethers.toUtf8Bytes(problem.verifierSourceDigest));
      problem.verifierImageHash = ethers.keccak256(ethers.toUtf8Bytes(problem.verifierImageDigest));
    }
    const config = readMultiBoardCeremonyConfig(ethers, input, { deployerAddress: deployer.address });
    assert.deepEqual(config.problems.map(({ problemSlug }) => problemSlug), PRODUCTION_LAUNCH_SLUGS);

    const objectiveArtifact = await artifacts.readArtifact(MULTIBOARD_CONTRACT_NAMES.objectiveVerifier);
    const objectiveVerifierRuntimeCodehash = ethers.keccak256(objectiveArtifact.deployedBytecode);
    const immutableBoardSetDigest = boardSetDigest(config.problems);
    const fundingBoardSetDigest = `0x${immutableBoardSetDigest.slice("sha256:".length)}`;
    const fundingReleaseBindingDigest = ethers.id("local-production-shaped-release-binding");
    const { definitions, canonicalDefinitions } = await buildCanonicalMultiBoardDeploymentDefinitions({
      ethers,
      config,
      chainId: 31337n,
      objectiveVerifierRuntimeCodehash,
      boardSetDigest: fundingBoardSetDigest,
      releaseBindingDigest: fundingReleaseBindingDigest,
    });
    assert.equal(definitions.length, 47);
    assert.equal(canonicalDefinitions.length, 47);
    assert.deepEqual(
      canonicalDefinitions.map(({ id, name }) => ({ id, name })),
      canonicalTopologyDescriptors().map(({ id, name }) => ({ id, name })),
    );
    const startNonce = await ethers.provider.getTransactionCount(deployer.address);
    const plan = await materializeCanonicalMultiBoardDeploymentPlan(ethers, deployer, startNonce, definitions);
    assert.equal(plan.steps.length, 47);
    assert.equal(new Set(Object.values(plan.addresses).map((address) => address.toLowerCase())).size, 47);

    const boards = config.problems.map((problem) => ({
      problem,
      addresses: {
        timelock: plan.addresses.timelock,
        registry: plan.addresses.registry,
        rolloverVault: plan.addresses.rolloverVault,
        ...Object.fromEntries(Object.keys(MULTIBOARD_BOARD_CONTRACT_NAMES).map((key) => [
          key,
          plan.addresses[`board-${problem.problemId}-${key}`],
        ])),
      },
    }));
    const operations = buildMultiBoardSetupOperations({
      ethers,
      chainId: 31337n,
      timelockAddress: plan.addresses.timelock,
      registryAddress: plan.addresses.registry,
      config,
      boards,
      interfaces: await interfaces(),
    });
    assert.equal(operations.length, 110);
    assert.equal(new Set(operations.map(({ operationId }) => operationId)).size, 110);
    const prerequisiteIds = new Set(multiBoardPredeploymentGovernanceOperations(operations).map(({ operationId }) => operationId));
    const predeploymentOperations = multiBoardPredeploymentGovernanceOperations(operations);
    const prerequisiteIndexes = operations.flatMap((operation, index) => prerequisiteIds.has(operation.operationId) ? [index] : []);
    const remainingIndexes = operations.flatMap((operation, index) => prerequisiteIds.has(operation.operationId) ? [] : [index]);
    assert.equal(prerequisiteIndexes.length, 40);
    assert.equal(remainingIndexes.length, 70);

    const directory = await mkdtemp(join(tmpdir(), "p42-production-shaped-"));
    const output = join(directory, "manifest.json");
    const journalPath = join(directory, "governance.json");
    try {
      const reservationIdentity = createDeploymentReservationIdentity(output, {
        deploymentCommit: "0".repeat(40),
        network: "hardhat",
        chainId: 31337,
        deployer: deployer.address,
      }, { trustedRoot: directory, configValue: input });
      const rpcEvidence = buildTrustedRpcEvidence({
        primaryUrl: "https://primary.example/rpc",
        secondaryUrl: "https://secondary.example/rpc",
        primaryOperatorId: "local-primary",
        secondaryOperatorId: "local-secondary",
      });
      const predeploymentJournalPath = join(directory, "predeployment-governance.json");
      let predeploymentVerification;
      let phaseGateCalls = 0;
      const beforeStep = async ({ index }) => {
        if (index !== MULTIBOARD_PRECHALLENGE_DEPLOYMENT_COUNT) return;
        phaseGateCalls += 1;
        const timelockFactory = await ethers.getContractFactory(MULTIBOARD_CONTRACT_NAMES.timelock);
        const timelock = timelockFactory.attach(plan.addresses.timelock).connect(deployer);
        predeploymentVerification ??= {
          operations: predeploymentOperations,
          timelock,
          secondaryTimelock: timelock,
          journalPath: predeploymentJournalPath,
          chainId: 31337,
          timelockAddress: plan.addresses.timelock,
          expectedTimelockCodeHash: ethers.keccak256(await ethers.provider.getCode(plan.addresses.timelock)),
          deploymentConfigHash: ethers.id("local-predeployment-config"),
          deploymentCommit: "a".repeat(40),
          governance: {
            signers: config.governance.signers,
            threshold: config.governance.threshold.toString(),
            overrideThreshold: config.governance.overrideThreshold.toString(),
            delaySeconds: config.governance.delaySeconds.toString(),
            overrideDelaySeconds: config.governance.overrideDelaySeconds.toString(),
            guardian: config.governance.guardian,
          },
          releaseBindingDigest: `sha256:${"1".repeat(64)}`,
          fromBlock: 0,
        };
        await verifyMultiBoardPredeploymentGovernancePhase({
          ...predeploymentVerification,
          toBlock: await ethers.provider.getBlockNumber(),
        });
      };
      const runnerOptions = {
        beforeStep,
        secondaryProvider: ethers.provider,
        rpcEvidence,
        chainId: 31337n,
        networkName: "hardhat",
      };
      const durableProgress = new Map();
      const recordProgress = async (definition, progress) => {
        const previous = durableProgress.get(definition.id);
        if (previous?.state === "mined" && progress.state !== "mined") {
          throw new Error(`deployment progress regressed for ${definition.id}`);
        }
        durableProgress.set(definition.id, progress);
      };
      await assert.rejects(
        executeSignedDeploymentPlan(
          ethers,
          deployer,
          output,
          reservationIdentity,
          definitions,
          recordProgress,
          1,
          null,
          plan,
          runnerOptions,
        ),
        /pre-challenge governance phase is incomplete/,
      );
      assert.equal(phaseGateCalls, 1);
      const signedAfterCrash = readSignedDeploymentJournal(signedDeploymentJournalPath(output));
      assert.equal(signedAfterCrash.steps.filter(({ state }) => state === "mined").length, 36);
      assert.equal(signedAfterCrash.steps.filter(({ state }) => state === "planned").length, 11);
      assert.equal([...durableProgress.values()].filter(({ state }) => state === "mined").length, 36);
      t.diagnostic("durable runner stopped at the 36-deployment governance boundary");
      const timelock = (await ethers.getContractFactory(MULTIBOARD_CONTRACT_NAMES.timelock))
        .attach(plan.addresses.timelock)
        .connect(deployer);
      const expectedJournal = buildGovernanceOperationJournal({
        chainId: 31337,
        timelock: plan.addresses.timelock,
        deploymentConfigHash: ethers.id("local-production-shaped-rehearsal"),
        deploymentCommit: "a".repeat(40),
        governance: {
          signers: config.governance.signers,
          threshold: config.governance.threshold.toString(),
          overrideThreshold: config.governance.overrideThreshold.toString(),
          delaySeconds: config.governance.delaySeconds.toString(),
          overrideDelaySeconds: config.governance.overrideDelaySeconds.toString(),
          guardian: config.governance.guardian,
        },
        releaseBindingDigest: `sha256:${"0".repeat(64)}`,
        expectedTimelockCodeHash: ethers.keccak256(await ethers.provider.getCode(plan.addresses.timelock)),
        operations,
      });
      reserveGovernanceOperationJournal(journalPath, expectedJournal);
      assert.equal(
        readGovernanceOperationJournal(predeploymentJournalPath).operations.filter(({ state }) => state === "planned").length,
        40,
      );
      await executeOperations(timelock, [signer1, signer2, signer3], operations, prerequisiteIndexes, journalPath);
      t.diagnostic("40 prerequisite governance operations executed");
      assert.equal(readGovernanceOperationJournal(journalPath).operations.filter(({ state }) => state === "executed").length, 40);
      const resumed = await executeSignedDeploymentPlan(
        ethers,
        deployer,
        output,
        reservationIdentity,
        definitions,
        recordProgress,
        1,
        null,
        plan,
        runnerOptions,
      );
      const deployed = Object.fromEntries(Object.entries(resumed.deployments).map(([id, deployment]) => [
        id,
        deployment.contract.connect(deployer),
      ]));
      assert.equal(phaseGateCalls, 2);
      const signedAfterResume = readSignedDeploymentJournal(signedDeploymentJournalPath(output));
      assert.equal(signedAfterResume.planDigest, signedAfterCrash.planDigest);
      assert.equal(signedAfterResume.steps.filter(({ state }) => state === "mined").length, 47);
      assert.equal([...durableProgress.values()].filter(({ state }) => state === "mined").length, 47);
      t.diagnostic("durable runner resumed the identical journal through all 47 deployments");
      assert.equal(
        readGovernanceOperationJournal(predeploymentJournalPath).operations.filter(({ state }) => state === "executed").length,
        40,
      );
      assert.equal(Object.keys(deployed).length, 47);
      for (const descriptor of canonicalTopologyDescriptors()) {
        assert.notEqual(await ethers.provider.getCode(plan.addresses[descriptor.id]), "0x", descriptor.id);
      }

      await assert.rejects(
        executeOperations(timelock, [signer1, signer2, signer3], operations, remainingIndexes, journalPath, { crashAfterExecute: 17 }),
        /post-execution pre-journal crash/,
      );
      assert.equal(readGovernanceOperationJournal(journalPath).operations.filter(({ state }) => state === "executed").length, 56);
      await executeOperations(timelock, [signer1, signer2, signer3], operations, remainingIndexes, journalPath);
      const journal = readGovernanceOperationJournal(journalPath);
      assert.equal(journal.operations.filter(({ state }) => state === "executed").length, 110);
      t.diagnostic("all 110 governed setup operations executed and reconciled");

      const registry = deployed.registry;
      const submissionFactory = deployed.submissionManagerFactory;
      const challengeFactory = deployed.challengeManagerFactory;
      const quorum = deployed.resolverQuorum;
      assert.equal(await registry.problemCount(), 10n);
      assert.equal(await quorum.managerCount(), 10n);
      assert.equal(await quorum.managersFrozen(), true);
      assert.equal(await quorum.objectiveVerifier(), plan.addresses.objectiveVerifier);
      assert.equal(await quorum.objectiveVerifierCodehash(), objectiveVerifierRuntimeCodehash);
      for (const [index, problem] of config.problems.entries()) {
        const problemId = String(index + 1);
        const contracts = boardContracts(deployed, problemId);
        assert.equal(await registry.explicitlyFrozen(BigInt(problemId)), true);
        assert.equal(await submissionFactory.isCanonicalSubmissionManager(await contracts.submissions.getAddress()), true);
        const submissionStep = plan.steps.find(({ addressKey }) => addressKey === `board-${problemId}-submissions`);
        const challengeStep = plan.steps.find(({ addressKey }) => addressKey === `board-${problemId}-challenges`);
        assert.ok(submissionStep);
        assert.ok(challengeStep);
        assert.equal(
          await submissionFactory.configurationHashOf(await contracts.submissions.getAddress()),
          submissionStep.configurationHash,
        );
        assert.equal(await challengeFactory.isCanonicalManager(await contracts.challenges.getAddress()), true);
        assert.equal(
          await challengeFactory.pairConfigurationHashOf(await contracts.challenges.getAddress()),
          challengeStep.configurationHash,
        );
        assert.equal(await quorum.managerAt(index), await contracts.challenges.getAddress());
        assert.equal(await quorum.isManager(await contracts.challenges.getAddress()), true);
        assert.equal(await contracts.pool.owner(), plan.addresses.timelock);
        assert.equal(await contracts.ledger.owner(), plan.addresses.timelock);
        assert.equal(await contracts.submissions.owner(), plan.addresses.timelock);
        assert.equal(await contracts.challenges.owner(), plan.addresses.timelock);
        assert.equal(await contracts.submissions.objectiveVerifier(), plan.addresses.objectiveVerifier);
        assert.equal(await contracts.submissions.objectiveVerifierCodehash(), objectiveVerifierRuntimeCodehash);
        assert.equal(await contracts.submissions.objectiveProofCapabilityActive(), false);
        assert.equal(await contracts.submissions.fundingArmed(), false);
        assert.equal(await contracts.pool.acceptingFunds(), false);
        assert.equal(await ethers.provider.getBalance(await contracts.pool.getAddress()), 0n);
        assert.equal(problem.problemId, problemId);
      }

      const active = boardContracts(deployed, "1");
      await advanceTo(await active.submissions.armNotBefore());
      const fundingDigest = ethers.id("local-production-shaped-funding-authorization");
      const expiresAt = 2n ** 64n - 1n;
      const fundingDomain = {
        name: "P42SubmissionManager",
        version: "2",
        chainId: 31337n,
        verifyingContract: await active.submissions.getAddress(),
      };
      const fundingTypes = {
        FundingAuthorization: [
          { name: "role", type: "bytes32" },
          { name: "boardSetDigest", type: "bytes32" },
          { name: "releaseBindingDigest", type: "bytes32" },
          { name: "authorizationDigest", type: "bytes32" },
          { name: "expiresAt", type: "uint64" },
          { name: "nonce", type: "uint256" },
        ],
      };
      const common = {
        boardSetDigest: fundingBoardSetDigest,
        releaseBindingDigest: fundingReleaseBindingDigest,
        authorizationDigest: fundingDigest,
        expiresAt,
        nonce: 0n,
      };
      const fundingSignatures = await Promise.all([
        productionLaunchAuthority.signTypedData(fundingDomain, fundingTypes, { ...common, role: ethers.id("production-launch-authority") }),
        independentSecurityAuthority.signTypedData(fundingDomain, fundingTypes, { ...common, role: ethers.id("independent-security-authority") }),
        governanceAuthority.signTypedData(fundingDomain, fundingTypes, { ...common, role: ethers.id("governance-authority") }),
      ]);
      await assert.rejects(
        active.submissions.connect(treasury).authorizeFunding(fundingDigest, expiresAt, 0n, fundingSignatures),
        /P42_OBJECTIVE_PROOF_CAPABILITY_INACTIVE/,
      );
      assert.equal(await active.submissions.authorizedFundingDigest(), ethers.ZeroHash);
      assert.equal(await active.submissions.fundingAuthorizationNonce(), 0n);
      assert.equal(await active.submissions.fundingArmed(), false);
      assert.equal(await active.pool.acceptingFunds(), false);
      await assert.rejects(active.pool.connect(sponsor).fund({ value: 1n }), /P42_FUNDING_NOT_ARMED/);

      const solutionBytes = ethers.toUtf8Bytes("production-shaped-local-solution");
      const daHash = ethers.sha256(solutionBytes);
      const solutionCid = "ipfs://production-shaped-local-solution";
      const salt = "production-shaped-local-salt";
      const commitment = await active.submissions["computeCommitment(string,address,bytes32,string)"](
        solutionCid,
        solver.address,
        daHash,
        salt,
      );
      await active.submissions.connect(solver).commit(commitment, daHash, {
        value: await active.submissions.requiredPostingBondNow(),
      });
      const submissionId = await active.submissions.submissionCount();
      const improvement = config.problems[0].minImprovementAtoms;
      const score = config.problems[0].seedScoreAtoms - improvement;
      await active.submissions.connect(solver).reveal(
        submissionId,
        solutionCid,
        score,
        improvement,
        salt,
        solutionBytes,
      );
      const challengeInstance = await active.submissions.revealInstanceHashOf(submissionId);
      const challengeBond = await active.challenges.requiredChallengeBond(
        await active.submissions.disputedEntitlementWei(submissionId),
      );
      await active.challenges.connect(challenger).challenge(
        submissionId,
        challengeInstance,
        ethers.id("production-shaped-challenge"),
        { value: challengeBond },
      );

      const resolverBond = await active.challenges.resolverDecisionBondWei();
      await quorum.connect(signer1).fundStake({ value: resolverBond * 2n });
      const transcriptURI = "ipfs://production-shaped-transcript";
      const decision = {
        chainId: 31337n,
        adapter: await quorum.getAddress(),
        manager: await active.challenges.getAddress(),
        submissionId,
        challengeInstanceHash: await active.challenges.challengeInstanceHashOf(submissionId),
        challengerWins: false,
        transcriptHash: ethers.id("production-shaped-transcript-bytes"),
        transcriptURIHash: ethers.keccak256(ethers.toUtf8Bytes(transcriptURI)),
        verdictHash: ethers.id("production-shaped-verdict"),
        bondBeneficiary: await quorum.getAddress(),
        nonce: 1n,
        expiry: BigInt((await ethers.provider.getBlock("latest")).timestamp) + 3_600n,
        signerEpoch: await quorum.signerEpoch(),
      };
      const domain = {
        name: "P42ResolverQuorum",
        version: "1",
        chainId: decision.chainId,
        verifyingContract: await quorum.getAddress(),
      };
      const signatures = (await Promise.all([signer1, signer2].map(async (signer) => ({
        signer: signer.address.toLowerCase(),
        signature: await signer.signTypedData(domain, DECISION_TYPES, decision),
      })))).sort((left, right) => left.signer.localeCompare(right.signer)).map(({ signature }) => signature);
      await quorum.resolve(decision, transcriptURI, signatures);
      const resolverBondState = await active.challenges.resolverBonds(submissionId);
      await advanceTo(resolverBondState.releaseAt);
      await active.challenges.finalizeResolution(submissionId, decision.challengeInstanceHash);
      await advanceTo((await active.submissions.submissions(submissionId)).challengeEndsAt);
      await active.submissions.connect(solver).finalize(submissionId, ethers.id("production-shaped-permanence"));
      assert.equal(await active.ledger.creditAtomsOf(solver.address), 0n);
      assert.equal(await active.submissions.claimableBondWei(solver.address), await active.submissions.minPostingBondWei());

      await advanceTo(await active.ledger.closeByTimestamp());
      await active.ledger.close();
      assert.equal(await active.ledger.finalEntitlement(solver.address), 0n);
      assert.equal(await active.pool.totalFunded(), 0n);
      assert.equal(await active.pool.totalGrossClaimed(), 0n);
      assert.equal(await active.pool.totalClaimed(), 0n);
      assert.equal(await active.pool.accountedBalance(), 0n);
      assert.equal(await ethers.provider.getBalance(await active.pool.getAddress()), 0n);

      for (let problemId = 2; problemId <= 10; problemId += 1) {
        const untouched = boardContracts(deployed, String(problemId));
        assert.equal(await untouched.submissions.submissionCount(), 0n);
        assert.equal(await untouched.submissions.fundingArmed(), false);
        assert.equal(await untouched.pool.acceptingFunds(), false);
        assert.equal(await untouched.ledger.totalCreditAtoms(), 0n);
        assert.equal(await ethers.provider.getBalance(await untouched.pool.getAddress()), 0n);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
