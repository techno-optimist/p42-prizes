import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { network } from "hardhat";

import {
  boardCeremonyConfig,
  buildMultiBoardSetupOperations,
  constructorArgsFor,
} from "../scripts/deployment-ceremony-helper.js";
import { readMultiBoardCeremonyConfig } from "../scripts/multiboard-ceremony-helper.js";
import {
  buildGovernanceOperationJournal,
  observeGovernanceOperation,
  readGovernanceOperationJournal,
  recordGovernanceObservation,
  reserveGovernanceOperationJournal,
} from "../scripts/governance-operation-journal.js";

const FIXTURE = new URL("./fixtures/multiboard-ceremony-10.json", import.meta.url);
const { ethers } = await network.create();

async function deploy(deployer, name, args) {
  const contract = await (await ethers.getContractFactory(name, deployer)).deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

async function interfaces() {
  return Object.fromEntries(await Promise.all(Object.entries({
    timelock: "P42MultisigTimelock",
    registry: "P42ProblemRegistry",
    pool: "P42BountyPool",
    ledger: "P42PayoutLedger",
    submissions: "P42SubmissionManager",
    challenges: "P42ChallengeManager",
  }).map(async ([key, name]) => [key, (await ethers.getContractFactory(name)).interface])));
}

async function deployBoard(deployer, config, roots) {
  const contracts = {};
  const addresses = { ...roots };
  for (const [key, name] of Object.entries({
    pool: "P42BountyPool",
    ledger: "P42PayoutLedger",
    submissions: "P42SubmissionManager",
    challenges: "P42ChallengeManager",
  })) {
    contracts[key] = await deploy(deployer, name, constructorArgsFor(name, config, addresses));
    addresses[key] = await contracts[key].getAddress();
  }
  return { contracts, addresses };
}

async function executePending(timelock, signers, operations, journalPath, { crashAfterExecute = Infinity } = {}) {
  const journalIdentity = readGovernanceOperationJournal(journalPath);
  const planDigest = journalIdentity.planDigest;
  const observe = async (operation) => observeGovernanceOperation(timelock, operation, {
    chainId: journalIdentity.chainId,
    timelockAddress: journalIdentity.timelock,
    expectedTimelockCodeHash: journalIdentity.expectedTimelockCodeHash,
    toBlock: await ethers.provider.getBlockNumber(),
  });
  let executed = 0;
  for (const [index, operation] of operations.entries()) {
    let evidence = await observe(operation);
    await recordGovernanceObservation(journalPath, planDigest, index, evidence);
    if (evidence.state === "executed") {
      continue;
    }
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
    // Deterministic advance to the operation's actual on-chain eta. Override-class
    // operations get a 2x timelock delay, so a plan-derived delaySeconds can
    // undershoot the real readyAt; evm_increaseTime is also wall-clock-relative and
    // drifts across a long multi-operation run. Reading eta and pinning the next
    // block to it is exact for both classes (7-day grace, so no OpExpired risk).
    const _eta = BigInt((await timelock.ops(operation.operationId)).eta);
    const _latest = await ethers.provider.getBlock("latest");
    if (BigInt(_latest.timestamp) < _eta) {
      await ethers.provider.send("evm_setNextBlockTimestamp", [Number(_eta)]);
      await ethers.provider.send("evm_mine", []);
    }
    try {
      await (await timelock.connect(signers[0]).execute(...args)).wait();
    } catch (error) {
      throw new Error(`operation ${operation.sequence} (${operation.label}) failed: ${error.message}`);
    }
    executed += 1;
    if (executed === crashAfterExecute) throw new Error("injected post-execution pre-journal crash");
    evidence = await observe(operation);
    await recordGovernanceObservation(journalPath, planDigest, index, evidence);
  }
}

describe("exact ten-board local ceremony rehearsal", { timeout: 240_000 }, function () {
  it("logically replays ten board stacks and 110 governance operations without funding", async function () {
    const input = JSON.parse(await readFile(FIXTURE, "utf8"));
    const signers = await ethers.getSigners();
    const [signer1, signer2, signer3, guardian, treasury, resolver, deployer] = signers;
    const roleAddresses = [signer1, signer2, signer3, guardian, treasury, resolver].map((signer) => signer.address);
    input.governance.signers = roleAddresses.slice(0, 3);
    input.governance.guardian = roleAddresses[3];
    input.roles.treasury = roleAddresses[4];
    input.roles.resolver = roleAddresses[5];
    for (const problem of input.problems) {
      problem.verifierSourceHash = ethers.keccak256(ethers.toUtf8Bytes(problem.verifierSourceDigest));
      problem.verifierImageHash = ethers.keccak256(ethers.toUtf8Bytes(problem.verifierImageDigest));
    }
    const config = readMultiBoardCeremonyConfig(ethers, input, { deployerAddress: deployer.address });
    assert.equal(config.problems.length, 10);

    const timelock = await deploy(deployer, "P42MultisigTimelock", constructorArgsFor("P42MultisigTimelock", config));
    const roots = { timelock: await timelock.getAddress() };
    const registry = await deploy(deployer, "P42ProblemRegistry", constructorArgsFor("P42ProblemRegistry", config, roots));
    roots.registry = await registry.getAddress();
    const vault = await deploy(deployer, "P42RolloverVault", constructorArgsFor("P42RolloverVault", config, roots));
    roots.rolloverVault = await vault.getAddress();
    const boards = [];
    for (const problem of config.problems) {
      boards.push({ problem, ...await deployBoard(deployer, boardCeremonyConfig(config, problem), roots) });
    }
    const operations = buildMultiBoardSetupOperations({
      ethers,
      chainId: 31337n,
      timelockAddress: roots.timelock,
      registryAddress: roots.registry,
      config,
      boards: boards.map(({ problem, addresses }) => ({ problem, addresses })),
      interfaces: await interfaces(),
    });
    assert.equal(operations.length, 110);

    const directory = await mkdtemp(join(tmpdir(), "p42-local-ceremony-"));
    const journalPath = join(directory, "journal.json");
    try {
      const expectedJournal = buildGovernanceOperationJournal({
        chainId: 31337, timelock: roots.timelock,
        deploymentConfigHash: ethers.keccak256(ethers.toUtf8Bytes("local-ten-board-rehearsal")),
        releaseBindingDigest: `sha256:${"0".repeat(64)}`,
        expectedTimelockCodeHash: ethers.keccak256(await ethers.provider.getCode(roots.timelock)),
        operations,
      });
      reserveGovernanceOperationJournal(journalPath, expectedJournal);
      await assert.rejects(observeGovernanceOperation(timelock, operations[0], {
        chainId: 1, timelockAddress: roots.timelock, expectedTimelockCodeHash: expectedJournal.expectedTimelockCodeHash,
        toBlock: await ethers.provider.getBlockNumber(),
      }), /chain or timelock binding/);
      await assert.rejects(observeGovernanceOperation(timelock, operations[0], {
        chainId: 31337, timelockAddress: roots.timelock, expectedTimelockCodeHash: expectedJournal.expectedTimelockCodeHash,
      }), /exact numeric chain range/);
      await assert.rejects(observeGovernanceOperation(timelock, operations[0], {
        chainId: 31337, timelockAddress: roots.timelock, expectedTimelockCodeHash: expectedJournal.expectedTimelockCodeHash,
        toBlock: await ethers.provider.getBlockNumber(), requireIndependent: true,
      }), /independent governance operation evidence is required/);
      await assert.rejects(
        executePending(timelock, [signer1, signer2, signer3], operations, journalPath, { crashAfterExecute: 37 }),
        /post-execution pre-journal crash/,
      );
      const interrupted = readGovernanceOperationJournal(journalPath);
      assert.equal(interrupted.operations.filter(({ state }) => state === "executed").length, 36);
      assert.equal(await timelock.stateOf(operations[36].operationId), 2n);
      const disagreeingTimelock = {
        runner: timelock.runner, filters: timelock.filters,
        getAddress: () => timelock.getAddress(),
        stateOf: async () => 0n,
        queryFilter: (...args) => timelock.queryFilter(...args),
      };
      await assert.rejects(observeGovernanceOperation(timelock, operations[36], {
        chainId: 31337, timelockAddress: roots.timelock, expectedTimelockCodeHash: expectedJournal.expectedTimelockCodeHash,
        toBlock: await ethers.provider.getBlockNumber(), secondaryTimelock: disagreeingTimelock, requireIndependent: true,
      }), /state.event mismatch|evidence disagreement/);
      await executePending(timelock, [signer1, signer2, signer3], operations, journalPath);
      const journal = readGovernanceOperationJournal(journalPath);
      assert.equal(journal.operations.filter(({ state }) => state === "executed").length, 110);
      assert.equal(new Set(journal.operations.map((entry) => entry.operationId)).size, 110);
      assert.equal(await registry.problemCount(), 10n);

      for (const [index, board] of boards.entries()) {
        const id = BigInt(index + 1);
        const registered = await registry.problems(id);
        assert.equal(registered.pool, board.addresses.pool);
        assert.equal(await registry.explicitlyFrozen(id), true);
        assert.equal(await board.contracts.pool.problemId(), id);
        assert.equal(await board.contracts.pool.registry(), roots.registry);
        assert.equal(await board.contracts.submissions.fundingArmed(), false);
        assert.equal(await board.contracts.pool.acceptingFunds(), false);
        assert.equal(await ethers.provider.getBalance(board.addresses.pool), 0n);
        for (const contract of Object.values(board.contracts)) {
          assert.equal(await contract.owner(), roots.timelock);
        }
      }
      assert.equal(await ethers.provider.getBalance(await vault.getAddress()), 0n);
      assert.ok((await ethers.provider.getBalance(deployer.address)) > 0n);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
