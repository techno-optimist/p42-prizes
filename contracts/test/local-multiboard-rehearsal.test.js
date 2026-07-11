import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

async function appendJournal(path, entry) {
  const current = JSON.parse(await readFile(path, "utf8"));
  current.entries.push(entry);
  await writeFile(path, `${JSON.stringify(current, null, 2)}\n`);
}

async function executePending(timelock, signers, operations, journalPath, stopAfter = Infinity) {
  const journal = JSON.parse(await readFile(journalPath, "utf8"));
  const completed = new Set(journal.entries.map((entry) => entry.operationId));
  let executed = 0;
  for (const operation of operations) {
    if (completed.has(operation.operationId)) {
      assert.equal(await timelock.stateOf(operation.operationId), 2n);
      continue;
    }
    const args = [operation.target, operation.value, operation.data, operation.salt];
    const scheduleFunction = operation.operationClass === "override" ? "scheduleOverride" : "schedule";
    await timelock.connect(signers[0])[scheduleFunction](...args);
    for (let index = 1; index < Number(operation.requiredConfirmations); index += 1) {
      await timelock.connect(signers[index]).confirm(operation.operationId);
    }
    await ethers.provider.send("evm_increaseTime", [Number(operation.delaySeconds) + 1]);
    await ethers.provider.send("evm_mine", []);
    let receipt;
    try {
      receipt = await (await timelock.connect(signers[0]).execute(...args)).wait();
    } catch (error) {
      throw new Error(`operation ${operation.sequence} (${operation.label}) failed: ${error.message}`);
    }
    await appendJournal(journalPath, {
      sequence: operation.sequence,
      label: operation.label,
      operationId: operation.operationId,
      txHash: receipt.hash,
      blockNumber: receipt.blockNumber,
    });
    executed += 1;
    if (executed === stopAfter) throw new Error("injected rehearsal interruption");
  }
}

describe("exact ten-board local ceremony rehearsal", { timeout: 240_000 }, function () {
  it("logically replays its journal and reconciles 43 contracts and 110 operations without funding", async function () {
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
      await writeFile(journalPath, `${JSON.stringify({ schema: "p42-prizes/local-ceremony-journal/v1", entries: [] }, null, 2)}\n`, { flag: "wx" });
      await assert.rejects(
        executePending(timelock, [signer1, signer2, signer3], operations, journalPath, 37),
        /injected rehearsal interruption/,
      );
      assert.equal(JSON.parse(await readFile(journalPath, "utf8")).entries.length, 37);
      await executePending(timelock, [signer1, signer2, signer3], operations, journalPath);
      const journal = JSON.parse(await readFile(journalPath, "utf8"));
      assert.equal(journal.entries.length, 110);
      assert.equal(new Set(journal.entries.map((entry) => entry.operationId)).size, 110);
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
