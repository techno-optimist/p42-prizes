import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

import {
  boardCeremonyConfig,
  buildMultiBoardSetupOperations,
  constructorArgsFor,
} from "../scripts/deployment-ceremony-helper.js";
import {
  readMultiBoardCeremonyConfig,
} from "../scripts/multiboard-ceremony-helper.js";

const { ethers } = await network.create();

function digest(character) {
  return `sha256:${character.repeat(64)}`;
}

function digestHash(value) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

function fixtureProblem({ id, slug, seed, onchainDa }) {
  const source = digest(id === 1 ? "a" : "b");
  const image = digest(id === 1 ? "c" : "d");
  const matrix = digest(id === 1 ? "e" : "f");
  return {
    fundingCapWei: "1000000000000000000",
    maxSolutionBytes: onchainDa ? "64" : "0",
    earliestCloseTimestamp: "1900000000",
    closeByTimestamp: "2000000000",
    specHash: ethers.id(`spec-${slug}`),
    problemSlug: slug,
    verifierVersion: "1.0.0",
    verifierSourceDigest: source,
    verifierSourceHash: digestHash(source),
    verifierImageDigest: image,
    verifierImageHash: digestHash(image),
    admissionMatrixDigest: matrix,
    admissionMatrixURI: `ipfs://${slug}-admission-matrix`,
    admissionMatrixPath: `release-evidence/${slug}/admission-matrix.json`,
    metadataURI: `ipfs://${slug}`,
    seedScoreAtoms: (BigInt(seed) * 10n ** 18n).toString(),
    minImprovementAtoms: "1",
    objectiveGuestElfPath: `release-evidence/${slug}/objective-program.bin`,
    objectiveGuestElfDigest: `sha256:${ethers.sha256(ethers.toUtf8Bytes(`objective-program-bytes-${slug}`)).slice(2)}`,
    objectiveGuestElfSha256: ethers.sha256(ethers.toUtf8Bytes(`objective-program-bytes-${slug}`)),
    objectiveProgramVKey: ethers.id(`objective-program-${slug}`),
    onchainDa,
    certifiedObjective: {
      seedBest: String(seed),
      direction: "minimize",
      minImprovement: "1/1000000000000000000",
    },
  };
}

async function contractInterfaces() {
  const entries = await Promise.all(
    [
      ["timelock", "P42MultisigTimelock"],
      ["registry", "P42ProblemRegistry"],
      ["pool", "P42BountyPool"],
      ["ledger", "P42PayoutLedger"],
      ["submissions", "P42SubmissionManager"],
      ["challenges", "P42ChallengeManager"],
    ].map(async ([key, name]) => [key, (await ethers.getContractFactory(name)).interface]),
  );
  return Object.fromEntries(entries);
}

async function deployContract(deployer, name, args) {
  const contract = await (await ethers.getContractFactory(name)).connect(deployer).deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

async function deployBoard(deployer, config, rootAddresses) {
  const addresses = { ...rootAddresses };
  const pool = await deployContract(
    deployer,
    "P42BountyPool",
    constructorArgsFor("P42BountyPool", config, addresses),
  );
  addresses.pool = await pool.getAddress();
  const ledger = await deployContract(
    deployer,
    "P42PayoutLedger",
    constructorArgsFor("P42PayoutLedger", config, addresses),
  );
  addresses.ledger = await ledger.getAddress();
  const submissions = await deployContract(
    deployer,
    "P42SubmissionManager",
    constructorArgsFor("P42SubmissionManager", config, addresses),
  );
  addresses.submissions = await submissions.getAddress();
  const challenges = await deployContract(
    deployer,
    "P42ChallengeManager",
    constructorArgsFor("P42ChallengeManager", config, addresses),
  );
  addresses.challenges = await challenges.getAddress();
  return { addresses, contracts: { pool, ledger, submissions, challenges } };
}

async function advance(seconds) {
  await ethers.provider.send("evm_increaseTime", [Number(seconds)]);
  await ethers.provider.send("evm_mine", []);
}

async function executeSetupOperation(timelock, signers, operation) {
  const args = [operation.target, BigInt(operation.value), operation.data, operation.salt];
  assert.equal(await timelock.opId(...args), operation.operationId);
  if (operation.operationClass === "override") {
    await timelock.connect(signers[0]).scheduleOverride(...args);
  } else {
    await timelock.connect(signers[0]).schedule(...args);
  }
  await timelock.connect(signers[1]).confirm(operation.operationId);
  if (operation.operationClass === "override") {
    await timelock.connect(signers[2]).confirm(operation.operationId);
  }
  await advance(BigInt(operation.delaySeconds) + 1n);
  await timelock.connect(signers[0]).execute(...args);
}

describe("multi-board governance ceremony integration", () => {
  it("wires two boards and restricts rollover funding until a future board is armed", async () => {
    const signers = await ethers.getSigners();
    const [signer1, signer2, signer3, guardian, treasury, resolver, deployer] = signers;
    const input = {
      schema: "p42-prizes/multi-board-ceremony/v1",
      governance: {
        signers: [signer1.address, signer2.address, signer3.address],
        threshold: "2",
        delaySeconds: "1",
        guardian: guardian.address,
      },
      roles: {
        treasury: treasury.address,
        resolver: resolver.address,
      },
      parameters: {
        alphaBps: "200",
        betaBps: "500",
        challengeWindowSeconds: "259200",
        feeBps: "0",
        minCounterBondWei: "1",
        minPostingBondWei: "1",
        rerunCostMultiplierBps: "30000",
        rerunCostWei: "1",
        resolverDecisionBondWei: "1",
        resolverFraudWindowSeconds: "86400",
      },
      problems: [
        fixtureProblem({ id: 1, slug: "board-one", seed: 1000, onchainDa: true }),
        fixtureProblem({ id: 2, slug: "board-two", seed: 2000, onchainDa: false }),
      ],
    };
    const config = readMultiBoardCeremonyConfig(ethers, input, { deployerAddress: deployer.address });
    const timelock = await deployContract(
      deployer,
      "P42MultisigTimelock",
      constructorArgsFor("P42MultisigTimelock", config),
    );
    const rootAddresses = { timelock: await timelock.getAddress() };
    const registry = await deployContract(
      deployer,
      "P42ProblemRegistry",
      constructorArgsFor("P42ProblemRegistry", config, rootAddresses),
    );
    rootAddresses.registry = await registry.getAddress();
    const rolloverVault = await deployContract(
      deployer,
      "P42RolloverVault",
      constructorArgsFor("P42RolloverVault", config, rootAddresses),
    );
    rootAddresses.rolloverVault = await rolloverVault.getAddress();

    const boards = [];
    for (const problem of config.problems) {
      const deployed = await deployBoard(deployer, boardCeremonyConfig(config, problem), rootAddresses);
      boards.push({ problem, ...deployed });
    }
    const operations = buildMultiBoardSetupOperations({
      ethers,
      chainId: 31337n,
      timelockAddress: rootAddresses.timelock,
      registryAddress: rootAddresses.registry,
      config,
      boards: boards.map(({ problem, addresses }) => ({ problem, addresses })),
      interfaces: await contractInterfaces(),
    });
    assert.equal(operations.length, 22);
    for (const operation of operations) {
      await executeSetupOperation(timelock, [signer1, signer2, signer3], operation);
    }

    assert.equal(await registry.problemCount(), 2n);
    for (const [index, board] of boards.entries()) {
      const problemId = BigInt(index + 1);
      assert.equal(await registry.explicitlyFrozen(problemId), true);
      assert.equal(await board.contracts.pool.registry(), rootAddresses.registry);
      assert.equal(await board.contracts.ledger.rolloverDestination(), rootAddresses.rolloverVault);
      assert.equal(await board.contracts.pool.problemId(), problemId);
      assert.equal(await board.contracts.submissions.fundingArmed(), false);
      assert.equal(await board.contracts.pool.acceptingFunds(), false);
      assert.equal(await board.contracts.pool.owner(), rootAddresses.timelock);
      assert.equal(await board.contracts.ledger.owner(), rootAddresses.timelock);
      assert.equal(await board.contracts.submissions.owner(), rootAddresses.timelock);
      assert.equal(await board.contracts.challenges.owner(), rootAddresses.timelock);
    }

    await deployer.sendTransaction({ to: rootAddresses.rolloverVault, value: 100n });
    await ethers.provider.send("hardhat_impersonateAccount", [rootAddresses.timelock]);
    await ethers.provider.send("hardhat_setBalance", [rootAddresses.timelock, "0x1000000000000000000"]);
    const allocator = await ethers.getSigner(rootAddresses.timelock);
    const pool0 = boards[0].addresses.pool;
    const pool1 = boards[1].addresses.pool;
    const pool0Code = await ethers.provider.getCode(pool0);
    const pool0Hash = ethers.keccak256(pool0Code);
    const pool1Hash = ethers.keccak256(await ethers.provider.getCode(pool1));
    await rolloverVault.connect(allocator).setPoolAllocation(pool0, pool0Hash, 40n);
    await rolloverVault.connect(allocator).setPoolAllocation(pool1, pool1Hash, 60n);
    assert.equal(await rolloverVault.allocationCodehashOf(pool0), pool0Hash);
    assert.equal(await rolloverVault.allocationCodehashOf(pool1), pool1Hash);
    await assert.rejects(
      rolloverVault.connect(deployer).fundRegisteredPool(pool0, 1n),
      /P42_NOT_ALLOCATOR/,
    );
    await assert.rejects(
      rolloverVault.connect(allocator).setPoolAllocation(pool0, ethers.ZeroHash, 40n),
      /P42_CODEHASH_MISMATCH/,
    );
    await assert.rejects(
      rolloverVault.connect(allocator).fundRegisteredPool(pool0, 40n),
      /P42_ROLLOVER_FUNDING_FAILED/,
    );
    assert.equal(await rolloverVault.allocationOf(pool0), 40n);
    assert.equal(await rolloverVault.allocationOf(pool1), 60n);
    assert.equal(await rolloverVault.totalAllocated(), 100n);
    assert.equal(await rolloverVault.allocationCodehashOf(pool0), pool0Hash);

    await rolloverVault.connect(allocator).setPoolAllocation(pool0, pool0Hash, 35n);
    assert.equal(await rolloverVault.allocationOf(pool0), 35n);
    assert.equal(await rolloverVault.totalAllocated(), 95n);
    assert.equal(await rolloverVault.allocationCodehashOf(pool0), pool0Hash);
    await rolloverVault.connect(allocator).setPoolAllocation(pool0, pool0Hash, 40n);
    assert.equal(await rolloverVault.totalAllocated(), 100n);

    await ethers.provider.send("hardhat_setCode", [pool0, "0x00"]);
    await rolloverVault.connect(allocator).setPoolAllocation(pool0, ethers.ZeroHash, 0n);
    assert.equal(await rolloverVault.allocationOf(pool0), 0n);
    assert.equal(await rolloverVault.totalAllocated(), 60n);
    assert.equal(await rolloverVault.allocationCodehashOf(pool0), ethers.ZeroHash);
    await ethers.provider.send("hardhat_setCode", [pool0, pool0Code]);
    await rolloverVault.connect(allocator).setPoolAllocation(pool0, pool0Hash, 40n);
    assert.equal(await rolloverVault.totalAllocated(), 100n);
    assert.equal(await rolloverVault.allocationCodehashOf(pool0), pool0Hash);

    await ethers.provider.send("hardhat_setCode", [pool0, "0x00"]);
    await assert.rejects(
      rolloverVault.connect(allocator).fundRegisteredPool(pool0, 40n),
      /P42_CODEHASH_MISMATCH/,
    );
    assert.equal(await rolloverVault.allocationOf(pool0), 40n);
    assert.equal(await rolloverVault.totalAllocated(), 100n);
    assert.equal(await rolloverVault.allocationCodehashOf(pool0), pool0Hash);
    await ethers.provider.send("hardhat_setCode", [pool0, pool0Code]);

    await advance(BigInt(input.parameters.challengeWindowSeconds) + 1n);
    await boards[0].contracts.submissions.connect(treasury).authorizeFunding("0x" + "42".repeat(32), 2n ** 64n - 1n);
    await boards[0].contracts.submissions.connect(allocator).armFunding("0x" + "42".repeat(32));
    await boards[0].contracts.pool.connect(allocator).setAcceptingFunds(true);
    await rolloverVault.connect(allocator).fundRegisteredPool(pool0, 10n);
    assert.equal(await rolloverVault.allocationOf(pool0), 30n);
    assert.equal(await rolloverVault.allocationCodehashOf(pool0), pool0Hash);
    await rolloverVault.connect(allocator).fundRegisteredPool(pool0, 30n);
    assert.equal(await boards[0].contracts.pool.sponsorshipOf(rootAddresses.rolloverVault), 40n);
    assert.equal(await boards[0].contracts.pool.accountedBalance(), 40n);
    assert.equal(await rolloverVault.allocationOf(pool0), 0n);
    assert.equal(await rolloverVault.allocationCodehashOf(pool0), ethers.ZeroHash);
    assert.equal(await rolloverVault.allocationOf(pool1), 60n);
    assert.equal(await rolloverVault.totalAllocated(), 60n);
    assert.equal(await ethers.provider.getBalance(rootAddresses.rolloverVault), 60n);

    await advance(BigInt(input.problems[0].closeByTimestamp) - BigInt((await ethers.provider.getBlock("latest")).timestamp));
    await boards[0].contracts.ledger.connect(deployer).close();
    assert.equal(await boards[0].contracts.ledger.sponsorRefundsEnabled(), true);
    await rolloverVault.connect(deployer).reclaimZeroCreditSponsorRefund(pool0);
    assert.equal(await boards[0].contracts.pool.sponsorshipOf(rootAddresses.rolloverVault), 0n);
    assert.equal(await boards[0].contracts.pool.accountedBalance(), 0n);
    assert.equal(await ethers.provider.getBalance(rootAddresses.rolloverVault), 100n);
    await ethers.provider.send("hardhat_stopImpersonatingAccount", [rootAddresses.timelock]);
  });
});
