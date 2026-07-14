import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

const DAY = 24n * 60n * 60n;
const FUNDING_CAP = ethers.parseEther("100");

function findErrorData(value) {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string") return /^0x[0-9a-fA-F]+$/.test(value) ? value : undefined;
  if (typeof value !== "object") return undefined;
  if (typeof value.data === "string" && /^0x[0-9a-fA-F]+$/.test(value.data)) return value.data;
  for (const nested of [value.cause, value.error, value.info?.error]) {
    const data = findErrorData(nested);
    if (data !== undefined) return data;
  }
  return undefined;
}

async function expectCustomError(action, contract, errorName) {
  try {
    await action;
  } catch (error) {
    const data = findErrorData(error);
    if (data !== undefined) {
      assert.equal(contract.interface.parseError(data)?.name, errorName);
      return;
    }
    assert.match(String(error), new RegExp(errorName));
    return;
  }
  throw new Error(`expected ${errorName} revert`);
}

async function advanceTo(timestamp) {
  await ethers.provider.send("evm_setNextBlockTimestamp", [Number(timestamp)]);
  await ethers.provider.send("evm_mine", []);
}

async function deployFixture({ registry: sharedRegistry = null, problemId = 1 } = {}) {
  const [owner, treasury, sponsor, solver, recipient] = await ethers.getSigners();
  const latest = await ethers.provider.getBlock("latest");
  const earliestClose = BigInt(latest.timestamp) + 31n * DAY;
  const closeBy = BigInt(latest.timestamp) + 181n * DAY;

  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address, FUNDING_CAP);
  await pool.waitForDeployment();

  let registry = sharedRegistry;
  if (registry === null) {
    const Registry = await ethers.getContractFactory("MockProblemRegistry");
    registry = await Registry.deploy();
    await registry.waitForDeployment();
  }
  await registry.setProblem(problemId, await pool.getAddress(), true);

  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), owner.address);
  await vault.waitForDeployment();

  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasury.address, 250, earliestClose, closeBy
  );
  await ledger.waitForDeployment();
  await pool.setLedger(await ledger.getAddress());
  await pool.setRegistry(await registry.getAddress(), problemId);
  await ledger.setRolloverDestination(await vault.getAddress());

  const Manager = await ethers.getContractFactory("MockFundingArmed");
  const manager = await Manager.deploy(true);
  await manager.waitForDeployment();
  await pool.setSubmissionManager(await manager.getAddress());
  await ledger.setCreditRecorder(await manager.getAddress());

  const openedAt = await ethers.provider.getBlock("latest");
  const authorizationExpiresAt = BigInt(openedAt.timestamp) + 100n;
  await manager.setFundingAuthorizationExpiresAt(authorizationExpiresAt);
  await pool.setAcceptingFunds(true);

  return {
    owner,
    sponsor,
    solver,
    recipient,
    pool,
    ledger,
    manager,
    registry,
    closeBy,
    authorizationExpiresAt,
  };
}

async function exerciseFundingRoute(route) {
  const fixture = await deployFixture();
  const { pool, sponsor, recipient, authorizationExpiresAt } = fixture;

  await ethers.provider.send("evm_setNextBlockTimestamp", [Number(authorizationExpiresAt)]);
  if (route === "fund") {
    await pool.connect(sponsor).fund({ value: 1n });
  } else if (route === "fundFor") {
    await pool.connect(sponsor).fundFor(recipient.address, { value: 1n });
  } else {
    await sponsor.sendTransaction({ to: await pool.getAddress(), value: 1n });
  }
  assert.equal(await pool.funded(), 1n);

  await ethers.provider.send("evm_setNextBlockTimestamp", [Number(authorizationExpiresAt + 1n)]);
  const expiredAction = route === "fund"
    ? pool.connect(sponsor).fund({ value: 1n })
    : route === "fundFor"
      ? pool.connect(sponsor).fundFor(recipient.address, { value: 1n })
      : sponsor.sendTransaction({ to: await pool.getAddress(), value: 1n });
  await expectCustomError(expiredAction, pool, "P42_FUNDING_AUTHORIZATION_EXPIRED");
  assert.equal(await pool.funded(), 1n);
}

describe("P42 funding authorization expiry", function () {
  for (const route of ["fund", "fundFor", "receive"]) {
    it(`${route} accepts at the exact authorization boundary and rejects one second later`, async function () {
      await exerciseFundingRoute(route);
    });
  }

  it("rolls back a matured award when the destination authorization has expired", async function () {
    const source = await deployFixture();
    const funding = ethers.parseEther("10");
    await source.manager.setFundingAuthorizationExpiresAt(2n ** 64n - 1n);
    await source.pool.connect(source.sponsor).fund({ value: funding });
    await source.manager.recordCredit(await source.ledger.getAddress(), source.solver.address, 1);
    await advanceTo(source.closeBy);
    await source.ledger.close();

    const destination = await deployFixture({ registry: source.registry, problemId: 2 });
    await advanceTo(destination.authorizationExpiresAt + 1n);
    const claimableBefore = await source.ledger.claimable(source.solver.address);
    const sourceBalanceBefore = await source.pool.funded();

    await expectCustomError(
      source.pool.connect(source.solver).donateClaimToPool(await destination.pool.getAddress()),
      destination.pool,
      "P42_FUNDING_AUTHORIZATION_EXPIRED"
    );

    assert.equal(await source.ledger.claimable(source.solver.address), claimableBefore);
    assert.equal(await source.pool.funded(), sourceBalanceBefore);
    assert.equal(await source.pool.totalWinningsDonated(), 0n);
    assert.equal(await destination.pool.funded(), 0n);
    assert.equal(await destination.pool.sponsorshipOf(source.solver.address), 0n);
  });
});
