import assert from "node:assert/strict";
import { increaseTime as advanceTimeBy, advanceToTimestamp } from "../test-support/time.js";
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
  await advanceToTimestamp(ethers.provider, timestamp);
}

async function deployFixture({
  feeBps = 250,
  rejectingTreasury = false,
  configureRollover = true,
  registry: sharedRegistry = null,
  problemId = 1,
} = {}) {
  const [owner, treasury, alice, bob, recipient, outsider] = await ethers.getSigners();
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

  let treasuryAddress = treasury.address;
  if (rejectingTreasury) {
    const RejectingTreasury = await ethers.getContractFactory("RejectingTreasury");
    const receiver = await RejectingTreasury.deploy();
    await receiver.waitForDeployment();
    treasuryAddress = await receiver.getAddress();
  }

  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasuryAddress, feeBps, earliestClose, closeBy
  );
  await ledger.waitForDeployment();
  await pool.setLedger(await ledger.getAddress());
  await pool.setRegistry(await registry.getAddress(), problemId);
  if (configureRollover) await ledger.setRolloverDestination(await vault.getAddress());

  const Manager = await ethers.getContractFactory("MockFundingArmed");
  const manager = await Manager.deploy(true);
  await manager.waitForDeployment();
  await pool.setSubmissionManager(await manager.getAddress());
  await ledger.setCreditRecorder(await manager.getAddress());
  if (configureRollover) await pool.setAcceptingFunds(true);

  return { owner, treasury, alice, bob, recipient, outsider, pool, registry, vault, ledger, manager, closeBy };
}

describe("P42 sponsorship economics", function () {
  it("refuses to enable funding before the canonical rollover destination is bound", async function () {
    const fixture = await deployFixture({ configureRollover: false });
    await expectCustomError(
      fixture.pool.connect(fixture.owner).setAcceptingFunds(true),
      fixture.pool,
      "P42_ROLLOVER_DESTINATION_NOT_SET"
    );
    await fixture.ledger.connect(fixture.owner).setRolloverDestination(await fixture.vault.getAddress());
    await fixture.pool.connect(fixture.owner).setAcceptingFunds(true);
    assert.equal(await fixture.pool.acceptingFunds(), true);
  });

  it("rejects a marker-spoofing rollover destination with arbitrary withdrawal code", async function () {
    const [owner, treasury] = await ethers.getSigners();
    const latest = await ethers.provider.getBlock("latest");
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const pool = await Pool.deploy(owner.address, FUNDING_CAP);
    await pool.waitForDeployment();
    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const ledger = await Ledger.deploy(
      await pool.getAddress(),
      owner.address,
      treasury.address,
      0,
      BigInt(latest.timestamp) + 31n * DAY,
      BigInt(latest.timestamp) + 181n * DAY
    );
    await ledger.waitForDeployment();
    const Spoof = await ethers.getContractFactory("MarkerSpoofRolloverDestination");
    const spoof = await Spoof.deploy();
    await spoof.waitForDeployment();

    await expectCustomError(
      ledger.setRolloverDestination(await spoof.getAddress()),
      ledger,
      "P42_ROLLOVER_DESTINATION_INVALID"
    );
  });

  it("rejects a genuine vault bound to an attacker-controlled registry", async function () {
    const fixture = await deployFixture({ configureRollover: false });
    const Registry = await ethers.getContractFactory("MockProblemRegistry");
    const attackerRegistry = await Registry.deploy();
    await attackerRegistry.waitForDeployment();
    const Vault = await ethers.getContractFactory("P42RolloverVault");
    const attackerVault = await Vault.deploy(await attackerRegistry.getAddress(), fixture.owner.address);
    await attackerVault.waitForDeployment();

    await expectCustomError(
      fixture.ledger.setRolloverDestination(await attackerVault.getAddress()),
      fixture.ledger,
      "P42_ROLLOVER_REGISTRY_MISMATCH"
    );
    await fixture.ledger.setRolloverDestination(await fixture.vault.getAddress());
  });

  it("allows one permissionless close only at closeByTimestamp", async function () {
    const fixture = await deployFixture();
    await fixture.pool.connect(fixture.alice).fund({ value: 1n });

    await expectCustomError(
      fixture.ledger.setRolloverDestination(await fixture.vault.getAddress()),
      fixture.ledger,
      "P42_ROLLOVER_ALREADY_SET"
    );
    await expectCustomError(
      fixture.vault.connect(fixture.outsider).fundRegisteredPool(fixture.owner.address, 1n),
      fixture.vault,
      "P42_NOT_ALLOCATOR"
    );

    await expectCustomError(
      fixture.ledger.connect(fixture.owner).close(), fixture.ledger, "P42_CLOSE_BY_NOT_REACHED"
    );
    await advanceTo(fixture.closeBy);
    await fixture.ledger.connect(fixture.outsider).close();
    assert.equal(await fixture.ledger.closed(), true);
    await expectCustomError(fixture.ledger.close(), fixture.ledger, "P42_CLOSED");
  });

  it("returns each zero-credit sponsor's exact principal forever, with redirect support and no fee", async function () {
    const fixture = await deployFixture();
    await fixture.pool.connect(fixture.alice).fund({ value: ethers.parseEther("3") });
    await fixture.pool.connect(fixture.bob).fund({ value: ethers.parseEther("2") });
    await advanceTo(fixture.closeBy);
    await fixture.ledger.connect(fixture.outsider).close();

    assert.equal(await fixture.ledger.sponsorRefundsEnabled(), true);
    assert.equal(await fixture.ledger.claimDeadline(), 0n);
    const recipientBefore = await ethers.provider.getBalance(fixture.recipient.address);
    await fixture.pool.connect(fixture.alice).sponsorRefundTo(fixture.recipient.address);
    assert.equal(
      (await ethers.provider.getBalance(fixture.recipient.address)) - recipientBefore,
      ethers.parseEther("3")
    );

    await advanceTimeBy(ethers.provider, 2n * 365n * DAY);
    await fixture.pool.connect(fixture.bob).sponsorRefund();
    assert.equal(await fixture.pool.sponsorshipOf(fixture.alice.address), 0n);
    assert.equal(await fixture.pool.sponsorshipOf(fixture.bob.address), 0n);
    assert.equal(await fixture.pool.totalSponsorRefunded(), ethers.parseEther("5"));
    assert.equal(await fixture.pool.totalFeePaid(), 0n);
    assert.equal(await fixture.pool.funded(), 0n);
    await expectCustomError(fixture.ledger.sweepRollover(), fixture.ledger, "P42_ROLLOVER_NOT_AVAILABLE");
  });

  it("prevents sponsor-refund reentrancy and lets a rejecting sponsor redirect its principal", async function () {
    const fixture = await deployFixture();
    const ReentrantSponsor = await ethers.getContractFactory("ReentrantSponsor");
    const reentrant = await ReentrantSponsor.deploy();
    await reentrant.waitForDeployment();
    const RejectingSponsor = await ethers.getContractFactory("RejectingSponsor");
    const rejecting = await RejectingSponsor.deploy();
    await rejecting.waitForDeployment();
    await reentrant.fundPool(await fixture.pool.getAddress(), { value: 7n });
    await rejecting.fundPool(await fixture.pool.getAddress(), { value: 11n });
    await advanceTo(fixture.closeBy);
    await fixture.ledger.close();

    await reentrant.refund(await fixture.pool.getAddress());
    assert.equal(await reentrant.reentryAttempted(), true);
    assert.equal(await fixture.pool.sponsorshipOf(await reentrant.getAddress()), 0n);
    await expectCustomError(rejecting.refund(await fixture.pool.getAddress()), fixture.pool, "P42_TRANSFER_FAILED");
    assert.equal(await fixture.pool.sponsorshipOf(await rejecting.getAddress()), 11n);
    const recipientBefore = await ethers.provider.getBalance(fixture.recipient.address);
    await rejecting.refundTo(await fixture.pool.getAddress(), fixture.recipient.address);
    assert.equal((await ethers.provider.getBalance(fixture.recipient.address)) - recipientBefore, 11n);
    assert.equal(await fixture.pool.funded(), 0n);
  });

  it("settles a positive-credit claim as gross entitlement minus an atomic per-claim fee", async function () {
    const fixture = await deployFixture();
    const funding = ethers.parseEther("10");
    await fixture.pool.connect(fixture.alice).fund({ value: funding });
    await fixture.manager.recordCredit(await fixture.ledger.getAddress(), fixture.bob.address, 1);
    await advanceTo(fixture.closeBy);
    await fixture.ledger.connect(fixture.outsider).close();

    assert.equal(await fixture.ledger.finalEntitlement(fixture.bob.address), funding);
    await expectCustomError(
      fixture.pool.connect(fixture.alice).sponsorRefund(), fixture.pool, "P42_SPONSOR_REFUNDS_DISABLED"
    );
    const solverBefore = await ethers.provider.getBalance(fixture.recipient.address);
    await fixture.pool.connect(fixture.bob).claimTo(fixture.recipient.address);
    const fee = funding * 250n / 10_000n;
    assert.equal((await ethers.provider.getBalance(fixture.recipient.address)) - solverBefore, funding - fee);
    assert.equal(await fixture.pool.accruedFeeBalance(), fee);
    assert.equal(await fixture.pool.totalGrossClaimed(), funding);
    assert.equal(await fixture.pool.totalClaimed(), funding - fee);
    assert.equal(await fixture.pool.totalFeeAccrued(), fee);
    assert.equal(await fixture.pool.totalFeePaid(), 0n);
    assert.equal(await fixture.ledger.totalFeeAccrued(), fee);
    assert.equal(await fixture.pool.funded(), fee);
    const treasuryBefore = await ethers.provider.getBalance(fixture.treasury.address);
    await fixture.pool.connect(fixture.outsider).claimFees();
    assert.equal((await ethers.provider.getBalance(fixture.treasury.address)) - treasuryBefore, fee);
    assert.equal(await fixture.pool.totalFeePaid(), fee);
    assert.equal(await fixture.pool.funded(), 0n);
    await expectCustomError(fixture.ledger.sweepFee(), fixture.ledger, "P42_FEE_CLAIM_ONLY");
  });

  it("lets a crowned solver atomically donate matured winnings to another active pool", async function () {
    const source = await deployFixture();
    const funding = ethers.parseEther("10");
    await source.pool.connect(source.alice).fund({ value: funding });
    await source.manager.recordCredit(await source.ledger.getAddress(), source.bob.address, 1);
    await advanceTo(source.closeBy);
    await source.ledger.close();

    const destination = await deployFixture({ registry: source.registry, problemId: 2 });
    const fee = funding * 250n / 10_000n;
    const donated = funding - fee;
    await source.pool.connect(source.bob).donateClaimToPool(await destination.pool.getAddress());

    assert.equal(await source.ledger.claimable(source.bob.address), 0n);
    assert.equal(await source.pool.totalWinningsDonated(), donated);
    assert.equal(await source.pool.totalClaimed(), donated);
    assert.equal(await source.pool.accruedFeeBalance(), fee);
    assert.equal(await destination.pool.funded(), donated);
    assert.equal(await destination.pool.sponsorshipOf(source.bob.address), donated);
    await expectCustomError(
      source.pool.connect(source.bob).donateClaimToPool(await destination.pool.getAddress()),
      source.pool,
      "P42_NOTHING_TO_CLAIM"
    );
  });

  it("rejects a cross-registry donation pool without consuming the solver claim", async function () {
    const source = await deployFixture();
    const funding = ethers.parseEther("10");
    await source.pool.connect(source.alice).fund({ value: funding });
    await source.manager.recordCredit(await source.ledger.getAddress(), source.bob.address, 1);
    await advanceTo(source.closeBy);
    await source.ledger.close();

    const impostor = await deployFixture();
    await expectCustomError(
      source.pool.connect(source.bob).donateClaimToPool(await impostor.pool.getAddress()),
      source.pool,
      "P42_INVALID_DONATION_POOL"
    );
    assert.equal(await source.ledger.claimable(source.bob.address), funding);
    assert.equal(await source.pool.totalWinningsDonated(), 0n);
  });

  it("does not let a rejecting treasury veto a solver and permits treasury redirection", async function () {
    const fixture = await deployFixture({ rejectingTreasury: true });
    const funding = ethers.parseEther("1");
    await fixture.pool.connect(fixture.alice).fund({ value: funding });
    await fixture.manager.recordCredit(await fixture.ledger.getAddress(), fixture.bob.address, 1);
    await advanceTo(fixture.closeBy);
    await fixture.ledger.close();

    await fixture.pool.connect(fixture.bob).claim();
    const fee = funding * 250n / 10_000n;
    assert.equal(await fixture.ledger.claimedWeiOf(fixture.bob.address), funding);
    assert.equal(await fixture.ledger.totalFeeAccrued(), fee);
    assert.equal(await fixture.pool.totalClaimed(), funding - fee);
    assert.equal(await fixture.pool.totalFeePaid(), 0n);
    assert.equal(await fixture.pool.funded(), fee);
    await expectCustomError(fixture.pool.claimFees(), fixture.pool, "P42_TRANSFER_FAILED");
    const recipientBefore = await ethers.provider.getBalance(fixture.recipient.address);
    const rejectingTreasury = await ethers.getContractAt("RejectingTreasury", await fixture.ledger.treasury());
    await rejectingTreasury.claimFeesTo(await fixture.pool.getAddress(), fixture.recipient.address);
    assert.equal((await ethers.provider.getBalance(fixture.recipient.address)) - recipientBefore, fee);
    assert.equal(await fixture.pool.funded(), 0n);
  });

  it("sends only accounted dust and expired awards to rollover, leaving forced ETH explicitly recoverable", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    await fixture.pool.connect(fixture.alice).fund({ value: 101n });
    await fixture.manager.recordCredit(await fixture.ledger.getAddress(), fixture.alice.address, 1);
    await fixture.manager.recordCredit(await fixture.ledger.getAddress(), fixture.bob.address, 2);
    const ForceEther = await ethers.getContractFactory("ForceEther");
    const forceEther = await ForceEther.deploy({ value: 7n });
    await forceEther.waitForDeployment();
    await forceEther.force(await fixture.pool.getAddress());
    await expectCustomError(
      fixture.pool.connect(fixture.owner).recoverForcedEth(7n),
      fixture.pool,
      "P42_FORCED_ETH_RECOVERY_NOT_CLOSED"
    );
    await advanceTo(fixture.closeBy);
    await fixture.ledger.close();

    await fixture.pool.connect(fixture.alice).claim();
    assert.equal(await fixture.ledger.finalEntitlement(fixture.alice.address), 33n);
    assert.equal(await fixture.ledger.finalEntitlement(fixture.bob.address), 67n);

    assert.equal(await fixture.pool.forcedEthAvailable(), 7n);

    await advanceTimeBy(ethers.provider, (await fixture.ledger.CLAIM_DEADLINE_SECONDS()) + 1n);
    const vaultBefore = await ethers.provider.getBalance(await fixture.vault.getAddress());
    await fixture.ledger.connect(fixture.outsider).sweepRollover();
    // 67 wei expired entitlement plus 1 wei floor dust; the forced 7 wei stays put.
    assert.equal((await ethers.provider.getBalance(await fixture.vault.getAddress())) - vaultBefore, 68n);
    assert.equal(await fixture.pool.totalRolloverPaid(), 68n);
    assert.equal(await fixture.pool.funded(), 0n);
    assert.equal(await fixture.pool.forcedEthAvailable(), 7n);
    const vaultBeforeForcedRecovery = await ethers.provider.getBalance(await fixture.vault.getAddress());
    await fixture.pool.connect(fixture.alice).recoverForcedEth(7n);
    assert.equal((await ethers.provider.getBalance(await fixture.vault.getAddress())) - vaultBeforeForcedRecovery, 7n);
    assert.equal(await fixture.pool.forcedEthAvailable(), 0n);
    assert.equal(await ethers.provider.getBalance(await fixture.pool.getAddress()), 0n);
  });

  it("reconstructs multi-sponsor, multi-solver, fee, rollover, and forced-ETH conservation", async function () {
    const fixture = await deployFixture();
    await fixture.pool.connect(fixture.alice).fund({ value: 4_001n });
    await fixture.pool.connect(fixture.bob).fund({ value: 6_002n });
    await fixture.manager.recordCredit(await fixture.ledger.getAddress(), fixture.recipient.address, 1);
    await fixture.manager.recordCredit(await fixture.ledger.getAddress(), fixture.outsider.address, 2);
    await advanceTo(fixture.closeBy);
    await fixture.ledger.close();
    assert.equal(await fixture.ledger.finalEntitlement(fixture.recipient.address), 3_334n);
    assert.equal(await fixture.ledger.finalEntitlement(fixture.outsider.address), 6_668n);
    await fixture.pool.connect(fixture.recipient).claim();
    await fixture.pool.connect(fixture.outsider).claim();
    await fixture.pool.claimFees();

    const ForceEther = await ethers.getContractFactory("ForceEther");
    const forceEther = await ForceEther.deploy({ value: 7n });
    await forceEther.waitForDeployment();
    await forceEther.force(await fixture.pool.getAddress());
    await advanceTimeBy(ethers.provider, (await fixture.ledger.CLAIM_DEADLINE_SECONDS()) + 1n);
    const vaultBefore = await ethers.provider.getBalance(await fixture.vault.getAddress());
    await fixture.ledger.sweepRollover();
    await fixture.pool.connect(fixture.alice).recoverForcedEth(7n);

    assert.equal(await fixture.pool.totalFunded(), 10_003n);
    assert.equal(await fixture.pool.totalGrossClaimed(), 10_002n);
    assert.equal(await fixture.pool.totalClaimed(), 9_753n);
    assert.equal(await fixture.pool.totalFeePaid(), 249n);
    assert.equal(await fixture.pool.totalRolloverPaid(), 1n);
    assert.equal(await fixture.pool.totalForcedEthRecovered(), 7n);
    assert.equal(await fixture.pool.funded(), 0n);
    assert.equal(await fixture.pool.forcedEthAvailable(), 0n);
    assert.equal((await ethers.provider.getBalance(await fixture.vault.getAddress())) - vaultBefore, 8n);
    assert.equal(await fixture.pool.sponsorshipOf(fixture.alice.address), 4_001n);
    assert.equal(await fixture.pool.sponsorshipOf(fixture.bob.address), 6_002n);
  });
});
