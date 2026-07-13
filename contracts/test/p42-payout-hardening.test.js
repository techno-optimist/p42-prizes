import assert from "node:assert/strict";
import { increaseTime as advanceTimeBy } from "../test-support/time.js";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

const FUNDING_CAP = ethers.parseEther("100");
const MIN_COMPETITION_SECONDS = 30n * 24n * 60n * 60n;
const MIN_CLOSE_DELAY_SECONDS = 180n * 24n * 60n * 60n;

function findErrorData(value) {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string") return /^0x[0-9a-fA-F]+$/.test(value) ? value : undefined;
  if (typeof value !== "object") return undefined;
  if (typeof value.data === "string" && /^0x[0-9a-fA-F]+$/.test(value.data)) return value.data;
  if (typeof value.error?.data === "string") return value.error.data;
  if (typeof value.info?.error?.data === "string") return value.info.error.data;
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

async function increaseTime(seconds) {
  await advanceTimeBy(ethers.provider, seconds);
}

async function advanceTo(timestamp) {
  const latest = await ethers.provider.getBlock("latest");
  const remaining = timestamp - BigInt(latest.timestamp);
  if (remaining > 0n) await increaseTime(remaining);
}

async function deployFixture({ setRecorder = true, activateFunding = true } = {}) {
  const [owner, treasury, solver, recipient, caller] = await ethers.getSigners();
  const latest = await ethers.provider.getBlock("latest");
  const earliestClose = BigInt(latest.timestamp) + MIN_COMPETITION_SECONDS + 1_000n;
  const closeBy = BigInt(latest.timestamp) + MIN_CLOSE_DELAY_SECONDS + 1_000n;

  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address, FUNDING_CAP);
  await pool.waitForDeployment();

  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasury.address, 0, earliestClose, closeBy
  );
  await ledger.waitForDeployment();
  await pool.connect(owner).setLedger(await ledger.getAddress());

  const SubmissionManager = await ethers.getContractFactory("MockFundingArmed");
  const submissionManager = await SubmissionManager.deploy(true);
  await submissionManager.waitForDeployment();
  await pool.connect(owner).setSubmissionManager(await submissionManager.getAddress());

  const Registry = await ethers.getContractFactory("MockProblemRegistry");
  const registry = await Registry.deploy();
  await registry.waitForDeployment();
  await registry.setProblem(1, await pool.getAddress(), true);
  await pool.connect(owner).setRegistry(await registry.getAddress(), 1);
  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), owner.address);
  await vault.waitForDeployment();
  await ledger.connect(owner).setRolloverDestination(await vault.getAddress());

  if (setRecorder) {
    await ledger.connect(owner).setCreditRecorder(await submissionManager.getAddress());
  }
  if (activateFunding) {
    await pool.connect(owner).setAcceptingFunds(true);
  }

  return { owner, treasury, solver, recipient, caller, pool, ledger, submissionManager, vault };
}

async function closeWithCredit(fixture, solverAddress, funding = ethers.parseEther("10")) {
  const { owner, pool, ledger, submissionManager } = fixture;
  await pool.connect(owner).fund({ value: funding });
  await submissionManager.recordCredit(await ledger.getAddress(), solverAddress, 1);
  await advanceTo(await ledger.closeByTimestamp());
  await ledger.connect(owner).close();
  return funding;
}

describe("P42 payout hardening", function () {
  it("refuses funding activation when the credit recorder differs from the submission manager", async function () {
    const fixture = await deployFixture({ setRecorder: false, activateFunding: false });
    const OtherManager = await ethers.getContractFactory("MockFundingArmed");
    const otherManager = await OtherManager.deploy(true);
    await otherManager.waitForDeployment();
    await fixture.ledger.connect(fixture.owner).setCreditRecorder(await otherManager.getAddress());

    await expectCustomError(
      fixture.pool.connect(fixture.owner).setAcceptingFunds(true),
      fixture.pool,
      "P42_CREDIT_RECORDER_MISMATCH"
    );
    assert.equal(await fixture.pool.acceptingFunds(), false);
  });

  it("opens funding when the credit recorder and submission manager match", async function () {
    const fixture = await deployFixture({ activateFunding: false });
    assert.equal(
      await fixture.ledger.creditRecorder(),
      await fixture.submissionManager.getAddress()
    );

    await fixture.pool.connect(fixture.owner).setAcceptingFunds(true);
    await fixture.pool.connect(fixture.caller).fund({ value: ethers.parseEther("1") });
    assert.equal(await fixture.pool.totalFunded(), ethers.parseEther("1"));
  });

  it("lets a rejecting solver redirect exactly its entitlement with claimTo", async function () {
    const fixture = await deployFixture();
    const RejectingSolver = await ethers.getContractFactory("RejectingPayoutSolver");
    const rejectingSolver = await RejectingSolver.deploy();
    await rejectingSolver.waitForDeployment();
    const solverAddress = await rejectingSolver.getAddress();

    await closeWithCredit(fixture, solverAddress);
    const entitlement = await fixture.ledger.finalEntitlement(solverAddress);
    assert.equal(entitlement, ethers.parseEther("10"));

    await expectCustomError(
      rejectingSolver.claimTo(await fixture.pool.getAddress(), ethers.ZeroAddress),
      fixture.pool,
      "P42_RECIPIENT_ZERO"
    );
    assert.equal(await fixture.ledger.claimable(solverAddress), entitlement);

    await expectCustomError(
      rejectingSolver.claim(await fixture.pool.getAddress()),
      fixture.pool,
      "P42_TRANSFER_FAILED"
    );
    assert.equal(await fixture.ledger.claimable(solverAddress), entitlement);

    const recipientBefore = await ethers.provider.getBalance(fixture.recipient.address);
    const claimTx = await rejectingSolver.claimTo(await fixture.pool.getAddress(), fixture.recipient.address);
    const claimReceipt = await claimTx.wait();
    const claimedTo = claimReceipt.logs
      .map((log) => {
        try {
          return fixture.pool.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed?.name === "ClaimedTo");
    assert.ok(claimedTo, "ClaimedTo event present");
    assert.equal(claimedTo.args.solver, solverAddress);
    assert.equal(claimedTo.args.recipient, fixture.recipient.address);
    assert.equal(claimedTo.args.amount, entitlement);
    assert.equal((await ethers.provider.getBalance(fixture.recipient.address)) - recipientBefore, entitlement);
    assert.equal(await fixture.ledger.claimedWeiOf(solverAddress), entitlement);
    assert.equal(await fixture.ledger.claimable(solverAddress), 0n);
    assert.equal(await fixture.pool.totalClaimed(), entitlement);
  });

  it("hides expired claims while consumeClaim remains expired", async function () {
    const fixture = await deployFixture();
    await closeWithCredit(fixture, fixture.solver.address);
    const entitlement = await fixture.ledger.finalEntitlement(fixture.solver.address);
    assert.equal(await fixture.ledger.claimable(fixture.solver.address), entitlement);

    await increaseTime((await fixture.ledger.CLAIM_DEADLINE_SECONDS()) + 1n);
    assert.equal(await fixture.ledger.claimable(fixture.solver.address), 0n);
    await expectCustomError(
      fixture.pool.connect(fixture.solver).claim(),
      fixture.ledger,
      "P42_CLAIMS_EXPIRED"
    );
    assert.equal(await fixture.ledger.claimedWeiOf(fixture.solver.address), 0n);
  });

  it("keeps forced ETH outside rollover accounting and recovers it explicitly", async function () {
    const fixture = await deployFixture();
    const funding = await closeWithCredit(fixture, fixture.solver.address);
    const entitlement = await fixture.ledger.finalEntitlement(fixture.solver.address);

    await increaseTime((await fixture.ledger.CLAIM_DEADLINE_SECONDS()) + 1n);
    const vaultBeforeFirstSweep = await ethers.provider.getBalance(await fixture.vault.getAddress());
    await fixture.ledger.connect(fixture.caller).sweepResidual();
    assert.equal(
      (await ethers.provider.getBalance(await fixture.vault.getAddress())) - vaultBeforeFirstSweep,
      funding
    );
    assert.equal(await ethers.provider.getBalance(await fixture.pool.getAddress()), 0n);
    assert.equal(await fixture.pool.funded(), 0n);

    const forcedAmount = ethers.parseEther("2");
    const ForceEther = await ethers.getContractFactory("ForceEther");
    const forceEther = await ForceEther.deploy({ value: forcedAmount });
    await forceEther.waitForDeployment();
    await forceEther.force(await fixture.pool.getAddress());

    assert.equal(await ethers.provider.getBalance(await fixture.pool.getAddress()), forcedAmount);
    assert.equal(await fixture.pool.funded(), 0n);
    assert.equal(await fixture.pool.totalFunded(), funding);
    assert.equal(await fixture.ledger.closedPoolBalance(), funding);
    assert.equal(await fixture.ledger.finalEntitlement(fixture.solver.address), entitlement);
    assert.equal(await fixture.ledger.claimable(fixture.solver.address), 0n);

    await expectCustomError(
      fixture.ledger.connect(fixture.caller).sweepResidual(),
      fixture.ledger,
      "P42_ROLLOVER_ALREADY_SWEPT"
    );
    const vaultBeforeForcedRecovery = await ethers.provider.getBalance(await fixture.vault.getAddress());
    await fixture.pool.connect(fixture.owner).recoverForcedEth(forcedAmount);
    assert.equal(
      (await ethers.provider.getBalance(await fixture.vault.getAddress())) - vaultBeforeForcedRecovery,
      forcedAmount
    );
    assert.equal(await ethers.provider.getBalance(await fixture.pool.getAddress()), 0n);
    assert.equal(await fixture.pool.totalResidualPaid(), funding);
    assert.equal(await fixture.ledger.residualSwept(), true);
    await expectCustomError(
      fixture.ledger.connect(fixture.caller).sweepResidual(),
      fixture.ledger,
      "P42_ROLLOVER_ALREADY_SWEPT"
    );
  });
});
