import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { EconomicReference, seeded } from "../test-support/economic-reference.js";

const { ethers } = await network.create();
const DAY = 86_400n;
const FUNDING_CAP = ethers.parseEther("100");

async function advanceTo(timestamp) {
  const block = await ethers.provider.getBlock("latest");
  const delta = timestamp - BigInt(block.timestamp);
  if (delta > 0n) {
    await ethers.provider.send("evm_increaseTime", [Number(delta)]);
    await ethers.provider.send("evm_mine", []);
  }
}

async function setNextTimestamp(timestamp) {
  await ethers.provider.send("evm_setNextBlockTimestamp", [Number(timestamp)]);
}

async function succeeds(action) {
  try {
    await action();
    return true;
  } catch {
    return false;
  }
}

async function deployFixture(feeBps) {
  const [owner, treasury, sponsorA, sponsorB, sponsorC, solverA, solverB, solverC, outsider] =
    await ethers.getSigners();
  const latest = await ethers.provider.getBlock("latest");
  const closeBy = BigInt(latest.timestamp) + 181n * DAY;
  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address, FUNDING_CAP);
  await pool.waitForDeployment();
  const Registry = await ethers.getContractFactory("MockProblemRegistry");
  const registry = await Registry.deploy();
  await registry.waitForDeployment();
  await registry.setProblem(1, await pool.getAddress(), true);
  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), owner.address);
  await vault.waitForDeployment();
  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasury.address, feeBps,
    BigInt(latest.timestamp) + 31n * DAY, closeBy
  );
  await ledger.waitForDeployment();
  const Manager = await ethers.getContractFactory("EconomicStateMachineRecorder");
  const manager = await Manager.deploy();
  await manager.waitForDeployment();
  await pool.setLedger(await ledger.getAddress());
  await pool.setRegistry(await registry.getAddress(), 1);
  await pool.setSubmissionManager(await manager.getAddress());
  await ledger.setCreditRecorder(await manager.getAddress());
  await ledger.setRolloverDestination(await vault.getAddress());
  await pool.setAcceptingFunds(true);
  return {
    owner, treasury, sponsors: [sponsorA, sponsorB, sponsorC], solvers: [solverA, solverB, solverC],
    outsider, pool, ledger, manager, vault, closeBy
  };
}

async function deployRealManagerFixture() {
  const [owner, treasury, solver, outsider] = await ethers.getSigners();
  const latest = await ethers.provider.getBlock("latest");
  const closeBy = BigInt(latest.timestamp) + 181n * DAY;
  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address, FUNDING_CAP);
  await pool.waitForDeployment();
  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasury.address, 0n,
    BigInt(latest.timestamp) + 31n * DAY, closeBy
  );
  await ledger.waitForDeployment();
  const Manager = await ethers.getContractFactory("P42SubmissionManager");
  const manager = await Manager.deploy(
    await pool.getAddress(), await ledger.getAddress(), owner.address, treasury.address,
    200n, 1n, DAY, false, 0n, 1_000_000n, 1n
  );
  await manager.waitForDeployment();
  const Registry = await ethers.getContractFactory("MockProblemRegistry");
  const registry = await Registry.deploy();
  await registry.waitForDeployment();
  await registry.setProblem(1, await pool.getAddress(), true);
  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), owner.address);
  await vault.waitForDeployment();
  await pool.setLedger(await ledger.getAddress());
  await pool.setRegistry(await registry.getAddress(), 1);
  await pool.setSubmissionManager(await manager.getAddress());
  await ledger.setCreditRecorder(await manager.getAddress());
  await ledger.setRolloverDestination(await vault.getAddress());
  return { owner, solver, outsider, pool, ledger, manager, closeBy };
}

async function assertState(f, model) {
  assert.equal(await f.pool.funded(), model.accounted);
  assert.equal(await f.pool.totalFunded(), model.totalFunded);
  assert.equal(await f.pool.totalClaimed(), model.totalClaimed);
  assert.equal(await f.pool.totalGrossClaimed(), model.totalGrossClaimed);
  assert.equal(await f.pool.totalFeeAccrued(), model.feeAccrued);
  assert.equal(await f.pool.totalFeePaid(), model.feePaid);
  assert.equal(await f.pool.accruedFeeBalance(), model.feeAccrued - model.feePaid);
  assert.equal(await f.pool.totalSponsorRefunded(), model.sponsorRefunded);
  assert.equal(await f.pool.totalRolloverPaid(), model.rolloverPaid);
  assert.equal(await f.pool.totalForcedEthRecovered(), model.forcedRecovered);
  assert.equal(await f.pool.forcedEthAvailable(), model.forced);
  assert.equal(await ethers.provider.getBalance(await f.pool.getAddress()), model.accounted + model.forced);
  assert.equal(
    await ethers.provider.getBalance(await f.vault.getAddress()),
    model.rolloverPaid + model.forcedRecovered
  );
  assert.equal(await f.ledger.closed(), model.closed);
  assert.equal(await f.ledger.pausedNewActions(), model.paused);
  assert.equal(await f.ledger.totalCreditAtoms(), model.totalCredit);
  assert.equal(await f.ledger.closedPoolBalance(), model.closedPoolBalance);
  assert.equal(await f.ledger.totalGrossClaimed(), model.totalGrossClaimed);
  assert.equal(await f.ledger.totalFeeAccrued(), model.feeAccrued);
  assert.equal(await f.ledger.rolloverSwept(), model.rolloverSwept);
  for (const sponsor of f.sponsors) {
    assert.equal(await f.pool.sponsorshipOf(sponsor.address), model.sponsorships.get(sponsor.address));
  }
  for (const solver of f.solvers) {
    const credit = model.credits.get(solver.address);
    assert.equal(await f.ledger.creditAtomsOf(solver.address), credit);
    assert.equal(await f.ledger.claimedWeiOf(solver.address), model.claimedGross.get(solver.address));
    if (model.closed && model.totalCredit > 0n) {
      assert.equal(await f.ledger.finalEntitlement(solver.address), model.closedPoolBalance * credit / model.totalCredit);
    }
  }
  assert.equal(
    model.totalFunded + model.totalForced,
    model.totalClaimed + model.feePaid + model.sponsorRefunded + model.rolloverPaid
      + model.forcedRecovered + model.accounted + model.forced
  );
}

describe("P42 economic state-machine differential", function () {
  it("matches the reference model across deterministic bounded sequences", async function () {
    const seeds = [0x42, 0x153, 0x416, 0x5eed, 0xc0ffee, 0xdecaf, 0xbadc0de, 0xfee250];
    for (const [seedIndex, seed] of seeds.entries()) {
      const pick = seeded(seed);
      const feeBps = [250n, 0n, 50n, 125n][seedIndex % 4];
      const f = await deployFixture(feeBps);
      const model = new EconomicReference({
        feeBps,
        sponsors: f.sponsors.map((x) => x.address),
        solvers: f.solvers.map((x) => x.address),
        fundingCap: FUNDING_CAP
      });
      const ledgerAddress = await f.ledger.getAddress();
      const zeroCredit = seedIndex < 2;

      for (const [index, sponsor] of f.sponsors.entries()) {
        const amount = BigInt(101 + index * 37);
        assert.equal(await succeeds(() => f.pool.connect(sponsor).fund({ value: amount })), model.fund(sponsor.address, amount));
      }
      if (!zeroCredit) {
        for (const [index, solver] of f.solvers.entries()) {
          const atoms = BigInt(index + 1);
          assert.equal(
            await succeeds(() => f.manager.recordCredit(ledgerAddress, solver.address, atoms)),
            model.recordCredit(solver.address, atoms)
          );
        }
      }
      const ForceEther = await ethers.getContractFactory("ForceEther");
      const initialForce = await ForceEther.deploy({ value: 7n });
      await initialForce.waitForDeployment();
      await initialForce.force(await f.pool.getAddress());
      model.force(7n);
      assert.equal(await succeeds(() => f.ledger.connect(f.outsider).close()), false);
      await assertState(f, model);

      for (let step = 0; step < 18; step += 1) {
        const action = pick(6);
        if (action === 0) {
          const sponsor = f.sponsors[pick(f.sponsors.length)];
          const amount = BigInt(1 + pick(10_000));
          assert.equal(await succeeds(() => f.pool.connect(sponsor).fund({ value: amount })), model.fund(sponsor.address, amount));
        } else if (action === 1) {
          const solver = f.solvers[pick(f.solvers.length)];
          const atoms = BigInt(1 + pick(100));
          if (!zeroCredit) {
            assert.equal(
              await succeeds(() => f.manager.recordCredit(ledgerAddress, solver.address, atoms)),
              model.recordCredit(solver.address, atoms)
            );
          }
        } else if (action === 2) {
          const solver = f.solvers[pick(f.solvers.length)];
          const available = model.credits.get(solver.address);
          const atoms = available === 0n ? 1n : 1n + BigInt(pick(Number(available)));
          assert.equal(
            await succeeds(() => f.manager.voidCredit(ledgerAddress, solver.address, atoms)),
            model.voidCredit(solver.address, atoms)
          );
        } else if (action === 3) {
          model.paused = !model.paused;
          await f.ledger.connect(f.owner).setPausedNewActions(model.paused);
        } else if (action === 4) {
          const amount = BigInt(1 + pick(100));
          const ForceEther = await ethers.getContractFactory("ForceEther");
          const force = await ForceEther.deploy({ value: amount });
          await force.waitForDeployment();
          await force.force(await f.pool.getAddress());
          model.force(amount);
        } else {
          assert.equal(await succeeds(() => f.ledger.connect(f.outsider).close()), false);
        }
        await assertState(f, model);
      }

      await advanceTo(f.closeBy);
      model.closeReady = true;
      assert.equal(await succeeds(() => f.ledger.connect(f.outsider).close()), model.close());
      await assertState(f, model);
      assert.equal(await succeeds(() => f.pool.connect(f.sponsors[0]).fund({ value: 1n })), false);
      assert.equal(
        await succeeds(() => f.manager.recordCredit(ledgerAddress, f.solvers[0].address, 1n)), false
      );

      const actors = [...f.sponsors, ...f.solvers];
      for (let step = 0; step < 14; step += 1) {
        const action = pick(4);
        if (action === 0) {
          const solver = f.solvers[pick(f.solvers.length)];
          assert.equal(await succeeds(() => f.pool.connect(solver).claim()), model.claim(solver.address));
        } else if (action === 1) {
          const sponsor = f.sponsors[pick(f.sponsors.length)];
          assert.equal(await succeeds(() => f.pool.connect(sponsor).sponsorRefund()), model.refund(sponsor.address));
        } else if (action === 2) {
          assert.equal(await succeeds(() => f.pool.connect(f.outsider).claimFees()), model.claimFees());
        } else {
          const amount = BigInt(1 + pick(100));
          const ForceEther = await ethers.getContractFactory("ForceEther");
          const force = await ForceEther.deploy({ value: amount });
          await force.waitForDeployment();
          await force.force(await f.pool.getAddress());
          model.force(amount);
        }
        await assertState(f, model);
      }

      if (zeroCredit) {
        for (const sponsor of f.sponsors) {
          assert.equal(await succeeds(() => f.pool.connect(sponsor).sponsorRefund()), model.refund(sponsor.address));
        }
      } else {
        const solver = f.solvers[pick(f.solvers.length)];
        assert.equal(await succeeds(() => f.pool.connect(solver).claim()), model.claim(solver.address));
        assert.equal(await succeeds(() => f.pool.connect(f.outsider).claimFees()), model.claimFees());
      }
      await assertState(f, model);

      await advanceTo(BigInt(await f.ledger.closedAt()) + BigInt(await f.ledger.CLAIM_DEADLINE_SECONDS()) + 1n);
      model.expired = true;
      for (const solver of f.solvers) {
        assert.equal(await succeeds(() => f.pool.connect(solver).claim()), false);
      }
      assert.equal(await succeeds(() => f.ledger.connect(actors[pick(actors.length)]).sweepRollover()), model.sweepRollover());
      assert.equal(await succeeds(() => f.ledger.connect(f.outsider).sweepRollover()), false);
      assert.equal(await succeeds(() => f.pool.connect(f.outsider).claimFees()), model.claimFees());
      if (model.forced > 0n) {
        const amount = 1n + BigInt(pick(Number(model.forced)));
        assert.equal(await succeeds(() => f.pool.connect(f.outsider).recoverForcedEth(amount)), model.recoverForced(amount));
      }
      await assertState(f, model);
    }
  });

  it("differentiates funding gates, cap behavior, and the exact funding deadline", async function () {
    const f = await deployFixture(250n);
    const model = new EconomicReference({
      feeBps: 250n,
      sponsors: f.sponsors.map((x) => x.address),
      solvers: f.solvers.map((x) => x.address),
      fundingCap: FUNDING_CAP
    });
    const sponsor = f.sponsors[0];

    assert.equal(await succeeds(() => f.pool.connect(sponsor).fund({ value: 0n })), model.fund(sponsor.address, 0n));
    await f.pool.connect(f.owner).setAcceptingFunds(false);
    model.acceptingFunds = false;
    assert.equal(await succeeds(() => f.pool.connect(sponsor).fund({ value: 1n })), model.fund(sponsor.address, 1n));
    await f.pool.connect(f.owner).setAcceptingFunds(true);
    model.acceptingFunds = true;
    await f.manager.setFundingArmed(false);
    model.fundingArmed = false;
    assert.equal(await succeeds(() => f.pool.connect(sponsor).fund({ value: 1n })), model.fund(sponsor.address, 1n));
    await f.manager.setFundingArmed(true);
    model.fundingArmed = true;
    assert.equal(
      await succeeds(() => f.pool.connect(sponsor).fund({ value: FUNDING_CAP })),
      model.fund(sponsor.address, FUNDING_CAP)
    );
    assert.equal(await succeeds(() => f.pool.connect(sponsor).fund({ value: 1n })), model.fund(sponsor.address, 1n));
    await assertState(f, model);

    const boundary = await deployFixture(250n);
    const boundaryModel = new EconomicReference({
      feeBps: 250n,
      sponsors: boundary.sponsors.map((x) => x.address),
      solvers: boundary.solvers.map((x) => x.address),
      fundingCap: FUNDING_CAP
    });
    const deadline = await boundary.ledger.fundingDeadline();
    await setNextTimestamp(deadline);
    assert.equal(
      await succeeds(() => boundary.pool.connect(boundary.sponsors[0]).fund({ value: 11n })),
      boundaryModel.fund(boundary.sponsors[0].address, 11n)
    );
    boundaryModel.fundingWindowOpen = false;
    await setNextTimestamp(deadline + 1n);
    assert.equal(
      await succeeds(() => boundary.pool.connect(boundary.sponsors[1]).fund({ value: 13n })),
      boundaryModel.fund(boundary.sponsors[1].address, 13n)
    );
    await assertState(boundary, boundaryModel);
  });

  it("tracks mutable denominators through valid, paused, and rejected voids", async function () {
    const f = await deployFixture(250n);
    const model = new EconomicReference({
      feeBps: 250n,
      sponsors: f.sponsors.map((x) => x.address),
      solvers: f.solvers.map((x) => x.address),
      fundingCap: FUNDING_CAP
    });
    const ledgerAddress = await f.ledger.getAddress();
    await f.pool.connect(f.sponsors[0]).fund({ value: 10_007n });
    model.fund(f.sponsors[0].address, 10_007n);
    for (const [solver, atoms] of [[f.solvers[0], 7n], [f.solvers[1], 11n], [f.solvers[2], 13n]]) {
      await f.manager.recordCredit(ledgerAddress, solver.address, atoms);
      model.recordCredit(solver.address, atoms);
    }
    await f.ledger.setPausedNewActions(true);
    model.paused = true;
    assert.equal(
      await succeeds(() => f.manager.voidCredit(ledgerAddress, f.solvers[1].address, 5n)),
      model.voidCredit(f.solvers[1].address, 5n)
    );
    assert.equal(
      await succeeds(() => f.manager.voidCredit(ledgerAddress, f.solvers[0].address, 8n)),
      model.voidCredit(f.solvers[0].address, 8n)
    );
    assert.equal(
      await succeeds(() => f.manager.recordCredit(ledgerAddress, f.solvers[0].address, 1n)),
      model.recordCredit(f.solvers[0].address, 1n)
    );
    await assertState(f, model);
    await advanceTo(f.closeBy);
    model.closeReady = true;
    assert.equal(await succeeds(() => f.ledger.close()), model.close());
    await assertState(f, model);
  });

  it("matches exact close and claim boundaries and rolls back invalid redirects", async function () {
    const f = await deployFixture(250n);
    const model = new EconomicReference({
      feeBps: 250n,
      sponsors: f.sponsors.map((x) => x.address),
      solvers: f.solvers.map((x) => x.address),
      fundingCap: FUNDING_CAP
    });
    const ledgerAddress = await f.ledger.getAddress();
    model.fund(f.sponsors[0].address, 10_003n);
    await f.pool.connect(f.sponsors[0]).fund({ value: 10_003n });
    for (const solver of f.solvers.slice(0, 2)) {
      model.recordCredit(solver.address, 1n);
      await f.manager.recordCredit(ledgerAddress, solver.address, 1n);
    }
    await setNextTimestamp(f.closeBy - 1n);
    assert.equal(await succeeds(() => f.ledger.close()), false);
    model.closeReady = true;
    await setNextTimestamp(f.closeBy);
    assert.equal(await succeeds(() => f.ledger.close()), model.close());

    assert.equal(await succeeds(() => f.pool.connect(f.solvers[0]).claimTo(ethers.ZeroAddress)), false);
    await assertState(f, model);
    const deadline = await f.ledger.claimDeadline();
    await setNextTimestamp(deadline);
    assert.equal(await succeeds(() => f.pool.connect(f.solvers[0]).claim()), model.claim(f.solvers[0].address));
    model.expired = true;
    await setNextTimestamp(deadline + 1n);
    assert.equal(await succeeds(() => f.pool.connect(f.solvers[1]).claim()), model.claim(f.solvers[1].address));
    assert.equal(await succeeds(() => f.ledger.sweepRollover()), model.sweepRollover());
    assert.equal(await succeeds(() => f.ledger.sweepRollover()), false);
    assert.equal(await succeeds(() => f.pool.claimFees()), model.claimFees());
    await assertState(f, model);
  });

  it("keeps failed zero-credit refund transfers atomic and permits redirect", async function () {
    const f = await deployFixture(0n);
    const RejectingSponsor = await ethers.getContractFactory("RejectingSponsor");
    const rejecting = await RejectingSponsor.deploy();
    await rejecting.waitForDeployment();
    const address = await rejecting.getAddress();
    const poolAddress = await f.pool.getAddress();
    f.sponsors.push({ address });
    const model = new EconomicReference({
      feeBps: 0n,
      sponsors: f.sponsors.map((x) => x.address),
      solvers: f.solvers.map((x) => x.address),
      fundingCap: FUNDING_CAP
    });
    await rejecting.fundPool(poolAddress, { value: 777n });
    model.fund(address, 777n);
    await advanceTo(f.closeBy);
    model.closeReady = true;
    await f.ledger.close();
    model.close();
    assert.equal(await succeeds(() => rejecting.refund(poolAddress)), false);
    await assertState(f, model);
    assert.equal(
      await succeeds(() => rejecting.refundTo(poolAddress, f.outsider.address)),
      model.refund(address)
    );
    await assertState(f, model);
  });

  it("differentiates close guards at their exact boundaries", async function () {
    const real = await deployRealManagerFixture();
    const realModel = new EconomicReference({
      feeBps: 0n,
      sponsors: [],
      solvers: []
    });
    const commitment = ethers.id("economic-state-machine-open-commit");
    await real.manager.connect(real.solver).commit(commitment, ethers.id("economic-state-machine-da"), { value: 1n });
    realModel.openSubmissions = 1;
    realModel.closeReady = true;
    await setNextTimestamp(real.closeBy);
    assert.equal(await succeeds(() => real.ledger.connect(real.outsider).close()), realModel.close());
    await real.manager.connect(real.outsider).expireCommitted(1n);
    realModel.openSubmissions = 0;
    await real.manager.connect(real.owner).setPausedAll(true);
    realModel.pausedAll = true;
    assert.equal(await succeeds(() => real.ledger.connect(real.outsider).close()), realModel.close());
    await real.manager.connect(real.owner).setPausedAll(false);
    realModel.pausedAll = false;
    assert.equal(await succeeds(() => real.ledger.connect(real.outsider).close()), realModel.close());
    assert.equal(await real.ledger.closed(), realModel.closed);

    const recovery = await deployFixture(0n);
    const recoveryModel = new EconomicReference({
      feeBps: 0n,
      sponsors: recovery.sponsors.map((x) => x.address),
      solvers: recovery.solvers.map((x) => x.address)
    });
    recoveryModel.closeReady = true;
    recoveryModel.recoveryWindowOpen = true;
    const recoveryEndsAt = recovery.closeBy + 100n;
    await recovery.manager.setCloseGuard(0n, false, recoveryEndsAt);
    await setNextTimestamp(recovery.closeBy);
    assert.equal(await succeeds(() => recovery.ledger.close()), recoveryModel.close());
    recoveryModel.recoveryWindowOpen = false;
    await setNextTimestamp(recoveryEndsAt);
    assert.equal(await succeeds(() => recovery.ledger.close()), recoveryModel.close());
    assert.equal(await recovery.ledger.closed(), recoveryModel.closed);
  });
});
