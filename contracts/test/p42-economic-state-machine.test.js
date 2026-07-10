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
  const Manager = await ethers.getContractFactory("MockFundingArmed");
  const manager = await Manager.deploy(true);
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
    for (const seed of [0x42, 0x153, 0x416, 0x5eed, 0xc0ffee, 0xdecaf]) {
      const pick = seeded(seed);
      const feeBps = [0n, 50n, 125n, 250n][pick(4)];
      const f = await deployFixture(feeBps);
      const model = new EconomicReference({
        feeBps,
        sponsors: f.sponsors.map((x) => x.address),
        solvers: f.solvers.map((x) => x.address)
      });
      const ledgerAddress = await f.ledger.getAddress();
      const zeroCredit = seed === 0x42;

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
        const action = pick(5);
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
          model.paused = !model.paused;
          await f.ledger.connect(f.owner).setPausedNewActions(model.paused);
        } else if (action === 3) {
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
      assert.equal(await succeeds(() => f.pool.connect(f.outsider).claimFees()), model.claimFees());
      if (model.forced > 0n) {
        const amount = 1n + BigInt(pick(Number(model.forced)));
        assert.equal(await succeeds(() => f.pool.connect(f.outsider).recoverForcedEth(amount)), model.recoverForced(amount));
      }
      await assertState(f, model);
    }
  });
});
