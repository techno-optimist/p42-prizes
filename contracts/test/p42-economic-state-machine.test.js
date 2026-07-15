import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { EconomicReference, seeded } from "../test-support/economic-reference.js";

const { ethers } = await network.create();
const DAY = 86_400n;
const FUNDING_CAP = ethers.parseEther("100");
const STATEFUL_SEED_COUNT = 100;
const PRE_CLOSE_STEPS = 100;
const POST_CLOSE_STEPS = 50;

function statefulSeeds() {
  const fixed = [0x42, 0x153, 0x416, 0x5eed, 0xc0ffee, 0xdecaf, 0xbadc0de, 0xfee250];
  const generated = Array.from(
    { length: STATEFUL_SEED_COUNT - fixed.length },
    (_, index) => (0x9e3779b1 * (index + 1)) >>> 0
  );
  return [...fixed, ...generated];
}

function tracedFailure(error, seed, trace) {
  const detail = `stateful seed=${seed}; actions=${JSON.stringify(trace)}`;
  if (error instanceof Error) {
    error.message = `${error.message}\n${detail}`;
    return error;
  }
  return new Error(`${String(error)}\n${detail}`);
}

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
  const [owner, treasury, solver, outsider, productionLaunch, independentSecurity, governance] = await ethers.getSigners();
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
  const manager = await Manager.deploy({
    pool: await pool.getAddress(), ledger: await ledger.getAddress(), owner: owner.address,
    treasury: treasury.address, alphaBps: 200n, minPostingBondWei: 1n,
    challengeWindowSeconds: DAY, onchainDa: false, maxSolutionBytes: 0n,
    seedScoreAtoms: 1_000_000n, minImprovementAtoms: 1n,
  }, {
    boardSetDigest: ethers.id("economic-state-machine-board-set"),
    releaseBindingDigest: ethers.id("economic-state-machine-release"),
    productionLaunchAuthority: productionLaunch.address,
    independentSecurityAuthority: independentSecurity.address,
    governanceAuthority: governance.address,
  });
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

async function assertChainConservation(f) {
  const poolAddress = await f.pool.getAddress();
  const rawBalance = await ethers.provider.getBalance(poolAddress);
  const accounted = await f.pool.accountedBalance();
  const forced = await f.pool.forcedEthAvailable();
  const forcedRecovered = await f.pool.totalForcedEthRecovered();
  assert.equal(rawBalance, accounted + forced, "raw balance must separate accounted and forced ETH");
  assert.equal(
    await f.pool.totalFunded() + forced + forcedRecovered,
    await f.pool.totalClaimed() + await f.pool.totalFeePaid()
      + await f.pool.totalSponsorRefunded() + await f.pool.totalRolloverPaid()
      + forcedRecovered + accounted + forced,
    "on-chain cumulative inflows and outflows must conserve"
  );

  if (!await f.ledger.closed()) {
    assert.equal(accounted, await f.pool.totalFunded(), "open accounted balance is unresolved escrow");
    return;
  }

  const totalCredit = await f.ledger.totalCreditAtoms();
  if (totalCredit === 0n) {
    let sponsorPrincipal = 0n;
    for (const sponsor of f.sponsors) sponsorPrincipal += await f.pool.sponsorshipOf(sponsor.address);
    assert.equal(accounted, sponsorPrincipal, "zero-credit balance is remaining sponsor principal");
    return;
  }

  const accruedFees = await f.pool.accruedFeeBalance();
  if (await f.ledger.rolloverSwept()) {
    assert.equal(accounted, accruedFees, "post-rollover balance is accrued protocol fees only");
    return;
  }

  let entitlementTotal = 0n;
  let unclaimedGross = 0n;
  for (const solver of f.solvers) {
    const entitlement = await f.ledger.finalEntitlement(solver.address);
    const claimed = await f.ledger.claimedWeiOf(solver.address);
    entitlementTotal += entitlement;
    unclaimedGross += entitlement - claimed;
  }
  const roundingDust = await f.ledger.closedPoolBalance() - entitlementTotal;
  assert.equal(
    accounted,
    unclaimedGross + accruedFees + roundingDust,
    "closed balance must equal outstanding awards, fees, and rounding dust"
  );
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
  await assertChainConservation(f);
}

describe("P42 economic state-machine differential", function () {
  it("matches the reference model across deterministic bounded sequences", async function () {
    const seeds = statefulSeeds();
    const coverage = {
      attempted: 0,
      successful: 0,
      pausedClaims: 0,
      duplicateClaimRejections: 0,
      sponsorRefunds: 0,
      duplicateRefundRejections: 0,
      forcedRecoveryRejections: 0,
      forcedRecoveries: 0
    };
    assert.equal(seeds.length, STATEFUL_SEED_COUNT);
    assert.equal(new Set(seeds).size, STATEFUL_SEED_COUNT);
    for (const [seedIndex, seed] of seeds.entries()) {
      const trace = [];
      try {
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
      const zeroCredit = seedIndex % 4 === 0;

      for (const [index, sponsor] of f.sponsors.entries()) {
        const amount = BigInt(101 + index * 37);
        trace.push(["fund-initial", index, amount.toString()]);
        assert.equal(await succeeds(() => f.pool.connect(sponsor).fund({ value: amount })), model.fund(sponsor.address, amount));
      }
      if (!zeroCredit) {
        for (const [index, solver] of f.solvers.entries()) {
          const atoms = BigInt(index + 1);
          trace.push(["credit-initial", index, atoms.toString()]);
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
      trace.push(["force-initial", "7"]);
      assert.equal(await succeeds(() => f.ledger.connect(f.outsider).close()), false);
      trace.push(["close-early"]);
      await assertState(f, model);

      for (let step = 0; step < PRE_CLOSE_STEPS; step += 1) {
        coverage.attempted += 1;
        const action = pick(6);
        if (action === 0) {
          const sponsorIndex = pick(f.sponsors.length);
          const sponsor = f.sponsors[sponsorIndex];
          const amount = BigInt(1 + pick(10_000));
          trace.push(["fund", sponsorIndex, amount.toString()]);
          const actual = await succeeds(() => f.pool.connect(sponsor).fund({ value: amount }));
          assert.equal(actual, model.fund(sponsor.address, amount));
          if (actual) coverage.successful += 1;
        } else if (action === 1) {
          const solverIndex = pick(f.solvers.length);
          const solver = f.solvers[solverIndex];
          const atoms = BigInt(1 + pick(100));
          trace.push(["credit", solverIndex, atoms.toString(), !zeroCredit]);
          if (!zeroCredit) {
            const actual = await succeeds(() => f.manager.recordCredit(ledgerAddress, solver.address, atoms));
            assert.equal(actual, model.recordCredit(solver.address, atoms));
            if (actual) coverage.successful += 1;
          }
        } else if (action === 2) {
          const solverIndex = pick(f.solvers.length);
          const solver = f.solvers[solverIndex];
          const available = model.credits.get(solver.address);
          const atoms = available === 0n ? 1n : 1n + BigInt(pick(Number(available)));
          trace.push(["void", solverIndex, atoms.toString()]);
          const actual = await succeeds(() => f.manager.voidCredit(ledgerAddress, solver.address, atoms));
          assert.equal(actual, model.voidCredit(solver.address, atoms));
          if (actual) coverage.successful += 1;
        } else if (action === 3) {
          model.paused = !model.paused;
          trace.push(["pause", model.paused]);
          await f.ledger.connect(f.owner).setPausedNewActions(model.paused);
          coverage.successful += 1;
        } else if (action === 4) {
          const amount = BigInt(1 + pick(100));
          trace.push(["force", amount.toString()]);
          const ForceEther = await ethers.getContractFactory("ForceEther");
          const force = await ForceEther.deploy({ value: amount });
          await force.waitForDeployment();
          await force.force(await f.pool.getAddress());
          model.force(amount);
          coverage.successful += 1;
        } else {
          trace.push(["close-early"]);
          assert.equal(await succeeds(() => f.ledger.connect(f.outsider).close()), false);
        }
        await assertState(f, model);
      }

      await advanceTo(f.closeBy);
      model.closeReady = true;
      if (!zeroCredit && model.totalCredit === 0n) {
        if (model.paused) {
          await f.ledger.connect(f.owner).setPausedNewActions(false);
          model.paused = false;
        }
        const solver = f.solvers[0];
        assert.equal(await succeeds(() => f.manager.recordCredit(ledgerAddress, solver.address, 1n)), true);
        assert.equal(model.recordCredit(solver.address, 1n), true);
        trace.push(["credit-before-close", 0, "1"]);
      }
      if (!model.paused) {
        await f.ledger.connect(f.owner).setPausedNewActions(true);
        model.paused = true;
        trace.push(["pause-before-close", true]);
      }
      trace.push(["advance-close"]);
      assert.equal(await succeeds(() => f.ledger.connect(f.outsider).close()), model.close());
      trace.push(["close"]);
      await assertState(f, model);
      assert.equal(await succeeds(() => f.pool.connect(f.sponsors[0]).fund({ value: 1n })), false);
      assert.equal(
        await succeeds(() => f.manager.recordCredit(ledgerAddress, f.solvers[0].address, 1n)), false
      );

      assert.equal(
        await succeeds(() => f.pool.connect(f.outsider).recoverForcedEth(model.forced + 1n)),
        false
      );
      assert.equal(await succeeds(() => f.pool.connect(f.outsider).recoverForcedEth(0n)), false);
      coverage.forcedRecoveryRejections += 2;

      if (zeroCredit) {
        const sponsor = f.sponsors[0];
        assert.equal(await succeeds(() => f.pool.connect(sponsor).sponsorRefund()), model.refund(sponsor.address));
        coverage.sponsorRefunds += 1;
        assert.equal(await succeeds(() => f.pool.connect(sponsor).sponsorRefund()), false);
        coverage.duplicateRefundRejections += 1;
      } else {
        const solver = f.solvers.find((candidate) => model.credits.get(candidate.address) > 0n);
        assert.ok(solver, "positive-credit campaign must retain a solver entitlement");
        assert.equal(await succeeds(() => f.pool.connect(solver).claim()), model.claim(solver.address));
        coverage.pausedClaims += 1;
        assert.equal(await succeeds(() => f.pool.connect(solver).claim()), false);
        coverage.duplicateClaimRejections += 1;
      }
      await assertState(f, model);

      const actors = [...f.sponsors, ...f.solvers];
      for (let step = 0; step < POST_CLOSE_STEPS; step += 1) {
        coverage.attempted += 1;
        const action = pick(4);
        if (action === 0) {
          const solverIndex = pick(f.solvers.length);
          const solver = f.solvers[solverIndex];
          trace.push(["claim", solverIndex]);
          const actual = await succeeds(() => f.pool.connect(solver).claim());
          assert.equal(actual, model.claim(solver.address));
          if (actual) coverage.successful += 1;
        } else if (action === 1) {
          const sponsorIndex = pick(f.sponsors.length);
          const sponsor = f.sponsors[sponsorIndex];
          trace.push(["refund", sponsorIndex]);
          const actual = await succeeds(() => f.pool.connect(sponsor).sponsorRefund());
          assert.equal(actual, model.refund(sponsor.address));
          if (actual) coverage.successful += 1;
        } else if (action === 2) {
          trace.push(["claim-fees"]);
          const actual = await succeeds(() => f.pool.connect(f.outsider).claimFees());
          assert.equal(actual, model.claimFees());
          if (actual) coverage.successful += 1;
        } else {
          const amount = BigInt(1 + pick(100));
          trace.push(["force", amount.toString()]);
          const ForceEther = await ethers.getContractFactory("ForceEther");
          const force = await ForceEther.deploy({ value: amount });
          await force.waitForDeployment();
          await force.force(await f.pool.getAddress());
          model.force(amount);
          coverage.successful += 1;
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
      trace.push(["advance-expiry"]);
      for (const solver of f.solvers) {
        assert.equal(await succeeds(() => f.pool.connect(solver).claim()), false);
      }
      assert.equal(await succeeds(() => f.ledger.connect(actors[pick(actors.length)]).sweepRollover()), model.sweepRollover());
      assert.equal(await succeeds(() => f.ledger.connect(f.outsider).sweepRollover()), false);
      assert.equal(await succeeds(() => f.pool.connect(f.outsider).claimFees()), model.claimFees());
      if (model.forced > 0n) {
        const amount = 1n + BigInt(pick(Number(model.forced)));
        trace.push(["recover-forced", amount.toString()]);
        const actual = await succeeds(() => f.pool.connect(f.outsider).recoverForcedEth(amount));
        assert.equal(actual, model.recoverForced(amount));
        if (actual) coverage.forcedRecoveries += 1;
      }
      await assertState(f, model);
      } catch (error) {
        throw tracedFailure(error, seed, trace);
      }
    }
    assert.equal(coverage.attempted, STATEFUL_SEED_COUNT * (PRE_CLOSE_STEPS + POST_CLOSE_STEPS));
    assert.ok(coverage.successful >= 5_000, `insufficient successful state transitions: ${coverage.successful}`);
    assert.equal(coverage.pausedClaims, 75);
    assert.equal(coverage.duplicateClaimRejections, 75);
    assert.equal(coverage.sponsorRefunds, 25);
    assert.equal(coverage.duplicateRefundRejections, 25);
    assert.equal(coverage.forcedRecoveryRejections, 200);
    assert.equal(coverage.forcedRecoveries, 100);
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
