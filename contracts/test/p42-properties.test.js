import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const CHALLENGE_WINDOW_SECONDS = 72n * 60n * 60n;
const PERMANENCE_HASH = ethers.keccak256(ethers.toUtf8Bytes("property permanence receipt"));

async function expectCustomError(action, contract, errorName) {
  try {
    await action;
  } catch (error) {
    const data = findErrorData(error);
    if (data !== undefined) {
      const parsed = contract.interface.parseError(data);
      assert.equal(parsed?.name, errorName);
      return;
    }
    assert.match(String(error), new RegExp(errorName));
    return;
  }
  throw new Error(`expected ${errorName} revert`);
}

function findErrorData(value) {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string") {
    return /^0x[0-9a-fA-F]+$/.test(value) ? value : undefined;
  }
  if (typeof value !== "object") return undefined;
  if (typeof value.data === "string" && /^0x[0-9a-fA-F]+$/.test(value.data)) return value.data;
  if (typeof value.error?.data === "string") return value.error.data;
  if (typeof value.info?.error?.data === "string") return value.info.error.data;
  if (typeof value.receipt?.revertReason === "string") return value.receipt.revertReason;
  for (const nested of [value.cause, value.error, value.info?.error]) {
    const data = findErrorData(nested);
    if (data !== undefined) return data;
  }
  return undefined;
}

async function increaseTime(seconds) {
  await ethers.provider.send("evm_increaseTime", [Number(seconds)]);
  await ethers.provider.send("evm_mine", []);
}

function rng(seed) {
  let state = BigInt(seed);
  return () => {
    state = (state * 1103515245n + 12345n) % 2147483648n;
    return state;
  };
}

function scenarioFromSeed(seed) {
  const next = rng(seed);
  const submissionCount = 3 + Number(next() % 4n);
  const submissions = [];
  for (let index = 0; index < submissionCount; index += 1) {
    submissions.push({
      solverIndex: Number(next() % 5n),
      improvementAtoms: 1n + next() % 29n,
      donationBeforeFinalizeWei: index === 0 ? 2000n + (next() % 5000n) : next() % 400n
    });
  }
  return {
    seed,
    feeBps: [0, 50, 125, 250][seed % 4],
    alphaBps: [100, 500, 2_000][seed % 3],
    initialPoolWei: seed === 1 ? 0n : 100n + (next() % 10_000n),
    finalDonationWei: next() % 3000n,
    submissions
  };
}

async function deployFixture({ alphaBps = 200n, minBond = 1n, feeBps = 0 } = {}) {
  const [owner, treasury, resolver, ...participants] = await ethers.getSigners();
  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address);
  await pool.waitForDeployment();

  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(await pool.getAddress(), owner.address, treasury.address, feeBps);
  await ledger.waitForDeployment();
  await pool.connect(owner).setLedger(await ledger.getAddress());

  const Submissions = await ethers.getContractFactory("P42SubmissionManager");
  const submissions = await Submissions.deploy(
    await pool.getAddress(),
    await ledger.getAddress(),
    owner.address,
    treasury.address,
    alphaBps,
    minBond,
    CHALLENGE_WINDOW_SECONDS
  );
  await submissions.waitForDeployment();
  await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());

  return { owner, treasury, resolver, participants, pool, ledger, submissions };
}

async function submitAndFinalize(fixture, solver, scenarioSeed, index, improvementAtoms, donationBeforeFinalizeWei) {
  const { pool, ledger, submissions } = fixture;
  const solutionCid = `sha256:property-${scenarioSeed}-${index}`;
  const salt = `salt-${scenarioSeed}-${index}`;
  const commitDaHash = ethers.keccak256(ethers.toUtf8Bytes(`da:${scenarioSeed}:${index}`));
  const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
    solutionCid,
    solver.address,
    commitDaHash,
    salt
  );
  const postingBond = await submissions.requiredPostingBondNow();

  await submissions.connect(solver).commit(commitment, commitDaHash, { value: postingBond });
  const submissionId = await submissions.submissionCount();
  await submissions.connect(solver).reveal(submissionId, solutionCid, 0, improvementAtoms, salt);

  if (donationBeforeFinalizeWei > 0n) {
    await pool.fund({ value: donationBeforeFinalizeWei });
  }
  await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);

  const entitlement = await ledger.provisionalEntitlement(solver.address, improvementAtoms);
  const requiredAtFinalize = await submissions.requiredPostingBondForPool(entitlement);
  const posted = (await submissions.submissions(submissionId)).bondWei;
  let undercovered = false;
  if (posted < requiredAtFinalize) {
    undercovered = true;
    await expectCustomError(
      submissions.connect(solver).finalize(submissionId, PERMANENCE_HASH),
      submissions,
      "P42_BOND_UNDERCOVERS_ENTITLEMENT"
    );
    await submissions.connect(solver).topUpBond(submissionId, { value: requiredAtFinalize - posted });
  }

  assert.equal(await submissions.bondCoversEntitlement(submissionId, entitlement), true);
  await submissions.connect(solver).finalize(submissionId, PERMANENCE_HASH);
  assert.equal((await submissions.submissions(submissionId)).status, 4n);
  return undercovered;
}

describe("P42 contract property checks", function () {
  it("preserves final-denominator payouts under seeded funding and submission sequences", async function () {
    let undercoveredCases = 0;
    for (let seed = 1; seed <= 8; seed += 1) {
      const scenario = scenarioFromSeed(seed);
      const fixture = await deployFixture({
        alphaBps: BigInt(scenario.alphaBps),
        minBond: 1n,
        feeBps: scenario.feeBps
      });
      const { participants, pool, ledger, submissions } = fixture;
      if (scenario.initialPoolWei > 0n) {
        await pool.fund({ value: scenario.initialPoolWei });
      }

      const expectedCredits = new Map();
      for (const [index, submission] of scenario.submissions.entries()) {
        const solver = participants[submission.solverIndex];
        const undercovered = await submitAndFinalize(
          fixture,
          solver,
          seed,
          index,
          submission.improvementAtoms,
          submission.donationBeforeFinalizeWei
        );
        if (undercovered) undercoveredCases += 1;
        expectedCredits.set(
          solver.address,
          (expectedCredits.get(solver.address) ?? 0n) + submission.improvementAtoms
        );
      }

      if (scenario.finalDonationWei > 0n) {
        await pool.fund({ value: scenario.finalDonationWei });
      }
      assert.equal(await submissions.openSubmissionCount(), 0n);
      await ledger.connect(fixture.owner).close();

      const closedPoolBalance = await ledger.closedPoolBalance();
      const feeReserve = await ledger.feeReserve();
      const distributable = closedPoolBalance - feeReserve;
      const totalCredit = [...expectedCredits.values()].reduce((sum, atoms) => sum + atoms, 0n);
      assert.equal(await ledger.totalCreditAtoms(), totalCredit);

      let expectedTotalClaimed = 0n;
      for (const [solverAddress, creditAtoms] of expectedCredits.entries()) {
        const expected = distributable * creditAtoms / totalCredit;
        assert.equal(await ledger.creditAtomsOf(solverAddress), creditAtoms);
        assert.equal(await ledger.finalEntitlement(solverAddress), expected);
        assert.equal(await ledger.claimable(solverAddress), expected);

        const solver = participants.find((participant) => participant.address === solverAddress);
        await pool.connect(solver).claim();
        expectedTotalClaimed += expected;
        assert.equal(await pool.totalClaimed(), expectedTotalClaimed);
        assert.equal(await ledger.claimedWeiOf(solverAddress), expected);
        await expectCustomError(pool.connect(solver).claim(), pool, "P42_NOTHING_TO_CLAIM");
      }

      const dust = distributable - expectedTotalClaimed;
      assert.equal(dust >= 0n, true);
      assert.equal(dust < BigInt(expectedCredits.size), true);
    }
    assert.equal(undercoveredCases > 0, true);
  });

  it("keeps sybil-split payout less than or equal to equivalent combined credit", async function () {
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const [owner, treasury, combined, splitA, splitB, honestA, honestB] = await ethers.getSigners();

    async function entitlements(credits) {
      const pool = await Pool.deploy(owner.address);
      await pool.waitForDeployment();
      const ledger = await Ledger.deploy(await pool.getAddress(), owner.address, treasury.address, 0);
      await ledger.waitForDeployment();
      await pool.connect(owner).setLedger(await ledger.getAddress());
      await pool.fund({ value: 10_003n });
      for (const [solver, atoms] of credits) {
        await ledger.connect(owner).recordCredit(solver.address, atoms);
      }
      await ledger.connect(owner).close();
      const result = new Map();
      for (const [solver] of credits) {
        result.set(solver.address, await ledger.finalEntitlement(solver.address));
      }
      return result;
    }

    for (let seed = 10; seed < 30; seed += 1) {
      const next = rng(seed);
      const left = 1n + next() % 97n;
      const right = 1n + next() % 97n;
      const honestLeft = 1n + next() % 97n;
      const honestRight = 1n + next() % 97n;

      const split = await entitlements([
        [splitA, left],
        [splitB, right],
        [honestA, honestLeft],
        [honestB, honestRight]
      ]);
      const oneIdentity = await entitlements([
        [combined, left + right],
        [honestA, honestLeft],
        [honestB, honestRight]
      ]);

      const splitTotal = split.get(splitA.address) + split.get(splitB.address);
      assert.equal(splitTotal <= oneIdentity.get(combined.address), true);
    }
  });

  it("caps the protocol fee at the advertised 2.5% (250 bps)", async function () {
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const [owner, treasury] = await ethers.getSigners();
    const pool = await Pool.deploy(owner.address);
    await pool.waitForDeployment();

    // 250 bps (2.5%) is the maximum accepted fee.
    const capped = await Ledger.deploy(await pool.getAddress(), owner.address, treasury.address, 250);
    await capped.waitForDeployment();
    assert.equal(await capped.feeBps(), 250n);
    assert.equal(await capped.MAX_FEE_BPS(), 250n);

    // Anything above the cap is rejected at construction.
    await expectCustomError(
      Ledger.deploy(await pool.getAddress(), owner.address, treasury.address, 251),
      Ledger,
      "P42_FEE_TOO_HIGH"
    );
  });
});
