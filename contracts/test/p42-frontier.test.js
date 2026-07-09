import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

// F1 frontier redesign — marginal-credit accounting.
//
// The on-chain frontier `bestScoreAtoms` holds the ABSOLUTE best (lowest)
// score in atoms (score_atoms = ceil(score * 1e18), computed off-chain).
// reveal() requires a strict improvement over the CURRENT frontier;
// finalize() credits the MARGINAL reduction against the LIVE frontier
// (previous best - new score), so ledger shares are Delta_i / SigmaDelta_j.
// A superseded submission finalizes with credit 0 and reclaims its bond.

const CHALLENGE_WINDOW_SECONDS = 72n * 60n * 60n;
const SCALE = 10n ** 18n; // SCORE_ATOM_SCALE: atoms per score unit
const SEED = 1000n * SCALE; // seed frontier: true best-known score = 1000
const DA_HASH = ethers.keccak256(ethers.toUtf8Bytes("frontier DA receipt"));
const PERMANENCE_HASH = ethers.keccak256(ethers.toUtf8Bytes("frontier permanence receipt"));

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

describe("P42 frontier marginal-credit accounting (F1)", function () {
  async function deployFixture({
    alphaBps = 200n,
    minBond = ethers.parseEther("0.01"),
    feeBps = 0,
    seedScoreAtoms = SEED,
    minImprovementAtoms = 1n,
  } = {}) {
    const [owner, treasury, resolver, alice, bob, carol] = await ethers.getSigners();
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
      CHALLENGE_WINDOW_SECONDS,
      false, // off-chain DA mode: frontier fixtures exercise economics, not DA binding
      0,
      seedScoreAtoms,
      minImprovementAtoms
    );
    await submissions.waitForDeployment();
    await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());

    return { owner, treasury, resolver, alice, bob, carol, pool, ledger, submissions, minBond };
  }

  // Commit + reveal an ABSOLUTE claimed score for `solver`; returns the id.
  async function commitReveal(fixture, solver, claimedScoreAtoms, { cid, salt, improvementAtoms = 1n } = {}) {
    const { submissions } = fixture;
    const solutionCid = cid ?? `bafy-frontier-${solver.address.slice(2, 10)}-${claimedScoreAtoms}`;
    const revealSalt = salt ?? `salt-${solver.address.slice(2, 10)}-${claimedScoreAtoms}`;
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
      solutionCid,
      solver.address,
      DA_HASH,
      revealSalt
    );
    const bond = await submissions.requiredPostingBondNow();
    await submissions.connect(solver).commit(commitment, DA_HASH, { value: bond });
    const submissionId = await submissions.submissionCount();
    await submissions
      .connect(solver)
      .reveal(submissionId, solutionCid, claimedScoreAtoms, improvementAtoms, revealSalt, "0x");
    return { submissionId, bond };
  }

  async function finalizeAndParse(fixture, solver, submissionId) {
    const tx = await fixture.submissions.connect(solver).finalize(submissionId, PERMANENCE_HASH);
    const receipt = await tx.wait();
    const finalized = receipt.logs
      .map((log) => {
        try {
          return fixture.submissions.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed && parsed.name === "Finalized");
    assert.ok(finalized, "Finalized event present");
    return finalized.args;
  }

  it("initializes the frontier at the seed and anchors the shared atom scale", async function () {
    const { submissions } = await deployFixture({ minImprovementAtoms: 7n });
    assert.equal(await submissions.SCORE_ATOM_SCALE(), SCALE);
    assert.equal(await submissions.seedScoreAtoms(), SEED);
    assert.equal(await submissions.bestScoreAtoms(), SEED);
    assert.equal(await submissions.minImprovementAtoms(), 7n);
  });

  // -------------------------------------------------------------------------
  // (b) WORSE-THAN-FRONTIER: a claimed score >= the current frontier cannot
  // even reveal. This is the on-chain guard that kills hadamard-668-style
  // worse-than-baseline "improvements" once the seed is the true best known.
  // -------------------------------------------------------------------------
  it("rejects reveals whose claimed absolute score does not strictly beat the seed", async function () {
    const fixture = await deployFixture();
    const { alice, bob, ledger, submissions } = fixture;

    for (const claimed of [SEED, SEED + 1n, SEED + 668n * SCALE]) {
      const cid = `bafy-worse-${claimed}`;
      const salt = `worse-${claimed}`;
      const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
        cid,
        alice.address,
        DA_HASH,
        salt
      );
      await submissions.connect(alice).commit(commitment, DA_HASH, { value: fixture.minBond });
      const id = await submissions.submissionCount();
      await expectCustomError(
        submissions.connect(alice).reveal(id, cid, claimed, 1n, salt, "0x"),
        submissions,
        "P42_NOT_STRICT_IMPROVEMENT"
      );
    }

    // A strictly better score reveals fine...
    const { submissionId } = await commitReveal(fixture, alice, SEED - 100n * SCALE);
    assert.equal((await submissions.submissions(submissionId)).status, 2n); // Revealed
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.connect(alice).finalize(submissionId, PERMANENCE_HASH);
    assert.equal(await submissions.bestScoreAtoms(), SEED - 100n * SCALE);

    // ...and a claim that beats the SEED but NOT the advanced frontier now
    // REVEALS fine — the gate is on the IMMUTABLE seed, not the moving best.
    // This is the F1 griefing fix: gating reveal on the live best would brick
    // an honest solver superseded between commit and reveal (a rival advances
    // the frontier after their commit) and seize their bond to the treasury.
    // Here bob's SEED-100 ties the advanced best, so finalize credits 0 and the
    // bond is fully reclaimable — no seizure.
    const superseded = await commitReveal(fixture, bob, SEED - 100n * SCALE);
    assert.equal((await submissions.submissions(superseded.submissionId)).status, 2n); // Revealed OK
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.connect(bob).finalize(superseded.submissionId, PERMANENCE_HASH);
    assert.equal((await submissions.submissions(superseded.submissionId)).status, 4n); // Finalized
    assert.equal(await submissions.bestScoreAtoms(), SEED - 100n * SCALE); // no credit -> unchanged
    assert.equal(await ledger.creditAtomsOf(bob.address), 0n);
    assert.equal(await submissions.claimableBondWei(bob.address), superseded.bond); // bond back, not seized
  });

  it("rejects out-of-range score claims that would poison the marginal arithmetic", async function () {
    const fixture = await deployFixture();
    const { alice, submissions } = fixture;
    const INT256_MIN = -(2n ** 255n);
    const BOUND = 2n ** 254n;

    // A claim at/below -2^254 (e.g. int256 min) must fail at reveal with a
    // named error — never enter Revealed and later panic finalize/challenge.
    for (const claimed of [INT256_MIN, -BOUND]) {
      const cid = `bafy-range-${claimed}`;
      const salt = `range-${claimed}`;
      const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
        cid,
        alice.address,
        DA_HASH,
        salt
      );
      await submissions.connect(alice).commit(commitment, DA_HASH, { value: fixture.minBond });
      const id = await submissions.submissionCount();
      await expectCustomError(
        submissions.connect(alice).reveal(id, cid, claimed, 1n, salt, "0x"),
        submissions,
        "P42_SCORE_ATOMS_OUT_OF_RANGE"
      );
    }

    // Out-of-range seeds are rejected at construction.
    const Submissions = await ethers.getContractFactory("P42SubmissionManager");
    const [owner, treasury] = await ethers.getSigners();
    await expectCustomError(
      Submissions.deploy(
        await fixture.pool.getAddress(),
        await fixture.ledger.getAddress(),
        owner.address,
        treasury.address,
        200n,
        fixture.minBond,
        CHALLENGE_WINDOW_SECONDS,
        false,
        0,
        BOUND, // seed >= 2^254
        1n
      ),
      submissions,
      "P42_SCORE_ATOMS_OUT_OF_RANGE"
    );
  });

  // -------------------------------------------------------------------------
  // (a) FREE-RIDER: the audit's break. A does the real work (seed 1000 -> 500),
  // B nudges the frontier (500 -> 400). Old accounting credited B the whole
  // seed-relative distance (600) for a 54.5% pool share (600/1100). New
  // accounting credits B only the marginal 100 => a 1/6 share.
  // -------------------------------------------------------------------------
  it("credits a free-rider only their marginal frontier reduction, not the seed-relative distance", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { alice, bob, pool, ledger, submissions } = fixture;
    await pool.fund({ value: ethers.parseEther("11") });

    const scoreA = 500n * SCALE;
    const scoreB = 400n * SCALE;

    // Solver A: seed -> 500. Marginal (and credit) = 500 units.
    const a = await commitReveal(fixture, alice, scoreA);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const aArgs = await finalizeAndParse(fixture, alice, a.submissionId);
    assert.equal(aArgs.creditAtoms, SEED - scoreA);
    assert.equal(aArgs.bestScoreAtoms, scoreA);
    assert.equal(await submissions.bestScoreAtoms(), scoreA);
    assert.equal(await ledger.creditAtomsOf(alice.address), 500n * SCALE);

    // Solver B free-rides A's public frontier: 500 -> 400.
    const b = await commitReveal(fixture, bob, scoreB);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const bArgs = await finalizeAndParse(fixture, bob, b.submissionId);

    // B is credited ONLY the marginal 100 units — never the 600 seed-relative.
    assert.equal(bArgs.creditAtoms, scoreA - scoreB);
    assert.equal(await ledger.creditAtomsOf(bob.address), 100n * SCALE);
    assert.notEqual(await ledger.creditAtomsOf(bob.address), SEED - scoreB);
    assert.equal(await submissions.bestScoreAtoms(), scoreB);
    assert.equal(await ledger.totalCreditAtoms(), 600n * SCALE);

    // Pool shares are proportional to marginals: B gets 100/600 = 1/6.
    await ledger.close();
    const distributable = await ledger.distributablePool();
    const bEntitlement = await ledger.finalEntitlement(bob.address);
    const aEntitlement = await ledger.finalEntitlement(alice.address);
    assert.equal(bEntitlement, (distributable * 100n) / 600n);
    assert.equal(aEntitlement, (distributable * 500n) / 600n);

    // The audit's break — B at 600/1100 = ~54.5% of the pool — must be gone.
    const oldBrokenShare = (distributable * 600n) / 1100n;
    assert.equal(oldBrokenShare, ethers.parseEther("6")); // ~54.5% of 11 ETH
    assert.notEqual(bEntitlement, oldBrokenShare);
    assert.equal(bEntitlement < aEntitlement, true);

    // And the money actually moves that way.
    await pool.connect(bob).claim();
    assert.equal(await ledger.claimedWeiOf(bob.address), bEntitlement);
  });

  // -------------------------------------------------------------------------
  // (c) SELF-LADDER: splitting one discovery into a staircase of submissions
  // earns exactly the same total credit as submitting the final score once —
  // marginals telescope, so there is no denominator advantage.
  // -------------------------------------------------------------------------
  it("gives a self-laddering solver no denominator advantage over a single submission", async function () {
    const s1 = 800n * SCALE;
    const s2 = 600n * SCALE;

    // Ladder: alice finalizes seed -> 800, then 800 -> 600.
    const ladder = await deployFixture({ feeBps: 0 });
    await ladder.pool.fund({ value: ethers.parseEther("4") });
    const first = await commitReveal(ladder, ladder.alice, s1);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await ladder.submissions.connect(ladder.alice).finalize(first.submissionId, PERMANENCE_HASH);
    assert.equal(await ladder.ledger.creditAtomsOf(ladder.alice.address), SEED - s1);

    const second = await commitReveal(ladder, ladder.alice, s2);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await ladder.submissions.connect(ladder.alice).finalize(second.submissionId, PERMANENCE_HASH);

    // Total credit telescopes to seed - s2, exactly as if s2 were submitted once.
    assert.equal(await ladder.ledger.creditAtomsOf(ladder.alice.address), SEED - s2);
    assert.equal(await ladder.ledger.totalCreditAtoms(), SEED - s2);
    assert.equal(await ladder.submissions.bestScoreAtoms(), s2);

    // Control: a single direct submission of s2 in a fresh deployment.
    const direct = await deployFixture({ feeBps: 0 });
    await direct.pool.fund({ value: ethers.parseEther("4") });
    const only = await commitReveal(direct, direct.bob, s2);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await direct.submissions.connect(direct.bob).finalize(only.submissionId, PERMANENCE_HASH);

    assert.equal(
      await direct.ledger.creditAtomsOf(direct.bob.address),
      await ladder.ledger.creditAtomsOf(ladder.alice.address)
    );
    assert.equal(await direct.ledger.totalCreditAtoms(), await ladder.ledger.totalCreditAtoms());
  });

  // -------------------------------------------------------------------------
  // (d) SUPERSEDED: B reveals, then A finalizes a better score first. B still
  // finalizes — with 0 credit — and reclaims its bond. Being beaten is not
  // fraud; the bond is never seized to the treasury for it.
  // -------------------------------------------------------------------------
  it("finalizes a fully superseded submission with zero credit and a reclaimable bond", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { alice, bob, treasury, pool, ledger, submissions } = fixture;
    await pool.fund({ value: ethers.parseEther("3") });

    // Both reveal against the seed frontier; B claims 900, A claims 700.
    const b = await commitReveal(fixture, bob, 900n * SCALE);
    const a = await commitReveal(fixture, alice, 700n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);

    // A finalizes first and takes the frontier to 700 (credit 300).
    const aArgs = await finalizeAndParse(fixture, alice, a.submissionId);
    assert.equal(aArgs.creditAtoms, 300n * SCALE);
    assert.equal(await submissions.bestScoreAtoms(), 700n * SCALE);

    // B's claimed 900 is now behind the live frontier: finalize succeeds with
    // credit 0, no ledger entry, no frontier movement.
    const bArgs = await finalizeAndParse(fixture, bob, b.submissionId);
    assert.equal(bArgs.creditAtoms, 0n);
    assert.equal(bArgs.claimedScoreAtoms, 900n * SCALE);
    assert.equal(bArgs.bestScoreAtoms, 700n * SCALE);
    assert.equal((await submissions.submissions(b.submissionId)).status, 4n); // Finalized
    assert.equal(await ledger.creditAtomsOf(bob.address), 0n);
    assert.equal(await ledger.totalCreditAtoms(), 300n * SCALE);
    assert.equal(await submissions.bestScoreAtoms(), 700n * SCALE);
    assert.equal(await submissions.openSubmissionCount(), 0n);

    // The honest-but-beaten solver reclaims their full bond; treasury gets none.
    assert.equal(await submissions.claimableBondWei(bob.address), b.bond);
    assert.equal(await submissions.claimableBondWei(treasury.address), 0n);
    const before = await ethers.provider.getBalance(await submissions.getAddress());
    await submissions.connect(bob).claimBond();
    assert.equal(before - (await ethers.provider.getBalance(await submissions.getAddress())), b.bond);
    assert.equal(await submissions.claimableBondWei(bob.address), 0n);

    // The ledger can close: only A holds credit.
    await ledger.close();
    assert.equal(await ledger.finalEntitlement(alice.address), await ledger.distributablePool());
    assert.equal(await ledger.finalEntitlement(bob.address), 0n);
  });

  it("credits a partially superseded submission its remaining marginal over the advanced frontier", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { alice, bob, ledger, submissions } = fixture;
    await fixture.pool.fund({ value: ethers.parseEther("3") });

    // B reveals 600 while the frontier is still the seed (implied marginal 400)...
    const b = await commitReveal(fixture, bob, 600n * SCALE);
    // ...but A finalizes 700 first.
    const a = await commitReveal(fixture, alice, 700n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.connect(alice).finalize(a.submissionId, PERMANENCE_HASH);
    assert.equal(await submissions.bestScoreAtoms(), 700n * SCALE);

    // B's credit is recomputed against the LIVE frontier: 700 - 600 = 100.
    const bArgs = await finalizeAndParse(fixture, bob, b.submissionId);
    assert.equal(bArgs.creditAtoms, 100n * SCALE);
    assert.equal(await ledger.creditAtomsOf(bob.address), 100n * SCALE);
    assert.equal(await submissions.bestScoreAtoms(), 600n * SCALE);
    // Total credit still telescopes to seed - final best.
    assert.equal(await ledger.totalCreditAtoms(), SEED - 600n * SCALE);
  });

  it("treats a marginal below minImprovementAtoms as superseded: no credit, no frontier move, bond back", async function () {
    const fixture = await deployFixture({ feeBps: 0, minImprovementAtoms: 50n * SCALE });
    const { alice, ledger, submissions } = fixture;
    await fixture.pool.fund({ value: ethers.parseEther("1") });

    // Strictly better than the seed, but by only 10 units < the 50-unit floor.
    const { submissionId, bond } = await commitReveal(fixture, alice, SEED - 10n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const args = await finalizeAndParse(fixture, alice, submissionId);

    assert.equal(args.creditAtoms, 0n);
    assert.equal(args.bestScoreAtoms, SEED); // frontier untouched
    assert.equal(await submissions.bestScoreAtoms(), SEED);
    assert.equal(await ledger.creditAtomsOf(alice.address), 0n);
    assert.equal(await ledger.totalCreditAtoms(), 0n);
    assert.equal((await submissions.submissions(submissionId)).status, 4n);
    assert.equal(await submissions.claimableBondWei(alice.address), bond);
  });

  // -------------------------------------------------------------------------
  // (e) Regression: the ordinary lifecycle still finalizes, records the
  // (now-marginal) credit, and pays out after close.
  // -------------------------------------------------------------------------
  it("keeps the happy-path lifecycle working end to end with marginal credit", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { alice, pool, ledger, submissions } = fixture;
    await pool.fund({ value: ethers.parseEther("2") });

    const claimed = 250n * SCALE;
    const { submissionId, bond } = await commitReveal(fixture, alice, claimed);
    await expectCustomError(
      submissions.connect(alice).finalize(submissionId, PERMANENCE_HASH),
      submissions,
      "P42_CHALLENGE_WINDOW_OPEN"
    );
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);

    const args = await finalizeAndParse(fixture, alice, submissionId);
    assert.equal(args.creditAtoms, SEED - claimed);
    assert.equal(args.claimedScoreAtoms, claimed);
    assert.equal(args.bestScoreAtoms, claimed);
    assert.equal(args.permanenceHash, PERMANENCE_HASH);

    const stored = await submissions.submissions(submissionId);
    assert.equal(stored.status, 4n); // Finalized
    assert.equal(stored.claimedScoreAtoms, claimed);
    assert.equal(await submissions.bestScoreAtoms(), claimed);
    assert.equal(await ledger.creditAtomsOf(alice.address), SEED - claimed);

    await submissions.connect(alice).claimBond();
    assert.equal(await submissions.claimableBondWei(alice.address), 0n);
    assert.ok(bond > 0n);

    await ledger.close();
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), ethers.parseEther("2"));
  });

  // ===========================================================================
  // POISONED-FRONTIER RECOVERY (policy decision 6): a fraudulent unchallenged
  // finalize can set bestScoreAtoms unreachably low so every honest score
  // thereafter finalizes with 0 credit — bricking the problem. voidFinalize
  // (owner/timelock, under the full pause) reverses exactly that finalize:
  // restores the stored prevBestScoreAtoms and voids the stored creditAtoms.
  // ===========================================================================

  it("recovers a poisoned frontier: voidFinalize restores the frontier, voids the fraud's credit, and honest work resumes", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { owner, alice, bob, carol, ledger, submissions } = fixture;
    await fixture.pool.fund({ value: ethers.parseEther("2") });

    // Carol finalizes a fraudulent, unreachably low score (1 atom = 1e-18
    // score units) unchallenged: the frontier is poisoned.
    const fraud = await commitReveal(fixture, carol, 1n);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const fraudArgs = await finalizeAndParse(fixture, carol, fraud.submissionId);
    assert.equal(fraudArgs.creditAtoms, SEED - 1n);
    assert.equal(await submissions.bestScoreAtoms(), 1n);
    assert.equal(await ledger.creditAtomsOf(carol.address), SEED - 1n);

    // The problem is bricked for honest work: a genuinely strong score (500)
    // still reveals (the reveal gate is the immutable seed) but finalizes with
    // ZERO credit — no achievable score beats the poisoned frontier.
    const honest = await commitReveal(fixture, alice, 500n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const honestArgs = await finalizeAndParse(fixture, alice, honest.submissionId);
    assert.equal(honestArgs.creditAtoms, 0n);
    assert.equal(await ledger.creditAtomsOf(alice.address), 0n);
    assert.equal(await submissions.bestScoreAtoms(), 1n);

    // Recovery: arm the full pause, then void the fraudulent finalize. The
    // stored snapshot pins exactly what is reversed — no governance numbers.
    await submissions.connect(owner).setPausedAll(true);
    const info = await submissions.finalizeInfo(fraud.submissionId);
    assert.equal(info.prevBestScoreAtoms, SEED);
    assert.equal(info.creditAtoms, SEED - 1n);

    const tx = await submissions.connect(owner).voidFinalize(fraud.submissionId);
    const receipt = await tx.wait();
    const voided = receipt.logs
      .map((log) => {
        try {
          return submissions.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed && parsed.name === "FinalizeVoided");
    assert.ok(voided, "FinalizeVoided event present");
    assert.equal(voided.args.submissionId, fraud.submissionId);
    assert.equal(voided.args.solver, carol.address);
    assert.equal(voided.args.creditAtoms, SEED - 1n);
    assert.equal(voided.args.restoredBestScoreAtoms, SEED);

    // Frontier restored, fraud credit zeroed, and no double-void is possible.
    assert.equal(await submissions.bestScoreAtoms(), SEED);
    assert.equal(await ledger.creditAtomsOf(carol.address), 0n);
    assert.equal(await ledger.totalCreditAtoms(), 0n);
    assert.equal((await submissions.submissions(fraud.submissionId)).status, 6n); // Voided
    await expectCustomError(
      submissions.connect(owner).voidFinalize(fraud.submissionId),
      submissions,
      "P42_BAD_SUBMISSION_STATUS"
    );

    // The fraud's bond is deliberately untouched: economic punishment is the
    // challenge/slash path's concern, voidFinalize only corrects the frontier.
    assert.equal(await submissions.claimableBondWei(carol.address), fraud.bond);

    // Disarm the pause: a fresh honest cycle earns real marginal credit again.
    await submissions.connect(owner).setPausedAll(false);
    const fresh = await commitReveal(fixture, bob, 400n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const freshArgs = await finalizeAndParse(fixture, bob, fresh.submissionId);
    assert.equal(freshArgs.creditAtoms, SEED - 400n * SCALE);
    assert.equal(await submissions.bestScoreAtoms(), 400n * SCALE);
    assert.equal(await ledger.creditAtomsOf(bob.address), SEED - 400n * SCALE);
    // The telescoping invariant holds again: totalCredit == seed - best.
    assert.equal(await ledger.totalCreditAtoms(), SEED - 400n * SCALE);
  });

  it("refuses voidFinalize unless the full pause is armed, and stays owner-only", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { owner, carol, submissions } = fixture;
    const fraud = await commitReveal(fixture, carol, 1n);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await finalizeAndParse(fixture, carol, fraud.submissionId);

    // Without pausedAll a void could race an in-flight finalize: refused.
    await expectCustomError(
      submissions.connect(owner).voidFinalize(fraud.submissionId),
      submissions,
      "P42_NOT_PAUSED_ALL"
    );
    assert.equal(await submissions.bestScoreAtoms(), 1n);

    // Owner-only, even when the pause is armed.
    await expectCustomError(submissions.connect(carol).setPausedAll(true), submissions, "P42_NOT_OWNER");
    await submissions.connect(owner).setPausedAll(true);
    await expectCustomError(
      submissions.connect(carol).voidFinalize(fraud.submissionId),
      submissions,
      "P42_NOT_OWNER"
    );
  });

  it("refuses to void a superseded finalize but unwinds stacked frontier-holders newest-first", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { owner, alice, bob, carol, ledger, submissions } = fixture;

    // alice: seed -> 500 (credited), then bob advances 500 -> 400 (credited).
    const a = await commitReveal(fixture, alice, 500n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await finalizeAndParse(fixture, alice, a.submissionId);
    const b = await commitReveal(fixture, bob, 400n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await finalizeAndParse(fixture, bob, b.submissionId);
    // carol beats the seed but not the live frontier: finalizes with 0 credit.
    const c = await commitReveal(fixture, carol, 450n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const cArgs = await finalizeAndParse(fixture, carol, c.submissionId);
    assert.equal(cArgs.creditAtoms, 0n);

    await submissions.connect(owner).setPausedAll(true);
    // alice's credited finalize is no longer the live frontier: refused —
    // restoring ITS prevBest over bob's better score would corrupt the frontier.
    await expectCustomError(
      submissions.connect(owner).voidFinalize(a.submissionId),
      submissions,
      "P42_VOID_NOT_FRONTIER"
    );
    // carol's superseded finalize earned nothing: nothing to void.
    await expectCustomError(
      submissions.connect(owner).voidFinalize(c.submissionId),
      submissions,
      "P42_VOID_NO_CREDIT"
    );

    // The live frontier holder (bob) IS voidable; after that unwind, alice's
    // finalize becomes the live frontier again and unwinds too — stacked
    // frauds unwind newest-first by repeated calls, exactly reversing each.
    await submissions.connect(owner).voidFinalize(b.submissionId);
    assert.equal(await submissions.bestScoreAtoms(), 500n * SCALE);
    assert.equal(await ledger.creditAtomsOf(bob.address), 0n);
    await submissions.connect(owner).voidFinalize(a.submissionId);
    assert.equal(await submissions.bestScoreAtoms(), SEED);
    assert.equal(await ledger.creditAtomsOf(alice.address), 0n);
    assert.equal(await ledger.totalCreditAtoms(), 0n);
  });

  it("pausedAll blocks commit, reveal, and finalize so no finalize can race a recovery", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { owner, alice, bob, submissions } = fixture;

    // Stage a committed-but-unrevealed submission and a revealed one whose
    // challenge window has elapsed (finalize-ready).
    const cid = "bafy-pause-committed";
    const salt = "pause-committed";
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
      cid,
      alice.address,
      DA_HASH,
      salt
    );
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: fixture.minBond });
    const committedId = await submissions.submissionCount();
    const revealed = await commitReveal(fixture, bob, 600n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);

    await submissions.connect(owner).setPausedAll(true);
    await expectCustomError(
      submissions
        .connect(alice)
        .commit(ethers.keccak256(ethers.toUtf8Bytes("paused-all-commit")), DA_HASH, { value: fixture.minBond }),
      submissions,
      "P42_PAUSED_ALL"
    );
    await expectCustomError(
      submissions.connect(alice).reveal(committedId, cid, 700n * SCALE, 1n, salt, "0x"),
      submissions,
      "P42_PAUSED_ALL"
    );
    await expectCustomError(
      submissions.connect(bob).finalize(revealed.submissionId, PERMANENCE_HASH),
      submissions,
      "P42_PAUSED_ALL"
    );

    // Disarm: the identical actions immediately succeed.
    await submissions.connect(owner).setPausedAll(false);
    await submissions.connect(alice).reveal(committedId, cid, 700n * SCALE, 1n, salt, "0x");
    await submissions.connect(bob).finalize(revealed.submissionId, PERMANENCE_HASH);
    assert.equal(await submissions.bestScoreAtoms(), 600n * SCALE);
  });

  it("voidCredit enforces recorder scope and checked balance math", async function () {
    const [owner, treasury, recorder, alice] = await ethers.getSigners();
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const pool = await Pool.deploy(owner.address);
    await pool.waitForDeployment();
    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const ledger = await Ledger.deploy(await pool.getAddress(), owner.address, treasury.address, 0);
    await ledger.waitForDeployment();
    await ledger.connect(owner).setCreditRecorder(recorder.address);

    await ledger.connect(recorder).recordCredit(alice.address, 100n);
    // Only the creditRecorder may void — not even the owner.
    await expectCustomError(
      ledger.connect(owner).voidCredit(alice.address, 10n),
      ledger,
      "P42_NOT_CREDIT_RECORDER"
    );
    // Zero voids and over-voids are refused: a balance can never go negative.
    await expectCustomError(ledger.connect(recorder).voidCredit(alice.address, 0n), ledger, "P42_ZERO_CREDIT");
    await expectCustomError(
      ledger.connect(recorder).voidCredit(alice.address, 101n),
      ledger,
      "P42_VOID_EXCEEDS_CREDIT"
    );

    await ledger.connect(recorder).voidCredit(alice.address, 40n);
    assert.equal(await ledger.creditAtomsOf(alice.address), 60n);
    assert.equal(await ledger.totalCreditAtoms(), 60n);
    await ledger.connect(recorder).voidCredit(alice.address, 60n);
    assert.equal(await ledger.creditAtomsOf(alice.address), 0n);
    assert.equal(await ledger.totalCreditAtoms(), 0n);
    await expectCustomError(
      ledger.connect(recorder).voidCredit(alice.address, 1n),
      ledger,
      "P42_VOID_EXCEEDS_CREDIT"
    );
  });

  it("refuses to void a finalize once the ledger has closed (entitlements are snapshotted)", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { owner, alice, ledger, submissions } = fixture;
    const a = await commitReveal(fixture, alice, 500n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await finalizeAndParse(fixture, alice, a.submissionId);
    await ledger.close();

    await submissions.connect(owner).setPausedAll(true);
    await expectCustomError(
      submissions.connect(owner).voidFinalize(a.submissionId),
      ledger,
      "P42_CLOSED"
    );
    // Nothing moved: the frontier and credit are untouched by the refused void.
    assert.equal(await submissions.bestScoreAtoms(), 500n * SCALE);
    assert.equal(await ledger.creditAtomsOf(alice.address), SEED - 500n * SCALE);
  });
});
