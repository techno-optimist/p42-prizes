import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { deployActiveObjectiveProofCapability } from "../test-support/objective-proof-capability.js";

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
const FUNDING_CAP = ethers.parseEther("100");
const MIN_COMPETITION_SECONDS = 30n * 24n * 60n * 60n;
const BOARD_SET_DIGEST = ethers.id("p42-frontier-board-set");
const RELEASE_BINDING_DIGEST = ethers.id("p42-frontier-release-binding");
const FUNDING_ROLES = [
  ethers.id("production-launch-authority"),
  ethers.id("independent-security-authority"),
  ethers.id("governance-authority"),
];
const FUNDING_TYPES = {
  FundingAuthorization: [
    { name: "role", type: "bytes32" },
    { name: "boardSetDigest", type: "bytes32" },
    { name: "releaseBindingDigest", type: "bytes32" },
    { name: "authorizationDigest", type: "bytes32" },
    { name: "expiresAt", type: "uint64" },
    { name: "nonce", type: "uint256" },
  ],
};

function fundingAuthorizationConfig(authorities, capability) {
  return {
    boardSetDigest: BOARD_SET_DIGEST,
    releaseBindingDigest: RELEASE_BINDING_DIGEST,
    objectiveVerifier: capability.objectiveVerifier,
    objectiveVerifierCodehash: capability.objectiveVerifierCodehash,
    productionLaunchAuthority: authorities[0].address,
    independentSecurityAuthority: authorities[1].address,
    governanceAuthority: authorities[2].address,
  };
}

async function authorizeFunding(submissions, relayer, authorities, authorizationDigest, expiresAt) {
  const nonce = await submissions.fundingAuthorizationNonce();
  const { chainId } = await ethers.provider.getNetwork();
  const domain = {
    name: "P42SubmissionManager",
    version: "2",
    chainId,
    verifyingContract: await submissions.getAddress(),
  };
  const common = {
    boardSetDigest: BOARD_SET_DIGEST,
    releaseBindingDigest: RELEASE_BINDING_DIGEST,
    authorizationDigest,
    expiresAt,
    nonce,
  };
  const signatures = await Promise.all(authorities.slice(0, 3).map((authority, index) =>
    authority.signTypedData(domain, FUNDING_TYPES, { ...common, role: FUNDING_ROLES[index] })
  ));
  return submissions.connect(relayer).authorizeFunding(authorizationDigest, expiresAt, nonce, signatures);
}

async function nextEarliestClose() {
  const latest = await ethers.provider.getBlock("latest");
  return BigInt(latest.timestamp) + MIN_COMPETITION_SECONDS + 1_000n;
}

async function nextCloseBy() {
  const latest = await ethers.provider.getBlock("latest");
  return BigInt(latest.timestamp) + 181n * 24n * 60n * 60n;
}

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

async function advanceToEffectiveClose(ledger) {
  const target = await ledger.closeByTimestamp();
  const latest = await ethers.provider.getBlock("latest");
  if (target > BigInt(latest.timestamp)) await increaseTime(target - BigInt(latest.timestamp));
}

describe("P42 frontier marginal-credit accounting (F1)", function () {
  async function deployFixture({
    alphaBps = 200n,
    minBond = ethers.parseEther("0.01"),
    feeBps = 0,
    seedScoreAtoms = SEED,
    minImprovementAtoms = 1n,
    // PAID phase by default: existing economic suites assert real marginal
    // credit, so the fixture arms funding up front. Open-phase suites pass
    // arm: false to exercise the free witness phase.
    arm = true,
    advanceCompetition = true,
  } = {}) {
    const [owner, treasury, resolver, alice, bob, carol, ...authorities] = await ethers.getSigners();
    const capability = await deployActiveObjectiveProofCapability(ethers);
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const pool = await Pool.deploy(owner.address, FUNDING_CAP);
    await pool.waitForDeployment();

    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const ledger = await Ledger.deploy(
      await pool.getAddress(), owner.address, treasury.address, feeBps,
      await nextEarliestClose(), await nextCloseBy()
    );
    await ledger.waitForDeployment();
    await pool.connect(owner).setLedger(await ledger.getAddress());

    const Submissions = await ethers.getContractFactory("P42SubmissionManager");
    const submissions = await Submissions.deploy({
      pool: await pool.getAddress(),
      ledger: await ledger.getAddress(),
      owner: owner.address,
      treasury: treasury.address,
      alphaBps,
      minPostingBondWei: minBond,
      challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS,
      onchainDa: false,
      maxSolutionBytes: 0,
      seedScoreAtoms,
      minImprovementAtoms,
    }, fundingAuthorizationConfig(authorities, capability));
    await submissions.waitForDeployment();
    await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());

    // Funding gate wiring: the pool refuses deposits until the submission
    // manager is wired AND armFunding(digest) has flipped it to the PAID phase.
    await pool.connect(owner).setSubmissionManager(await submissions.getAddress());
    const Registry = await ethers.getContractFactory("P42ProblemRegistry");
    const fundingRegistry = await Registry.deploy(owner.address);
    await fundingRegistry.waitForDeployment();
    await fundingRegistry.register({
      specHash: ethers.id("frontier-spec"),
      verifierSourceHash: ethers.id("frontier-source"),
      verifierImageHash: ethers.id("frontier-image"),
      admissionMatrixHash: ethers.id("frontier-matrix"),
      metadataURI: "ipfs://frontier-fixture",
      pool: await pool.getAddress(),
      ledger: await ledger.getAddress(),
      submissionManager: await submissions.getAddress(),
      challengeManager: owner.address,
      challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS,
      minImprovementAtoms,
    });
    await fundingRegistry.freeze(1);
    await pool.connect(owner).setRegistry(await fundingRegistry.getAddress(), 1);
    const Vault = await ethers.getContractFactory("P42RolloverVault");
    const vault = await Vault.deploy(await fundingRegistry.getAddress(), owner.address);
    await vault.waitForDeployment();
    await ledger.connect(owner).setRolloverDestination(await vault.getAddress());
    if (arm) {
      await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
      await authorizeFunding(submissions, treasury, authorities, "0x" + "42".repeat(32), 2n ** 64n - 1n);
      await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
      await pool.connect(owner).setAcceptingFunds(true);
    }
    if (advanceCompetition) await increaseTime(MIN_COMPETITION_SECONDS + 1_001n);

    return { owner, treasury, resolver, alice, bob, carol, authorities, capability, pool, ledger, submissions, vault, minBond };
  }

  // Commit + reveal an ABSOLUTE claimed score for `solver`; returns the id.
  async function commitReveal(fixture, solver, claimedScoreAtoms, { cid, salt } = {}) {
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
    const improvementAtoms = await submissions.seedScoreAtoms() - BigInt(claimedScoreAtoms);
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
      await submissions.connect(alice).commit(commitment, DA_HASH, {
        value: await submissions.requiredPostingBondNow(),
      });
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
      await submissions.connect(alice).commit(commitment, DA_HASH, {
        value: await submissions.requiredPostingBondNow(),
      });
      const id = await submissions.submissionCount();
      await expectCustomError(
        submissions.connect(alice).reveal(id, cid, claimed, 1n, salt, "0x"),
        submissions,
        "P42_SCORE_ATOMS_OUT_OF_RANGE"
      );
    }

    // Out-of-range seeds are rejected at construction.
    const Submissions = await ethers.getContractFactory("P42SubmissionManager");
    const [owner, treasury, , , , , ...authorities] = await ethers.getSigners();
    await expectCustomError(
      Submissions.deploy({
        pool: await fixture.pool.getAddress(), ledger: await fixture.ledger.getAddress(),
        owner: owner.address, treasury: treasury.address, alphaBps: 200n,
        minPostingBondWei: fixture.minBond, challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS,
        onchainDa: false, maxSolutionBytes: 0, seedScoreAtoms: BOUND, minImprovementAtoms: 1n,
      }, fundingAuthorizationConfig(authorities, fixture.capability)),
      submissions,
      "P42_SCORE_ATOMS_OUT_OF_RANGE"
    );
    await assert.rejects(
      Submissions.deploy({
        pool: await fixture.pool.getAddress(), ledger: await fixture.ledger.getAddress(),
        owner: owner.address, treasury: treasury.address, alphaBps: 200n,
        minPostingBondWei: fixture.minBond, challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS,
        onchainDa: false, maxSolutionBytes: 0, seedScoreAtoms: 1000n * SCALE, minImprovementAtoms: 1n,
      }, { ...fundingAuthorizationConfig(authorities, fixture.capability), productionLaunchAuthority: owner.address }),
      /P42_FUNDING_AUTHORITIES_NOT_DISTINCT/
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
    await advanceToEffectiveClose(ledger);
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
    await advanceToEffectiveClose(ledger);
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

    assert.ok(bond > 0n);

    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await submissions.releaseFinalizedBond(submissionId);
    await submissions.connect(alice).claimBond();
    assert.equal(await submissions.claimableBondWei(alice.address), 0n);
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
    const { owner, alice, bob, carol, treasury, ledger, submissions } = fixture;
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

    // The paid finalize's still-retained collateral is forfeited with the
    // governance-confirmed poison; it cannot be returned to the fraud solver.
    assert.equal(await submissions.claimableBondWei(carol.address), 0n);
    assert.equal(await submissions.claimableBondWei(treasury.address), fraud.bond);

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
    // ...and a second superseded finalize that exactly TIES the live frontier
    // (claimed == best == 400): 0 marginal, no frontier movement.
    const tie = await commitReveal(fixture, carol, 400n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const tieArgs = await finalizeAndParse(fixture, carol, tie.submissionId);
    assert.equal(tieArgs.creditAtoms, 0n);

    await submissions.connect(owner).setPausedAll(true);
    // alice's credited finalize is no longer the live frontier: refused —
    // restoring ITS prevBest over bob's better score would corrupt the frontier.
    await expectCustomError(
      submissions.connect(owner).voidFinalize(a.submissionId),
      submissions,
      "P42_VOID_NOT_FRONTIER"
    );
    // carol's superseded 450 is behind the live frontier: refused at the tip check.
    await expectCustomError(
      submissions.connect(owner).voidFinalize(c.submissionId),
      submissions,
      "P42_VOID_NOT_FRONTIER"
    );
    // carol's frontier-TYING finalize passes the tip check (best == claimed)
    // but never moved the frontier (prevBest == claimed): refused — voiding it
    // would restore a frontier this finalize never advanced from.
    await expectCustomError(
      submissions.connect(owner).voidFinalize(tie.submissionId),
      submissions,
      "P42_VOID_NOT_ADVANCE"
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
    await submissions.connect(alice).commit(commitment, DA_HASH, {
      value: await submissions.requiredPostingBondNow(),
    });
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

    // Disarm: finalization can resume, but a hard-expired commitment cannot be
    // resurrected by a governance pause.
    await submissions.connect(owner).setPausedAll(false);
    await expectCustomError(
      submissions.connect(alice).reveal(committedId, cid, 700n * SCALE, 1n, salt, "0x"),
      submissions,
      "P42_COMMIT_EXPIRED"
    );
    await submissions.connect(bob).finalize(revealed.submissionId, PERMANENCE_HASH);
    assert.equal(await submissions.bestScoreAtoms(), 600n * SCALE);
  });

  it("voidCredit enforces recorder scope and checked balance math", async function () {
    const [owner, treasury, recorder, alice] = await ethers.getSigners();
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const pool = await Pool.deploy(owner.address, FUNDING_CAP);
    await pool.waitForDeployment();
    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const ledger = await Ledger.deploy(
      await pool.getAddress(), owner.address, treasury.address, 0,
      await nextEarliestClose(), await nextCloseBy()
    );
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
    await advanceToEffectiveClose(ledger);
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

  // ===========================================================================
  // OPEN-WITNESS-PHASE seeding redesign: the seed is only a LOOSE ceiling (no
  // human attestation). During the unpaid OPEN phase anyone posts witnesses
  // for free — each verified strict improvement advances bestScoreAtoms but
  // records ZERO credit, establishing the true public frontier on-chain by
  // construction. armFunding(digest) (owner, one-shot) then opens the PAID phase:
  // the pool accepts ETH and finalized improvements earn the marginal over
  // the open-established frontier. One call is the single arm authority for
  // both credit and deposits.
  // ===========================================================================

  it("armFunding is owner-only, one-shot, and emits FundingArmed", async function () {
    const fixture = await deployFixture({ arm: false, advanceCompetition: false });
    const { owner, treasury, alice, authorities, submissions } = fixture;
    assert.equal(await submissions.fundingArmed(), false);
    const deployedAt = await submissions.deployedAt();
    const armNotBefore = await submissions.armNotBefore();
    assert.equal(armNotBefore, deployedAt + CHALLENGE_WINDOW_SECONDS);

    await expectCustomError(submissions.connect(alice).armFunding("0x" + "42".repeat(32)), submissions, "P42_NOT_OWNER");
    assert.equal(await submissions.fundingArmed(), false);
    await expectCustomError(authorizeFunding(submissions, alice, authorities, "0x" + "42".repeat(32), 2n ** 64n - 1n), submissions, "P42_NOT_FUNDING_AUTHORIZER");
    await authorizeFunding(submissions, treasury, authorities, "0x" + "42".repeat(32), 2n ** 64n - 1n);

    await expectCustomError(
      submissions.connect(owner).armFunding("0x" + "42".repeat(32)),
      submissions,
      "P42_OPEN_WITNESS_WINDOW_OPEN"
    );
    assert.equal(await submissions.fundingArmed(), false);

    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await expectCustomError(
      submissions.connect(owner).armFunding("0x" + "00".repeat(32)),
      submissions,
      "P42_FUNDING_AUTHORIZATION_ZERO"
    );
    const authorizationDigest = "0x" + "42".repeat(32);
    await expectCustomError(
      submissions.connect(owner).armFunding("0x" + "43".repeat(32)),
      submissions,
      "P42_FUNDING_AUTHORIZATION_MISMATCH"
    );
    const tx = await submissions.connect(owner).armFunding(authorizationDigest);
    const receipt = await tx.wait();
    const armed = receipt.logs
      .map((log) => {
        try {
          return submissions.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed && parsed.name === "FundingArmed");
    assert.ok(armed, "FundingArmed event present");
    // NB: positional access — `args.at` hits ethers' Result.prototype.at.
    assert.ok(armed.args[0] > 0n);
    assert.equal(armed.args.authorizationDigest, authorizationDigest);
    assert.equal(await submissions.fundingArmed(), true);
    assert.equal(await submissions.fundingAuthorizationDigest(), authorizationDigest);

    // One-way: arming twice is refused, so the phase switch cannot be replayed.
    await expectCustomError(submissions.connect(owner).armFunding("0x" + "42".repeat(32)), submissions, "P42_FUNDING_ALREADY_ARMED");
  });

  it("cannot arm or open deposits after the launch authorization expires", async function () {
    const lateArm = await deployFixture({ arm: false, advanceCompetition: false });
    const lateArmBlock = await ethers.provider.getBlock("latest");
    const lateArmExpiry = BigInt(lateArmBlock.timestamp) + CHALLENGE_WINDOW_SECONDS;
    await authorizeFunding(lateArm.submissions, lateArm.treasury, lateArm.authorities, "0x" + "42".repeat(32), lateArmExpiry);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await expectCustomError(
      lateArm.submissions.connect(lateArm.owner).armFunding("0x" + "42".repeat(32)),
      lateArm.submissions,
      "P42_FUNDING_AUTHORIZATION_EXPIRED"
    );

    const lateOpen = await deployFixture({ arm: false, advanceCompetition: false });
    const lateOpenBlock = await ethers.provider.getBlock("latest");
    const lateOpenExpiry = BigInt(lateOpenBlock.timestamp) + CHALLENGE_WINDOW_SECONDS + 10n;
    await authorizeFunding(lateOpen.submissions, lateOpen.treasury, lateOpen.authorities, "0x" + "42".repeat(32), lateOpenExpiry);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await lateOpen.submissions.connect(lateOpen.owner).armFunding("0x" + "42".repeat(32));
    await increaseTime(10n);
    await expectCustomError(
      lateOpen.pool.connect(lateOpen.owner).setAcceptingFunds(true),
      lateOpen.pool,
      "P42_FUNDING_AUTHORIZATION_EXPIRED"
    );
  });

  it("keeps an authorization immutable through exact expiry, then permits replacement", async function () {
    const fixture = await deployFixture({ arm: false, advanceCompetition: false });
    const { owner, treasury, authorities, submissions } = fixture;
    const originalDigest = "0x" + "42".repeat(32);
    const replacementDigest = "0x" + "43".repeat(32);
    const latest = await ethers.provider.getBlock("latest");
    const expiresAt = BigInt(latest.timestamp) + CHALLENGE_WINDOW_SECONDS;

    await authorizeFunding(submissions, treasury, authorities, originalDigest, expiresAt);
    await expectCustomError(
      authorizeFunding(submissions, treasury, authorities, replacementDigest, expiresAt + 1n),
      submissions,
      "P42_FUNDING_AUTHORIZATION_ACTIVE"
    );
    assert.equal(await submissions.authorizedFundingDigest(), originalDigest);
    assert.equal(await submissions.fundingAuthorizationExpiresAt(), expiresAt);

    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(expiresAt)]);
    await expectCustomError(
      authorizeFunding(submissions, treasury, authorities, replacementDigest, expiresAt + 1n),
      submissions,
      "P42_FUNDING_AUTHORIZATION_ACTIVE"
    );
    assert.equal(await submissions.authorizedFundingDigest(), originalDigest);

    const replacementExpiresAt = expiresAt + CHALLENGE_WINDOW_SECONDS;
    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(expiresAt + 1n)]);
    await authorizeFunding(submissions, treasury, authorities, replacementDigest, replacementExpiresAt);
    assert.equal(await submissions.authorizedFundingDigest(), replacementDigest);
    assert.equal(await submissions.fundingAuthorizationExpiresAt(), replacementExpiresAt);

    await submissions.connect(owner).armFunding(replacementDigest);
    assert.equal(await submissions.fundingArmed(), true);
    assert.equal(await submissions.fundingAuthorizationDigest(), replacementDigest);
  });

  it("requires owner and exact digest to cancel an active funding authorization", async function () {
    const fixture = await deployFixture({ arm: false, advanceCompetition: false });
    const { owner, treasury, alice, authorities, submissions } = fixture;
    const authorizationDigest = "0x" + "42".repeat(32);
    const wrongDigest = "0x" + "43".repeat(32);
    const expiresAt = 2n ** 64n - 1n;

    await authorizeFunding(submissions, treasury, authorities, authorizationDigest, expiresAt);
    await expectCustomError(
      submissions.connect(owner).cancelFundingAuthorization(wrongDigest),
      submissions,
      "P42_FUNDING_AUTHORIZATION_MISMATCH"
    );
    await expectCustomError(
      submissions.connect(alice).cancelFundingAuthorization(authorizationDigest),
      submissions,
      "P42_NOT_OWNER"
    );
    assert.equal(await submissions.authorizedFundingDigest(), authorizationDigest);
    assert.equal(await submissions.fundingAuthorizationExpiresAt(), expiresAt);
  });

  it("owner can cancel a max-expiry authorization so treasury can replace it", async function () {
    const fixture = await deployFixture({ arm: false, advanceCompetition: false });
    const { owner, treasury, authorities, submissions } = fixture;
    const typoDigest = "0x" + "42".repeat(32);
    const replacementDigest = "0x" + "43".repeat(32);
    const maxExpiry = 2n ** 64n - 1n;

    await authorizeFunding(submissions, treasury, authorities, typoDigest, maxExpiry);
    await expectCustomError(
      authorizeFunding(submissions, treasury, authorities, replacementDigest, maxExpiry),
      submissions,
      "P42_FUNDING_AUTHORIZATION_ACTIVE"
    );

    const tx = await submissions.connect(owner).cancelFundingAuthorization(typoDigest);
    const receipt = await tx.wait();
    const cancelled = receipt.logs
      .map((log) => {
        try {
          return submissions.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed && parsed.name === "FundingAuthorizationCancelled");
    assert.ok(cancelled, "FundingAuthorizationCancelled event present");
    assert.equal(cancelled.args.authorizationDigest, typoDigest);
    assert.equal(cancelled.args.canceller, owner.address);
    assert.equal(cancelled.args.expiresAt, maxExpiry);
    assert.equal(await submissions.authorizedFundingDigest(), ethers.ZeroHash);
    assert.equal(await submissions.fundingAuthorizationExpiresAt(), 0n);

    await authorizeFunding(submissions, treasury, authorities, replacementDigest, maxExpiry);
    assert.equal(await submissions.authorizedFundingDigest(), replacementDigest);
    assert.equal(await submissions.fundingAuthorizationExpiresAt(), maxExpiry);
  });

  it("rejects funding authorization cancellation after arming", async function () {
    const fixture = await deployFixture({ arm: false, advanceCompetition: false });
    const { owner, treasury, authorities, submissions } = fixture;
    const authorizationDigest = "0x" + "42".repeat(32);

    await authorizeFunding(submissions, treasury, authorities, authorizationDigest, 2n ** 64n - 1n);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.connect(owner).armFunding(authorizationDigest);
    await expectCustomError(
      submissions.connect(owner).cancelFundingAuthorization(authorizationDigest),
      submissions,
      "P42_FUNDING_ALREADY_ARMED"
    );
    assert.equal(await submissions.authorizedFundingDigest(), authorizationDigest);
    assert.equal(await submissions.fundingAuthorizationDigest(), authorizationDigest);
  });

  it("the pool refuses deposits (fund and receive) until armFunding — no ETH strandable in the open phase", async function () {
    const fixture = await deployFixture({ arm: false });
    const { owner, alice, pool, submissions } = fixture;

    // Wired but not armed: both deposit paths revert with the named error.
    await expectCustomError(pool.fund({ value: 1n }), pool, "P42_FUNDING_NOT_ARMED");
    await expectCustomError(
      alice.sendTransaction({ to: await pool.getAddress(), value: 1n }),
      pool,
      "P42_FUNDING_NOT_ARMED"
    );
    assert.equal(await pool.funded(), 0n);

    // A pool with NO submission manager wired refuses deposits too (fail closed).
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const unwired = await Pool.deploy(owner.address, FUNDING_CAP);
    await unwired.waitForDeployment();
    await expectCustomError(unwired.fund({ value: 1n }), unwired, "P42_FUNDING_NOT_ARMED");

    // setSubmissionManager mirrors setLedger: owner-only, one-time.
    await expectCustomError(
      pool.connect(alice).setSubmissionManager(alice.address),
      pool,
      "P42_NOT_OWNER"
    );
    await expectCustomError(
      pool.connect(owner).setSubmissionManager(alice.address),
      pool,
      "P42_SUBMISSION_MANAGER_ALREADY_SET"
    );

    // The single arm call opens the deposit path.
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await authorizeFunding(submissions, fixture.treasury, fixture.authorities, "0x" + "42".repeat(32), 2n ** 64n - 1n);
    await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
    await pool.connect(owner).setAcceptingFunds(true);
    await pool.fund({ value: ethers.parseEther("1") });
    await alice.sendTransaction({ to: await pool.getAddress(), value: ethers.parseEther("0.5") });
    assert.equal(await pool.funded(), ethers.parseEther("1.5"));
  });

  it("stops paid commits if objective proof capability becomes inactive after arming", async function () {
    const fixture = await deployFixture();
    await fixture.capability.gateway.setObjectiveProofsActive(false);
    const commitment = ethers.id("capability-loss-commitment");
    const bond = await fixture.submissions.requiredPostingBondNow();

    await expectCustomError(
      fixture.submissions.connect(fixture.alice).commit(commitment, DA_HASH, { value: bond }),
      fixture.submissions,
      "P42_OBJECTIVE_PROOF_CAPABILITY_INACTIVE"
    );
    assert.equal(await fixture.submissions.submissionCount(), 0n);
  });

  it("open phase: free witness postings advance the frontier but record zero credit — the pool pays nothing for pre-arm work", async function () {
    const fixture = await deployFixture({ arm: false, feeBps: 0 });
    const { alice, bob, pool, ledger, submissions } = fixture;

    // Alice's witness: seed 1000 -> 600. The frontier advances...
    const a = await commitReveal(fixture, alice, 600n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const aArgs = await finalizeAndParse(fixture, alice, a.submissionId);
    assert.equal(aArgs.creditAtoms, 0n); // ...but earns NOTHING pre-arm.
    assert.equal(aArgs.bestScoreAtoms, 600n * SCALE);
    assert.equal(await submissions.bestScoreAtoms(), 600n * SCALE);
    assert.equal(await ledger.creditAtomsOf(alice.address), 0n);
    // The bond is fully reclaimable: witness posting is free, not slashed.
    assert.equal(await submissions.claimableBondWei(alice.address), a.bond);

    // Bob's witness tightens it further: 600 -> 500, still unpaid.
    const b = await commitReveal(fixture, bob, 500n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const bArgs = await finalizeAndParse(fixture, bob, b.submissionId);
    assert.equal(bArgs.creditAtoms, 0n);
    assert.equal(await submissions.bestScoreAtoms(), 500n * SCALE);
    assert.equal(await ledger.creditAtomsOf(bob.address), 0n);
    assert.equal(await ledger.totalCreditAtoms(), 0n);

    // The recovery snapshot still records the true prevBest (credit 0).
    const info = await submissions.finalizeInfo(b.submissionId);
    assert.equal(info.prevBestScoreAtoms, 600n * SCALE);
    assert.equal(info.creditAtoms, 0n);

    // The pool holds nothing and owes nothing: pre-arm work is unpayable.
    assert.equal(await pool.funded(), 0n);
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    assert.equal(await ledger.finalEntitlement(alice.address), 0n);
    assert.equal(await ledger.finalEntitlement(bob.address), 0n);
  });

  it("after armFunding a paid submission earns the marginal over the OPEN-established frontier, not the seed-relative distance", async function () {
    const fixture = await deployFixture({ arm: false, feeBps: 0 });
    const { owner, treasury, alice, bob, carol, pool, ledger, submissions } = fixture;

    // Open phase establishes the true public frontier: 1000 -> 600 -> 500.
    const a = await commitReveal(fixture, alice, 600n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await finalizeAndParse(fixture, alice, a.submissionId);
    const b = await commitReveal(fixture, bob, 500n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await finalizeAndParse(fixture, bob, b.submissionId);
    assert.equal(await submissions.bestScoreAtoms(), 500n * SCALE);
    assert.equal(await ledger.totalCreditAtoms(), 0n);

    // The funder arms: pool accepts ETH, finalize starts crediting.
    await authorizeFunding(submissions, treasury, fixture.authorities, "0x" + "42".repeat(32), 2n ** 64n - 1n);
    await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
    await pool.connect(owner).setAcceptingFunds(true);
    await pool.fund({ value: ethers.parseEther("5") });

    // Carol beats the OPEN-established 500 with 400: paid the marginal 100 —
    // never the seed-relative 600 the old attested-seed design would imply.
    const c = await commitReveal(fixture, carol, 400n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const cArgs = await finalizeAndParse(fixture, carol, c.submissionId);
    assert.equal(cArgs.creditAtoms, 100n * SCALE);
    assert.notEqual(cArgs.creditAtoms, SEED - 400n * SCALE); // not seed-relative
    assert.equal(await submissions.bestScoreAtoms(), 400n * SCALE);
    assert.equal(await ledger.creditAtomsOf(carol.address), 100n * SCALE);
    assert.equal(await ledger.totalCreditAtoms(), 100n * SCALE);
    // The open-phase witnesses stay unpaid even after arming.
    assert.equal(await ledger.creditAtomsOf(alice.address), 0n);
    assert.equal(await ledger.creditAtomsOf(bob.address), 0n);

    // Carol holds ALL recorded credit, so she claims the whole pool.
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    assert.equal(await ledger.finalEntitlement(carol.address), await ledger.distributablePool());
    await pool.connect(carol).claim();
    assert.equal(await ledger.claimedWeiOf(carol.address), ethers.parseEther("5"));
  });

  it("voidFinalize recovers an OPEN-PHASE poisoning (credit == 0) so honest witness postings can resume", async function () {
    const fixture = await deployFixture({ arm: false, feeBps: 0 });
    const { owner, alice, bob, carol, pool, ledger, submissions } = fixture;

    // Carol poisons the OPEN frontier with a fraudulent, unreachably low score.
    // It earns 0 credit (unarmed) — the old credit>0 void guard would have
    // made exactly this fraud unrecoverable.
    const fraud = await commitReveal(fixture, carol, 1n);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const fraudArgs = await finalizeAndParse(fixture, carol, fraud.submissionId);
    assert.equal(fraudArgs.creditAtoms, 0n);
    assert.equal(await submissions.bestScoreAtoms(), 1n);

    // Honest witnesses are bricked: a real 500 cannot advance the poisoned tip.
    const honest = await commitReveal(fixture, alice, 500n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const honestArgs = await finalizeAndParse(fixture, alice, honest.submissionId);
    assert.equal(honestArgs.creditAtoms, 0n);
    assert.equal(await submissions.bestScoreAtoms(), 1n); // frontier untouched

    // Recovery under the full pause: the void restores the frontier and calls
    // NO ledger voidCredit (there is no credit — voiding 0 would revert there).
    await submissions.connect(owner).setPausedAll(true);
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
    assert.equal(voided.args.creditAtoms, 0n);
    assert.equal(voided.args.restoredBestScoreAtoms, SEED);
    assert.equal(await submissions.bestScoreAtoms(), SEED);
    assert.equal((await submissions.submissions(fraud.submissionId)).status, 6n); // Voided
    assert.equal(await ledger.totalCreditAtoms(), 0n);
    // No double-void.
    await expectCustomError(
      submissions.connect(owner).voidFinalize(fraud.submissionId),
      submissions,
      "P42_BAD_SUBMISSION_STATUS"
    );

    // Honest witness posting resumes against the restored frontier...
    await submissions.connect(owner).setPausedAll(false);
    const fresh = await commitReveal(fixture, bob, 450n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const freshArgs = await finalizeAndParse(fixture, bob, fresh.submissionId);
    assert.equal(freshArgs.creditAtoms, 0n); // still open phase
    assert.equal(await submissions.bestScoreAtoms(), 450n * SCALE);

    // ...and after arming, paid work earns the marginal over that frontier.
    await authorizeFunding(submissions, fixture.treasury, fixture.authorities, "0x" + "42".repeat(32), 2n ** 64n - 1n);
    await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
    await pool.connect(owner).setAcceptingFunds(true);
    await pool.fund({ value: ethers.parseEther("1") });
    const paid = await commitReveal(fixture, alice, 400n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const paidArgs = await finalizeAndParse(fixture, alice, paid.submissionId);
    assert.equal(paidArgs.creditAtoms, 50n * SCALE);
    assert.equal(await ledger.creditAtomsOf(alice.address), 50n * SCALE);
  });

  it("pausedAll freezes the expiry tolls: no bond can be forfeited while a recovery blocks acting", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { owner, alice, bob, treasury, submissions } = fixture;

    // Stage an in-flight commit and an in-flight reveal, then let BOTH expiry
    // clocks run out while the contract is under the recovery-grade pause.
    const cid = "bafy-toll-frozen-commit";
    const salt = "toll-frozen-salt";
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
      cid,
      alice.address,
      DA_HASH,
      salt
    );
    const committedBond = await submissions.requiredPostingBondNow();
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: committedBond });
    const committedId = await submissions.submissionCount();
    const revealed = await commitReveal(fixture, bob, 600n * SCALE);

    await submissions.connect(owner).setPausedAll(true);
    await increaseTime(2n * CHALLENGE_WINDOW_SECONDS + 2n); // both tolls elapsed

    // The frozen solvers cannot reveal/finalize — so the tolls must not fire:
    // expiring now would forfeit honest bonds to the treasury during recovery.
    await expectCustomError(submissions.expireCommitted(committedId), submissions, "P42_PAUSED_ALL");
    await expectCustomError(submissions.expireRevealed(revealed.submissionId), submissions, "P42_PAUSED_ALL");
    assert.equal(await submissions.claimableBondWei(treasury.address), 0n);

    // Once the recovery ends, a FULL fresh challenge window must pass before any
    // expiry can fire — otherwise a solver frozen out by the recovery would be
    // instantly expirable the moment it can finally act. So expiry is STILL
    // blocked right after unpause...
    await submissions.connect(owner).setPausedAll(false);
    await expectCustomError(submissions.expireCommitted(committedId), submissions, "P42_REVEAL_WINDOW_OPEN");
    await expectCustomError(submissions.expireRevealed(revealed.submissionId), submissions, "P42_PERMANENCE_GRACE_OPEN");
    assert.equal(await submissions.claimableBondWei(treasury.address), 0n);

    // ...and only fires after the fresh grace window elapses (the solver had a
    // real chance to act and did not).
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.expireCommitted(committedId);
    await submissions.expireRevealed(revealed.submissionId);
    assert.equal(
      await submissions.claimableBondWei(treasury.address),
      committedBond + revealed.bond
    );
  });

  // -------------------------------------------------------------------------
  // BLOCKER fix: credit is bound to the COMMIT phase, not the finalize phase.
  // A witness committed+revealed for free in the OPEN phase cannot earn by
  // withholding finalize across armFunding.
  // -------------------------------------------------------------------------
  it("does not pay a pre-arm (open-phase) commit even if its finalize is withheld across armFunding", async function () {
    const fixture = await deployFixture({ arm: false }); // start in the OPEN (unpaid) phase
    const { owner, treasury, alice, bob, pool, ledger, submissions } = fixture;

    // Alice commits + reveals a strong score DURING the open phase (for free),
    // but does NOT finalize — she waits to straddle the arm.
    const attack = await commitReveal(fixture, alice, 600n * SCALE);

    // Funder arms; pool is funded.
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await authorizeFunding(submissions, treasury, fixture.authorities, "0x" + "42".repeat(32), 2n ** 64n - 1n);
    await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
    await pool.connect(owner).setAcceptingFunds(true);
    await pool.connect(owner).fund({ value: ethers.parseEther("1") });

    // Alice finalizes AFTER the arm. The frontier still advances (free), but she
    // earns ZERO — her commit predates armedAt.
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const args = await finalizeAndParse(fixture, alice, attack.submissionId);
    assert.equal(args.creditAtoms, 0n);
    assert.equal(await ledger.creditAtomsOf(alice.address), 0n);
    assert.equal(await submissions.bestScoreAtoms(), 600n * SCALE); // frontier advanced for free

    // An honest solver who COMMITS post-arm earns the marginal over that frontier.
    const honest = await commitReveal(fixture, bob, 500n * SCALE);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const honestArgs = await finalizeAndParse(fixture, bob, honest.submissionId);
    assert.equal(honestArgs.creditAtoms, 100n * SCALE); // 600 - 500, not seed-relative
    assert.equal(await ledger.creditAtomsOf(bob.address), 100n * SCALE);
    assert.equal(await ledger.totalCreditAtoms(), 100n * SCALE); // Alice's free work never counted
  });
});
