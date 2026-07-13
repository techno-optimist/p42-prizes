import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

const CHALLENGE_WINDOW = 100n;
const FRAUD_WINDOW = 50n;
const MIN_CLOSE_DELAY = 180n * 24n * 60n * 60n;
const MIN_BOND = ethers.parseEther("0.01");
const DEFAULT_CAP = ethers.parseEther("1");
const SEED_SCORE = 1_000_000n;
const SCORE = 1_000n;
const DA_HASH = ethers.id("p42-audit-da");
const PERMANENCE_HASH = ethers.id("p42-audit-permanence");

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
  await ethers.provider.send("evm_increaseTime", [Number(seconds)]);
  await ethers.provider.send("evm_mine", []);
}

async function advanceTo(timestamp) {
  const latest = await ethers.provider.getBlock("latest");
  const remaining = timestamp - BigInt(latest.timestamp);
  if (remaining > 0n) await increaseTime(remaining);
}

async function deployFixture({
  alphaBps = 200n,
  fundingCap = DEFAULT_CAP,
  freeze = true,
  arm = true,
  acceptFunds = freeze && arm,
} = {}) {
  const [owner, treasury, resolver, alice, bob, carol, outsider] = await ethers.getSigners();
  const latest = await ethers.provider.getBlock("latest");
  const earliestClose = BigInt(latest.timestamp) + 30n * 24n * 60n * 60n + 1_000n;
  const closeBy = BigInt(latest.timestamp) + MIN_CLOSE_DELAY + 1_000n;

  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address, fundingCap);
  await pool.waitForDeployment();

  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasury.address, 0, earliestClose, closeBy
  );
  await ledger.waitForDeployment();
  await pool.connect(owner).setLedger(await ledger.getAddress());

  const Submissions = await ethers.getContractFactory("P42SubmissionManager");
  const submissions = await Submissions.deploy(
    await pool.getAddress(),
    await ledger.getAddress(),
    owner.address,
    treasury.address,
    alphaBps,
    MIN_BOND,
    CHALLENGE_WINDOW,
    false,
    0,
    SEED_SCORE,
    1n
  );
  await submissions.waitForDeployment();
  await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());
  await pool.connect(owner).setSubmissionManager(await submissions.getAddress());

  const Challenges = await ethers.getContractFactory("P42ChallengeManager");
  const challenges = await Challenges.deploy(
    owner.address,
    resolver.address,
    treasury.address,
    await submissions.getAddress(),
    CHALLENGE_WINDOW,
    500n,
    ethers.parseEther("0.02"),
    ethers.parseEther("0.01"),
    30_000n,
    ethers.parseEther("0.005"),
    FRAUD_WINDOW
  );
  await challenges.waitForDeployment();
  await submissions.connect(owner).setChallengeManager(await challenges.getAddress());

  const Registry = await ethers.getContractFactory("P42ProblemRegistry");
  const registry = await Registry.deploy(owner.address);
  await registry.waitForDeployment();
  await registry.register({
    specHash: ethers.id("audit-spec"),
    verifierSourceHash: ethers.id("audit-source"),
    verifierImageHash: ethers.id("audit-image"),
    admissionMatrixHash: ethers.id("audit-matrix"),
    metadataURI: "ipfs://p42-audit-fixture",
    pool: await pool.getAddress(),
    ledger: await ledger.getAddress(),
    submissionManager: await submissions.getAddress(),
    challengeManager: await challenges.getAddress(),
    challengeWindowSeconds: CHALLENGE_WINDOW,
    minImprovementAtoms: 1n,
  });
  await pool.connect(owner).setRegistry(await registry.getAddress(), 1);
  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), owner.address);
  await vault.waitForDeployment();
  await ledger.connect(owner).setRolloverDestination(await vault.getAddress());
  if (freeze) await registry.connect(owner).freeze(1);
  if (arm) {
    await increaseTime(CHALLENGE_WINDOW + 1n);
    await submissions.connect(treasury).authorizeFunding("0x" + "42".repeat(32), 2n ** 64n - 1n);
    await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
  }
  if (acceptFunds) await pool.connect(owner).setAcceptingFunds(true);

  return {
    owner,
    treasury,
    resolver,
    alice,
    bob,
    carol,
    outsider,
    pool,
    ledger,
    submissions,
    challenges,
    registry,
    vault,
    earliestClose,
    closeBy,
  };
}

async function commitmentFor(submissions, solver, cid, salt) {
  return submissions["computeCommitment(string,address,bytes32,string)"](
    cid, solver.address, DA_HASH, salt
  );
}

async function commitOnly(fixture, solver, { cid, salt }) {
  const commitment = await commitmentFor(fixture.submissions, solver, cid, salt);
  const bond = await fixture.submissions.requiredPostingBondNow();
  await fixture.submissions.connect(solver).commit(commitment, DA_HASH, { value: bond });
  return { submissionId: await fixture.submissions.submissionCount(), commitment, bond, cid, salt };
}

async function commitAndReveal(fixture, solver, { cid, salt, score = SCORE }) {
  const committed = await commitOnly(fixture, solver, { cid, salt });
  await fixture.submissions
    .connect(solver)
    .reveal(committed.submissionId, cid, score, 1n, salt, "0x");
  return committed;
}

async function openChallenge(fixture, signer, submissionId, reasonHash, overrides) {
  return fixture.challenges.connect(signer).challenge(
    submissionId,
    await fixture.submissions.revealInstanceHashOf(submissionId),
    reasonHash,
    overrides,
  );
}

async function resolveChallenge(fixture, signer, submissionId, challengerWins, transcriptHash, transcriptURI, verdictHash, overrides) {
  return fixture.challenges.connect(signer).resolve(
    submissionId,
    await fixture.challenges.challengeInstanceHashOf(submissionId),
    challengerWins,
    transcriptHash,
    transcriptURI,
    verdictHash,
    overrides,
  );
}

async function finalizeChallengeResolution(fixture, submissionId) {
  return fixture.challenges.finalizeResolution(
    submissionId,
    await fixture.challenges.challengeInstanceHashOf(submissionId),
  );
}

async function expireChallenge(fixture, submissionId) {
  return fixture.challenges.expireChallenge(
    submissionId,
    await fixture.challenges.challengeInstanceHashOf(submissionId),
  );
}

async function slashResolverBond(fixture, submissionId, proofHash) {
  return fixture.challenges.connect(fixture.resolver).slashResolverBond(
    submissionId,
    await fixture.challenges.challengeInstanceHashOf(submissionId),
    proofHash,
  );
}

describe("P42 2026-07-09 economic and lifecycle audit regressions", function () {
  it("stores commit phase identity for both transaction orders in one block", async function () {
    const preArm = await deployFixture({ arm: false, acceptFunds: false });
    await increaseTime(CHALLENGE_WINDOW + 1n);
    const preCid = "bafy-phase-before-arm";
    const preSalt = "phase-before-arm";
    const preCommitment = await commitmentFor(preArm.submissions, preArm.owner, preCid, preSalt);
    const preNonce = await preArm.owner.getNonce();
    await preArm.submissions.connect(preArm.treasury).authorizeFunding("0x" + "42".repeat(32), 2n ** 64n - 1n);
    let preCommitTx;
    let preArmTx;

    await ethers.provider.send("evm_setAutomine", [false]);
    try {
      preCommitTx = await preArm.submissions.connect(preArm.owner).commit(preCommitment, DA_HASH, {
        value: MIN_BOND,
        nonce: preNonce,
        gasLimit: 1_000_000n,
      });
      preArmTx = await preArm.submissions.connect(preArm.owner).armFunding("0x" + "42".repeat(32), {
        nonce: preNonce + 1,
        gasLimit: 1_000_000n,
      });
      await ethers.provider.send("evm_mine", []);
    } finally {
      await ethers.provider.send("evm_setAutomine", [true]);
    }
    const preCommitReceipt = await preCommitTx.wait();
    const preArmReceipt = await preArmTx.wait();
    assert.equal(preCommitReceipt.blockNumber, preArmReceipt.blockNumber);
    assert.equal(await preArm.submissions.paidAtCommit(1), false);
    await preArm.pool.connect(preArm.owner).setAcceptingFunds(true);
    await preArm.submissions.connect(preArm.owner).reveal(1, preCid, SCORE, 1n, preSalt, "0x");
    await increaseTime(CHALLENGE_WINDOW + 1n);
    await preArm.submissions.connect(preArm.owner).finalize(1, PERMANENCE_HASH);
    assert.equal(await preArm.ledger.totalCreditAtoms(), 0n);

    const postArm = await deployFixture({ arm: false, acceptFunds: false });
    await increaseTime(CHALLENGE_WINDOW + 1n);
    const postCid = "bafy-phase-after-arm";
    const postSalt = "phase-after-arm";
    const postCommitment = await commitmentFor(postArm.submissions, postArm.owner, postCid, postSalt);
    const capBond = await postArm.submissions.requiredPostingBondForPool(DEFAULT_CAP);
    const postNonce = await postArm.owner.getNonce();
    let postArmTx;
    let postCommitTx;

    await postArm.submissions.connect(postArm.treasury).authorizeFunding("0x" + "42".repeat(32), 2n ** 64n - 1n);
    await ethers.provider.send("evm_setAutomine", [false]);
    try {
      postArmTx = await postArm.submissions.connect(postArm.owner).armFunding("0x" + "42".repeat(32), {
        nonce: postNonce,
        gasLimit: 1_000_000n,
      });
      postCommitTx = await postArm.submissions.connect(postArm.owner).commit(postCommitment, DA_HASH, {
        value: capBond,
        nonce: postNonce + 1,
        gasLimit: 1_000_000n,
      });
      await ethers.provider.send("evm_mine", []);
    } finally {
      await ethers.provider.send("evm_setAutomine", [true]);
    }
    const postArmReceipt = await postArmTx.wait();
    const postCommitReceipt = await postCommitTx.wait();
    assert.equal(postArmReceipt.blockNumber, postCommitReceipt.blockNumber);
    assert.equal(await postArm.submissions.paidAtCommit(1), true);
    await postArm.pool.connect(postArm.owner).setAcceptingFunds(true);
    await postArm.submissions.connect(postArm.owner).reveal(1, postCid, SCORE, 1n, postSalt, "0x");
    await increaseTime(CHALLENGE_WINDOW + 1n);
    await postArm.submissions.connect(postArm.owner).finalize(1, PERMANENCE_HASH);
    assert.equal(await postArm.ledger.totalCreditAtoms(), SEED_SCORE - SCORE);
  });

  it("rejects a copied pending reveal committed and revealed before the original in one block", async function () {
    const fixture = await deployFixture();
    const cid = "bafy-public-pending-solution";
    const salt = "public-pending-salt";
    const original = await commitOnly(fixture, fixture.alice, { cid, salt });
    const copiedCommitment = await commitmentFor(fixture.submissions, fixture.bob, cid, salt);
    const copyBond = await fixture.submissions.requiredPostingBondNow();
    const bobNonce = await fixture.bob.getNonce();
    const aliceNonce = await fixture.alice.getNonce();
    let copyCommitTx;
    let copyRevealTx;
    let originalRevealTx;

    await ethers.provider.send("evm_setAutomine", [false]);
    try {
      copyCommitTx = await fixture.submissions.connect(fixture.bob).commit(copiedCommitment, DA_HASH, {
        value: copyBond,
        nonce: bobNonce,
        gasLimit: 1_000_000n,
        gasPrice: 100_000_000_000n,
      });
      copyRevealTx = await fixture.submissions.connect(fixture.bob).reveal(
        2, cid, SCORE, 1n, salt, "0x",
        {
          nonce: bobNonce + 1,
          gasLimit: 1_000_000n,
          gasPrice: 100_000_000_000n,
        }
      );
      originalRevealTx = await fixture.submissions.connect(fixture.alice).reveal(
        original.submissionId, cid, SCORE, 1n, salt, "0x",
        {
          nonce: aliceNonce,
          gasLimit: 1_000_000n,
          gasPrice: 10_000_000_000n,
        }
      );
      await ethers.provider.send("evm_mine", []);
    } finally {
      await ethers.provider.send("evm_setAutomine", [true]);
    }

    const copyCommitReceipt = await ethers.provider.getTransactionReceipt(copyCommitTx.hash);
    const copyRevealReceipt = await ethers.provider.getTransactionReceipt(copyRevealTx.hash);
    const originalRevealReceipt = await ethers.provider.getTransactionReceipt(originalRevealTx.hash);
    assert.equal(copyCommitReceipt.blockNumber, copyRevealReceipt.blockNumber);
    assert.equal(copyRevealReceipt.blockNumber, originalRevealReceipt.blockNumber);
    assert.equal(copyCommitReceipt.index < copyRevealReceipt.index, true);
    assert.equal(copyRevealReceipt.index < originalRevealReceipt.index, true);
    assert.equal(copyCommitReceipt.status, 1);
    assert.equal(copyRevealReceipt.status, 0);
    assert.equal(originalRevealReceipt.status, 1);
    assert.equal((await fixture.submissions.submissions(2)).status, 1n);
    assert.equal((await fixture.submissions.submissions(original.submissionId)).status, 2n);
  });

  it("permits post-finalize donations only up to the cap and retains paid collateral until close", async function () {
    const fixture = await deployFixture({ alphaBps: 100n });
    const submission = await commitAndReveal(fixture, fixture.alice, {
      cid: "bafy-late-donation",
      salt: "late-donation",
    });
    assert.equal(submission.bond, MIN_BOND);
    await increaseTime(CHALLENGE_WINDOW + 1n);
    await fixture.submissions.connect(fixture.alice).finalize(submission.submissionId, PERMANENCE_HASH);
    assert.equal((await fixture.submissions.submissions(submission.submissionId)).bondWei, MIN_BOND);
    assert.equal(await fixture.submissions.claimableBondWei(fixture.alice.address), 0n);

    await fixture.pool.connect(fixture.bob).fund({ value: ethers.parseEther("0.4") });
    await fixture.pool.connect(fixture.carol).fund({ value: ethers.parseEther("0.6") });
    assert.equal(await fixture.pool.funded(), DEFAULT_CAP);
    await expectCustomError(
      fixture.pool.connect(fixture.bob).fund({ value: 1n }),
      fixture.pool,
      "P42_FUNDING_CAP_EXCEEDED"
    );

    await advanceTo(await fixture.ledger.closeByTimestamp());
    await fixture.ledger.close();
    assert.equal(await fixture.ledger.finalEntitlement(fixture.alice.address), DEFAULT_CAP);
    await fixture.submissions.releaseFinalizedBond(submission.submissionId);
    assert.equal(await fixture.submissions.claimableBondWei(fixture.alice.address), MIN_BOND);
  });

  it("forfeits retained paid poison collateral while zero-bond open-phase voids stay idempotent", async function () {
    const paid = await deployFixture();
    const poisoned = await commitAndReveal(paid, paid.alice, {
      cid: "bafy-paid-poison",
      salt: "paid-poison",
      score: 1n,
    });
    await increaseTime(CHALLENGE_WINDOW + 1n);
    await paid.submissions.connect(paid.alice).finalize(poisoned.submissionId, PERMANENCE_HASH);
    assert.equal((await paid.submissions.submissions(poisoned.submissionId)).bondWei, poisoned.bond);
    await paid.submissions.connect(paid.owner).setPausedAll(true);
    await paid.submissions.connect(paid.owner).voidFinalize(poisoned.submissionId);
    assert.equal(await paid.submissions.claimableBondWei(paid.treasury.address), poisoned.bond);
    assert.equal(await paid.submissions.claimableBondWei(paid.alice.address), 0n);
    assert.equal(await paid.ledger.totalCreditAtoms(), 0n);
    await expectCustomError(
      paid.submissions.connect(paid.owner).voidFinalize(poisoned.submissionId),
      paid.submissions,
      "P42_BAD_SUBMISSION_STATUS"
    );
    assert.equal(await paid.submissions.claimableBondWei(paid.treasury.address), poisoned.bond);

    const open = await deployFixture({ arm: false, acceptFunds: false });
    const openPoison = await commitAndReveal(open, open.alice, {
      cid: "bafy-open-poison",
      salt: "open-poison",
      score: 1n,
    });
    await increaseTime(CHALLENGE_WINDOW + 1n);
    await open.submissions.connect(open.alice).finalize(openPoison.submissionId, PERMANENCE_HASH);
    assert.equal(await open.submissions.claimableBondWei(open.alice.address), openPoison.bond);
    await open.submissions.connect(open.owner).setPausedAll(true);
    await open.submissions.connect(open.owner).voidFinalize(openPoison.submissionId);
    assert.equal(await open.submissions.claimableBondWei(open.alice.address), openPoison.bond);
    assert.equal(await open.submissions.claimableBondWei(open.treasury.address), 0n);
  });

  it("keeps resolver decisions pending and cancels their effect when the resolver is slashed", async function () {
    const fixture = await deployFixture();
    const submission = await commitAndReveal(fixture, fixture.alice, {
      cid: "bafy-slashed-resolver",
      salt: "slashed-resolver",
    });
    const challengeBond = await fixture.challenges.requiredChallengeBond(
      await fixture.submissions.disputedEntitlementWei(submission.submissionId)
    );
    await openChallenge(fixture, fixture.bob, submission.submissionId, ethers.id("resolver-lie"), { value: challengeBond });
    const resolveTx = await resolveChallenge(fixture, fixture.resolver, submission.submissionId,
      false,
      ethers.id("false-transcript"),
      "ipfs://false-transcript",
      ethers.id("false-verdict"),
      { value: await fixture.challenges.resolverDecisionBondWei() }
    );
    const resolveReceipt = await resolveTx.wait();
    const pendingEvent = resolveReceipt.logs
      .map((log) => {
        try {
          return fixture.challenges.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed?.name === "ResolverTranscriptPosted");
    assert.ok(pendingEvent);
    assert.equal(pendingEvent.args.challengerWins, false);

    assert.equal((await fixture.submissions.submissions(submission.submissionId)).status, 3n);
    assert.equal((await fixture.challenges.challenges(submission.submissionId)).decisionPending, true);
    await expectCustomError(
      finalizeChallengeResolution(fixture, submission.submissionId),
      fixture.challenges,
      "P42_RESOLVER_BOND_LOCKED"
    );

    await slashResolverBond(fixture, submission.submissionId, ethers.id("resolver-fraud-proof"));
    assert.equal((await fixture.submissions.submissions(submission.submissionId)).status, 2n);
    assert.equal((await fixture.challenges.challenges(submission.submissionId)).challenger, ethers.ZeroAddress);
    assert.equal(await fixture.challenges.claimableBondWei(fixture.bob.address), challengeBond);
    await expectCustomError(
      finalizeChallengeResolution(fixture, submission.submissionId),
      fixture.challenges,
      "P42_UNKNOWN_CHALLENGE"
    );
    await expectCustomError(
      fixture.submissions.connect(fixture.alice).finalize(submission.submissionId, PERMANENCE_HASH),
      fixture.submissions,
      "P42_CHALLENGE_WINDOW_OPEN"
    );

    await openChallenge(fixture, fixture.carol, submission.submissionId, ethers.id("fresh-fraud-proof"), { value: challengeBond });
    assert.equal((await fixture.challenges.challenges(submission.submissionId)).challenger, fixture.carol.address);
  });

  it("caps repeated refunded challenges at the immutable cumulative dispute deadline", async function () {
    const fixture = await deployFixture();
    const submission = await commitAndReveal(fixture, fixture.alice, {
      cid: "bafy-bounded-disputes",
      salt: "bounded-disputes",
    });
    const challengeBond = await fixture.challenges.requiredChallengeBond(
      await fixture.submissions.disputedEntitlementWei(submission.submissionId)
    );

    for (let attempt = 1; attempt <= 3; attempt += 1) {
      await openChallenge(fixture, fixture.bob, submission.submissionId, ethers.id(`recycled-${attempt}`), { value: challengeBond });
      await increaseTime(CHALLENGE_WINDOW + 1n);
      await expireChallenge(fixture, submission.submissionId);
    }

    assert.equal(await fixture.challenges.claimableBondWei(fixture.bob.address), 3n * challengeBond);
    await expectCustomError(
      openChallenge(fixture, fixture.bob, submission.submissionId, ethers.id("recycled-forever"), { value: challengeBond }),
      fixture.submissions,
      "P42_CHALLENGE_WINDOW_CLOSED"
    );
    await fixture.submissions.connect(fixture.alice).finalize(submission.submissionId, PERMANENCE_HASH);
    assert.equal((await fixture.submissions.submissions(submission.submissionId)).status, 4n);
  });

  it("ignores forced ETH for arming, freeze, funding, and entitlement accounting", async function () {
    const fixture = await deployFixture({ freeze: false, arm: false, acceptFunds: false });
    const forced = ethers.parseEther("0.75");
    await ethers.provider.send("hardhat_setBalance", [
      await fixture.pool.getAddress(),
      ethers.toQuantity(forced),
    ]);

    assert.equal(await ethers.provider.getBalance(await fixture.pool.getAddress()), forced);
    assert.equal(await fixture.pool.funded(), 0n);
    assert.equal(await fixture.pool.totalFunded(), 0n);
    assert.equal(await fixture.pool.everFunded(), false);
    assert.equal(await fixture.submissions.fundingArmed(), false);
    assert.equal(await fixture.registry.isFrozen(1), false);

    await increaseTime(CHALLENGE_WINDOW + 1n);
    await fixture.submissions.connect(fixture.treasury).authorizeFunding("0x" + "42".repeat(32), 2n ** 64n - 1n);
    await fixture.submissions.connect(fixture.owner).armFunding("0x" + "42".repeat(32));
    await expectCustomError(
      fixture.pool.connect(fixture.owner).setAcceptingFunds(true),
      fixture.pool,
      "P42_PROBLEM_NOT_FROZEN"
    );
    await fixture.registry.connect(fixture.owner).freeze(1);
    await fixture.pool.connect(fixture.owner).setAcceptingFunds(true);
    await fixture.pool.connect(fixture.bob).fund({ value: ethers.parseEther("0.25") });

    assert.equal(await fixture.pool.funded(), ethers.parseEther("0.25"));
    assert.equal(await fixture.pool.totalFunded(), ethers.parseEther("0.25"));
    assert.equal(await fixture.pool.everFunded(), true);
    assert.equal(await ethers.provider.getBalance(await fixture.pool.getAddress()), ethers.parseEther("1"));

    await advanceTo(await fixture.ledger.closeByTimestamp());
    await fixture.ledger.close();
    await increaseTime((await fixture.ledger.CLAIM_DEADLINE_SECONDS()) + 1n);
    await fixture.pool.connect(fixture.bob).sponsorRefund();
    assert.equal(await ethers.provider.getBalance(await fixture.pool.getAddress()), forced);
    assert.equal(await fixture.pool.totalResidualPaid(), 0n);
    const vaultBeforeForcedRecovery = await ethers.provider.getBalance(await fixture.vault.getAddress());
    await fixture.pool.connect(fixture.owner).recoverForcedEth(forced);
    assert.equal(
      (await ethers.provider.getBalance(await fixture.vault.getAddress())) - vaultBeforeForcedRecovery,
      forced
    );
    assert.equal(await ethers.provider.getBalance(await fixture.pool.getAddress()), 0n);
  });

  it("blocks every caller before closeBy, then permits anyone after closeBy", async function () {
    const ownerClose = await deployFixture();
    await advanceTo(ownerClose.earliestClose);
    await ownerClose.pool.connect(ownerClose.bob).fund({ value: ethers.parseEther("0.1") });
    await expectCustomError(
      ownerClose.ledger.connect(ownerClose.owner).close(),
      ownerClose.ledger,
      "P42_CLOSE_BY_NOT_REACHED"
    );
    await expectCustomError(
      ownerClose.ledger.connect(ownerClose.outsider).close(),
      ownerClose.ledger,
      "P42_CLOSE_BY_NOT_REACHED"
    );
    await advanceTo(ownerClose.closeBy);
    await ownerClose.ledger.connect(ownerClose.owner).close();
    assert.equal(await ownerClose.ledger.closed(), true);

    const lateClose = await deployFixture();
    await advanceTo((await lateClose.ledger.fundingDeadline()) + 1n);
    await expectCustomError(
      lateClose.pool.connect(lateClose.bob).fund({ value: 1n }),
      lateClose.pool,
      "P42_FUNDING_WINDOW_CLOSED"
    );
    await advanceTo(lateClose.closeBy);
    await lateClose.ledger.connect(lateClose.outsider).close();
    assert.equal(await lateClose.ledger.closed(), true);

    const cid = "bafy-post-close";
    const salt = "post-close";
    const commitment = await commitmentFor(lateClose.submissions, lateClose.alice, cid, salt);
    await expectCustomError(
      lateClose.submissions.connect(lateClose.alice).commit(commitment, DA_HASH, {
        value: await lateClose.submissions.requiredPostingBondNow(),
      }),
      lateClose.submissions,
      "P42_LEDGER_CLOSED"
    );
  });
});
