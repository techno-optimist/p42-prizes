import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const DAY = 24n * 60n * 60n;
const WINDOW = 60n * 60n;
const FRAUD_WINDOW = WINDOW / 4n;
const FUNDING_CAP = ethers.parseEther("100");
const DA_HASH = ethers.sha256(ethers.toUtf8Bytes("acceptance-solution"));
const PERMANENCE_HASH = ethers.id("acceptance-permanence");

function findErrorData(value) {
  if (value == null) return undefined;
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

async function expectCustomError(action, contract, name) {
  try {
    await action;
  } catch (error) {
    const data = findErrorData(error);
    if (data !== undefined) {
      assert.equal(contract.interface.parseError(data)?.name, name);
      return;
    }
    assert.match(String(error), new RegExp(name));
    return;
  }
  throw new Error(`expected ${name} revert`);
}

async function increaseTime(seconds) {
  await ethers.provider.send("evm_increaseTime", [Number(seconds)]);
  await ethers.provider.send("evm_mine", []);
}

async function advanceTo(timestamp) {
  const block = await ethers.provider.getBlock("latest");
  const delta = timestamp - BigInt(block.timestamp);
  if (delta > 0n) await increaseTime(delta);
}

async function closeTimes() {
  const block = await ethers.provider.getBlock("latest");
  return {
    earliest: BigInt(block.timestamp) + 30n * DAY + 100n,
    closeBy: BigInt(block.timestamp) + 200n * DAY,
  };
}

async function deployProtocol({ seed = 1_000_000n, fund = ethers.parseEther("10") } = {}) {
  const [owner, treasury, resolver, alice, bob, carol] = await ethers.getSigners();
  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address, FUNDING_CAP);
  await pool.waitForDeployment();

  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const times = await closeTimes();
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasury.address, 0, times.earliest, times.closeBy,
  );
  await ledger.waitForDeployment();
  await pool.connect(owner).setLedger(await ledger.getAddress());

  const Submissions = await ethers.getContractFactory("P42SubmissionManager");
  const submissions = await Submissions.deploy(
    await pool.getAddress(),
    await ledger.getAddress(),
    owner.address,
    treasury.address,
    200,
    ethers.parseEther("0.01"),
    WINDOW,
    false,
    0,
    seed,
    1,
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
    WINDOW,
    200,
    ethers.parseEther("0.001"),
    ethers.parseEther("0.001"),
    10_000,
    ethers.parseEther("0.01"),
    FRAUD_WINDOW,
  );
  await challenges.waitForDeployment();
  await submissions.connect(owner).setChallengeManager(await challenges.getAddress());

  const Registry = await ethers.getContractFactory("P42ProblemRegistry");
  const registry = await Registry.deploy(owner.address);
  await registry.waitForDeployment();
  await registry.connect(owner).register({
    specHash: ethers.id("acceptance-spec"),
    verifierSourceHash: ethers.id("acceptance-source"),
    verifierImageHash: ethers.id("acceptance-image"),
    admissionMatrixHash: ethers.id("acceptance-matrix"),
    metadataURI: "ipfs://acceptance",
    pool: await pool.getAddress(),
    ledger: await ledger.getAddress(),
    submissionManager: await submissions.getAddress(),
    challengeManager: await challenges.getAddress(),
    challengeWindowSeconds: WINDOW,
    minImprovementAtoms: 1,
  });
  await registry.connect(owner).freeze(1);
  await pool.connect(owner).setRegistry(await registry.getAddress(), 1);
  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), owner.address);
  await vault.waitForDeployment();
  await ledger.connect(owner).setRolloverDestination(await vault.getAddress());
  await increaseTime(WINDOW + 1n);
  await submissions.connect(treasury).authorizeFunding("0x" + "42".repeat(32), 2n ** 64n - 1n);
  await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
  await pool.connect(owner).setAcceptingFunds(true);
  if (fund > 0n) await pool.fund({ value: fund });

  return { owner, treasury, resolver, alice, bob, carol, pool, ledger, submissions, challenges, vault };
}

async function commitOnly(fixture, solver, cid, salt) {
  const commitment = await fixture.submissions["computeCommitment(string,address,bytes32,string)"](
    cid, solver.address, DA_HASH, salt,
  );
  await fixture.submissions.connect(solver).commit(commitment, DA_HASH, {
    value: await fixture.submissions.requiredPostingBondNow(),
  });
  return await fixture.submissions.submissionCount();
}

async function commitReveal(fixture, solver, cid, score, salt) {
  const submissionId = await commitOnly(fixture, solver, cid, salt);
  await fixture.submissions.connect(solver).reveal(submissionId, cid, score, 1, salt, "0x");
  return submissionId;
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

describe("P42 second-pass contract acceptance", () => {
  it("uses full-precision entitlement math for the largest accepted marginal and remains challengeable/claimable", async () => {
    const upper = (1n << 254n) - 1n;
    const lower = -(1n << 254n) + 1n;
    const fixture = await deployProtocol({ seed: upper });
    const { owner, resolver, alice, bob, pool, ledger, submissions, challenges } = fixture;
    const submissionId = await commitReveal(fixture, alice, "bafy-extreme-credit", lower, "extreme-credit");

    const disputed = await submissions.disputedEntitlementWei(submissionId);
    assert.equal(disputed, ethers.parseEther("10"));
    const challengeBond = await challenges.requiredChallengeBond(disputed);
    await openChallenge(fixture, bob, submissionId, ethers.id("extreme-score-check"), { value: challengeBond });
    await resolveChallenge(fixture, resolver, submissionId,
      false,
      ethers.id("extreme-transcript"),
      "ar://extreme-transcript",
      ethers.id("extreme-verdict"),
      { value: await challenges.resolverDecisionBondWei() },
    );
    await increaseTime(FRAUD_WINDOW + 1n);
    await finalizeChallengeResolution(fixture, submissionId);
    await advanceTo((await submissions.submissions(submissionId)).challengeEndsAt);
    await submissions.connect(alice).finalize(submissionId, PERMANENCE_HASH);
    assert.equal(await ledger.totalCreditAtoms(), (1n << 255n) - 2n);

    await advanceTo(await ledger.closeByTimestamp());
    await ledger.connect(owner).close();
    assert.equal(await ledger.finalEntitlement(alice.address), ethers.parseEther("10"));
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), ethers.parseEther("10"));
  });

  it("rejects cumulative credit beyond the protocol bound with a named error, never a panic", async () => {
    const [owner, treasury, alice, bob] = await ethers.getSigners();
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const pool = await Pool.deploy(owner.address, FUNDING_CAP);
    await pool.waitForDeployment();
    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const times = await closeTimes();
    const ledger = await Ledger.deploy(
      await pool.getAddress(), owner.address, treasury.address, 0, times.earliest, times.closeBy,
    );
    await ledger.waitForDeployment();
    await pool.connect(owner).setLedger(await ledger.getAddress());
    const Armed = await ethers.getContractFactory("MockFundingArmed");
    const armed = await Armed.deploy(true);
    await armed.waitForDeployment();
    await ledger.connect(owner).setCreditRecorder(await armed.getAddress());
    await pool.connect(owner).setSubmissionManager(await armed.getAddress());
    const Registry = await ethers.getContractFactory("MockProblemRegistry");
    const registry = await Registry.deploy();
    await registry.waitForDeployment();
    await registry.setProblem(1, await pool.getAddress(), true);
    await pool.connect(owner).setRegistry(await registry.getAddress(), 1);
    const Vault = await ethers.getContractFactory("P42RolloverVault");
    const vault = await Vault.deploy(await registry.getAddress(), owner.address);
    await vault.waitForDeployment();
    await ledger.connect(owner).setRolloverDestination(await vault.getAddress());
    await pool.connect(owner).setAcceptingFunds(true);
    await pool.fund({ value: ethers.parseEther("10") });

    const maxCredit = await ledger.MAX_TOTAL_CREDIT_ATOMS();
    await armed.recordCredit(await ledger.getAddress(), alice.address, maxCredit);
    await expectCustomError(
      armed.recordCredit(await ledger.getAddress(), bob.address, 1),
      ledger,
      "P42_CREDIT_BOUND_EXCEEDED"
    );
    await advanceTo(await ledger.closeByTimestamp());
    await ledger.connect(owner).close();
    assert.equal(await ledger.finalEntitlement(alice.address), ethers.parseEther("10"));
  });

  it("rejects a resolver mined at the active deadline and times out within the immutable horizon", async () => {
    const fixture = await deployProtocol();
    const { resolver, alice, bob, submissions, challenges } = fixture;
    const submissionId = await commitReveal(fixture, alice, "bafy-late-resolver", 900_000, "late-resolver");
    const maxDeadline = await submissions.maxDisputeEndsAtOf(submissionId);
    await openChallenge(fixture, bob, submissionId, ethers.id("late-resolver"), {
      value: await challenges.requiredChallengeBond(await submissions.disputedEntitlementWei(submissionId)),
    });
    const challenge = await challenges.challenges(submissionId);
    await advanceTo(challenge.disputeEndsAt);
    await expectCustomError(
      resolveChallenge(fixture, resolver, submissionId,
        false,
        ethers.id("late-transcript"),
        "ar://late-transcript",
        ethers.id("late-verdict"),
        { value: await challenges.resolverDecisionBondWei() },
      ),
      challenges,
      "P42_DISPUTE_WINDOW_CLOSED",
    );
    await expireChallenge(fixture, submissionId);
    assert.equal((await submissions.submissions(submissionId)).status, 2n);
    assert.equal(await submissions.maxDisputeEndsAtOf(submissionId), maxDeadline);
    assert.equal(challenge.disputeEndsAt <= maxDeadline, true);
  });

  it("gives an exact duplicate CID to the earliest valid commit even when the copied reveal lands first", async () => {
    const fixture = await deployProtocol();
    const { alice, bob, carol, ledger, submissions } = fixture;
    const cid = "bafy-censored-original";
    const aliceId = await commitOnly(fixture, alice, cid, "alice-priority");
    const bobId = await commitOnly(fixture, bob, cid, "bob-copy");

    await submissions.connect(bob).reveal(bobId, cid, 800_000, 1, "bob-copy", "0x");
    assert.equal(await submissions.prioritySubmissionOf(ethers.keccak256(ethers.toUtf8Bytes(cid))), bobId);

    const aliceCommit = await submissions.submissions(aliceId);
    // Leave enough room for the reveal block to mine before commit expiry.
    await advanceTo(aliceCommit.committedAt + WINDOW - 30n);
    await submissions.connect(alice).reveal(aliceId, cid, 800_000, 1, "alice-priority", "0x");
    assert.equal(await submissions.prioritySubmissionOf(ethers.keccak256(ethers.toUtf8Bytes(cid))), aliceId);
    assert.equal((await submissions.submissions(bobId)).status, 5n);
    assert.equal(await submissions.claimableBondWei(bob.address) > 0n, true);

    await advanceTo((await submissions.submissions(aliceId)).challengeEndsAt);
    await submissions.connect(alice).finalize(aliceId, PERMANENCE_HASH);
    assert.equal(await ledger.creditAtomsOf(alice.address), 200_000n);
    assert.equal(await ledger.creditAtomsOf(bob.address), 0n);

    const expiredId = await commitOnly(fixture, carol, "bafy-hard-expiry", "hard-expiry");
    await increaseTime(WINDOW);
    await expectCustomError(
      submissions.connect(carol).reveal(expiredId, "bafy-hard-expiry", 700_000, 1, "hard-expiry", "0x"),
      submissions,
      "P42_COMMIT_EXPIRED",
    );
  });

  it("rechecks the frozen registry's exact problem-to-pool binding on every deposit", async () => {
    const [owner, treasury, outsider] = await ethers.getSigners();
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const pool = await Pool.deploy(owner.address, FUNDING_CAP);
    await pool.waitForDeployment();
    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const times = await closeTimes();
    const ledger = await Ledger.deploy(
      await pool.getAddress(), owner.address, treasury.address, 0, times.earliest, times.closeBy,
    );
    await ledger.waitForDeployment();
    await pool.connect(owner).setLedger(await ledger.getAddress());
    const Armed = await ethers.getContractFactory("MockFundingArmed");
    const armed = await Armed.deploy(true);
    await armed.waitForDeployment();
    await ledger.connect(owner).setCreditRecorder(await armed.getAddress());
    await pool.connect(owner).setSubmissionManager(await armed.getAddress());
    const Registry = await ethers.getContractFactory("MockProblemRegistry");
    const registry = await Registry.deploy();
    await registry.waitForDeployment();
    await registry.setProblem(7, await pool.getAddress(), true);
    await pool.connect(owner).setRegistry(await registry.getAddress(), 7);
    const Vault = await ethers.getContractFactory("P42RolloverVault");
    const vault = await Vault.deploy(await registry.getAddress(), owner.address);
    await vault.waitForDeployment();
    await ledger.connect(owner).setRolloverDestination(await vault.getAddress());
    await pool.connect(owner).setAcceptingFunds(true);
    await pool.fund({ value: 1 });

    await registry.setProblem(7, outsider.address, true);
    await expectCustomError(pool.fund({ value: 1 }), pool, "P42_BAD_PROBLEM_BINDING");
    assert.equal(await pool.totalFunded(), 1n);
  });

  it("blocks voidFinalize while any submission is Revealed or Challenged without changing accounting", async () => {
    const fixture = await deployProtocol();
    const { owner, alice, bob, submissions, challenges, ledger } = fixture;
    const poisonId = await commitReveal(fixture, alice, "bafy-poison", 900_000, "poison");
    await advanceTo((await submissions.submissions(poisonId)).challengeEndsAt);
    await submissions.connect(alice).finalize(poisonId, PERMANENCE_HASH);
    const frontier = await submissions.bestScoreAtoms();
    const credit = await ledger.totalCreditAtoms();

    const pendingId = await commitReveal(fixture, bob, "bafy-pending", 800_000, "pending");
    await submissions.connect(owner).setPausedAll(true);
    await expectCustomError(
      submissions.connect(owner).voidFinalize(poisonId), submissions, "P42_ACTIVE_REVEALS_OR_CHALLENGES",
    );
    assert.equal(await submissions.bestScoreAtoms(), frontier);
    assert.equal(await ledger.totalCreditAtoms(), credit);

    await openChallenge(fixture, alice, pendingId, ethers.id("pending-challenge"), {
      value: await challenges.requiredChallengeBond(await submissions.disputedEntitlementWei(pendingId)),
    });
    assert.equal(await submissions.revealedSubmissionCount(), 0n);
    assert.equal(await submissions.challengedSubmissionCount(), 1n);
    await expectCustomError(
      submissions.connect(owner).voidFinalize(poisonId), submissions, "P42_ACTIVE_REVEALS_OR_CHALLENGES",
    );
    assert.equal(await submissions.bestScoreAtoms(), frontier);
    assert.equal(await ledger.totalCreditAtoms(), credit);
  });

  it("rotates threshold, lost signers, and guardian without signatures from unavailable keys", async () => {
    const [a, b, c, d, e, replacement, guardian, nextGuardian] = await ethers.getSigners();
    const Timelock = await ethers.getContractFactory("P42MultisigTimelock");
    const delay = 60n;
    const timelock = await Timelock.deploy(
      [a.address, b.address, c.address, d.address, e.address], 4, delay, guardian.address,
    );
    await timelock.waitForDeployment();
    const target = await timelock.getAddress();

    const swap = timelock.interface.encodeFunctionData("swapSigner", [e.address, replacement.address]);
    const swapSalt = ethers.id("survivors-swap-lost");
    await timelock.connect(a).scheduleOverride(target, 0, swap, swapSalt);
    const swapId = await timelock.opId(target, 0, swap, swapSalt);
    await timelock.connect(b).confirm(swapId);
    await timelock.connect(c).confirm(swapId);
    await timelock.connect(d).confirm(swapId);
    // e is unavailable; the independent guardian authorizes replacing only it.
    await timelock.connect(guardian).approveSignerRecovery(target, swap, swapSalt);
    await increaseTime(2n * delay + 1n);
    await timelock.execute(target, 0, swap, swapSalt);
    assert.equal(await timelock.isSigner(e.address), false);
    assert.equal(await timelock.isSigner(replacement.address), true);

    const lowerThreshold = timelock.interface.encodeFunctionData("setThreshold", [3]);
    const thresholdSalt = ethers.id("restored-quorum-lower-threshold");
    await timelock.connect(a).scheduleOverride(target, 0, lowerThreshold, thresholdSalt);
    const thresholdId = await timelock.opId(target, 0, lowerThreshold, thresholdSalt);
    await timelock.connect(b).confirm(thresholdId);
    await timelock.connect(c).confirm(thresholdId);
    await timelock.connect(d).confirm(thresholdId);
    await timelock.connect(replacement).confirm(thresholdId);
    await increaseTime(2n * delay + 1n);
    await timelock.execute(target, 0, lowerThreshold, thresholdSalt);
    assert.equal(await timelock.threshold(), 3n);
    assert.equal(await timelock.toleratedSignerLoss(), 2n);

    const rotateGuardian = timelock.interface.encodeFunctionData("setGuardian", [nextGuardian.address]);
    const guardianSalt = ethers.id("survivors-guardian");
    await timelock.connect(a).scheduleOverride(target, 0, rotateGuardian, guardianSalt);
    const guardianId = await timelock.opId(target, 0, rotateGuardian, guardianSalt);
    await timelock.connect(b).confirm(guardianId);
    await timelock.connect(c).confirm(guardianId);
    await timelock.connect(d).confirm(guardianId);
    await increaseTime(2n * delay + 1n);
    await timelock.execute(target, 0, rotateGuardian, guardianSalt);
    assert.equal(await timelock.guardian(), nextGuardian.address);
  });

  it("gives constructor and setSessionKey sessions finite, maximum-bounded expiry", async () => {
    const [owner, session, replacement] = await ethers.getSigners();
    const Wallet = await ethers.getContractFactory("P42AgentWallet");
    const wallet = await Wallet.deploy(owner.address, session.address, 0, 0);
    await wallet.waitForDeployment();
    const maxLifetime = await wallet.MAX_SESSION_LIFETIME();
    const deployedAt = await ethers.provider.getBlock("latest");
    assert.equal(await wallet.sessionExpiresAt() <= BigInt(deployedAt.timestamp) + maxLifetime, true);
    assert.notEqual(await wallet.sessionExpiresAt(), (1n << 64n) - 1n);

    await increaseTime(maxLifetime + 1n);
    await expectCustomError(wallet.connect(session).execute(owner.address, 0, "0x"), wallet, "SessionExpired");

    await wallet.connect(owner).setSessionKey(replacement.address);
    const rotatedAt = await ethers.provider.getBlock("latest");
    const rotatedExpiry = await wallet.sessionExpiresAt();
    assert.equal(rotatedExpiry <= BigInt(rotatedAt.timestamp) + maxLifetime, true);
    const chainId = (await ethers.provider.getNetwork()).chainId;
    await expectCustomError(
      wallet.connect(owner).setSessionPolicy(
        replacement.address, chainId, BigInt(rotatedAt.timestamp) + maxLifetime + 2n,
      ),
      wallet,
      "BadSessionPolicy",
    );
    await increaseTime(maxLifetime + 1n);
    await expectCustomError(
      wallet.connect(replacement).execute(owner.address, 0, "0x"), wallet, "SessionExpired",
    );
  });
});
