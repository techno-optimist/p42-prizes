import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const CHALLENGE_WINDOW_SECONDS = 72n * 60n * 60n;
const RESOLVER_FRAUD_WINDOW_SECONDS = 24n * 60n * 60n;
const FUNDING_CAP = ethers.parseEther("100");
const CLOSE_BY_TIMESTAMP = 4_102_444_800n;
const MIN_COMPETITION_SECONDS = 30n * 24n * 60n * 60n;

async function nextEarliestClose() {
  const latest = await ethers.provider.getBlock("latest");
  return BigInt(latest.timestamp) + MIN_COMPETITION_SECONDS + 1_000n;
}
// Absolute-score frontier seed for these economic fixtures. Reveals claim
// ABSOLUTE scores strictly below this; finalize credits the marginal
// reduction against the live frontier (F1).
const SEED_SCORE_ATOMS = 1_000_000n;
const DA_HASH = ethers.keccak256(ethers.toUtf8Bytes("commit block DA receipt"));
const PERMANENCE_HASH = ethers.keccak256(ethers.toUtf8Bytes("arweave permanence receipt"));

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
  const target = await ledger.effectiveEarliestCloseTimestamp();
  const latest = await ethers.provider.getBlock("latest");
  if (target > BigInt(latest.timestamp)) await increaseTime(target - BigInt(latest.timestamp));
}

describe("P42 Gate 1 contract scaffold", function () {
  async function deployFixture({
    alphaBps = 200n,
    minBond = ethers.parseEther("0.01"),
    feeBps = 0,
    activateRecorder = true,
  } = {}) {
    const [owner, treasury, resolver, alice, bob, challenger] = await ethers.getSigners();
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const pool = await Pool.deploy(owner.address, FUNDING_CAP);
    await pool.waitForDeployment();

    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const ledger = await Ledger.deploy(
      await pool.getAddress(), owner.address, treasury.address, feeBps,
      await nextEarliestClose(), CLOSE_BY_TIMESTAMP
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
      minBond,
      CHALLENGE_WINDOW_SECONDS,
      false, // off-chain DA mode: these fixtures test economics, not DA binding
      0,
      SEED_SCORE_ATOMS,
      1n // minImprovementAtoms
    );
    await submissions.waitForDeployment();
    if (activateRecorder) {
      await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());
    }

    // OPEN-WITNESS-PHASE wiring is completed after the required frozen
    // registry binding below.
    await pool.connect(owner).setSubmissionManager(await submissions.getAddress());

    const Challenges = await ethers.getContractFactory("P42ChallengeManager");
    const challenges = await Challenges.deploy(
      owner.address,
      resolver.address,
      treasury.address,
      await submissions.getAddress(),
      CHALLENGE_WINDOW_SECONDS,
      500,
      ethers.parseEther("0.02"),
      ethers.parseEther("0.01"),
      30000,
      ethers.parseEther("0.005"),
      RESOLVER_FRAUD_WINDOW_SECONDS
    );
    await challenges.waitForDeployment();
    await submissions.connect(owner).setChallengeManager(await challenges.getAddress());

    const Registry = await ethers.getContractFactory("P42ProblemRegistry");
    const registry = await Registry.deploy(owner.address);
    await registry.waitForDeployment();

    const fundingRegistry = await Registry.deploy(owner.address);
    await fundingRegistry.waitForDeployment();
    await fundingRegistry.register({
      specHash: ethers.id("fixture-spec"),
      verifierSourceHash: ethers.id("fixture-source"),
      verifierImageHash: ethers.id("fixture-image"),
      admissionMatrixHash: ethers.id("fixture-matrix"),
      metadataURI: "ipfs://fixture",
      pool: await pool.getAddress(),
      ledger: await ledger.getAddress(),
      submissionManager: await submissions.getAddress(),
      challengeManager: await challenges.getAddress(),
      challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS,
      minImprovementAtoms: 1n,
    });
    await fundingRegistry.freeze(1);
    await pool.connect(owner).setRegistry(await fundingRegistry.getAddress(), 1);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.connect(owner).armFunding();
    await pool.connect(owner).setAcceptingFunds(true);
    await increaseTime(MIN_COMPETITION_SECONDS + 1_001n);

    return { owner, treasury, resolver, alice, bob, challenger, pool, ledger, submissions, challenges, registry, minBond };
  }

  async function registryConfig(fixture, overrides = {}) {
    return {
      specHash: ethers.keccak256(ethers.toUtf8Bytes("hadamard-mini spec v1")),
      verifierSourceHash: ethers.keccak256(ethers.toUtf8Bytes("hadamard-mini verifier source v1")),
      verifierImageHash: ethers.keccak256(ethers.toUtf8Bytes("sha256:local-dev")),
      admissionMatrixHash: ethers.keccak256(ethers.toUtf8Bytes("p42-admission-matrix/v1 local fixture")),
      metadataURI: "ipfs://hadamard-mini/problem.yaml",
      pool: await fixture.pool.getAddress(),
      ledger: await fixture.ledger.getAddress(),
      submissionManager: await fixture.submissions.getAddress(),
      challengeManager: await fixture.challenges.getAddress(),
      challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS,
      minImprovementAtoms: 1n,
      ...overrides,
    };
  }

  async function commitAndReveal(fixture, overrides = {}) {
    const solutionCid = overrides.solutionCid ?? "bafy-challenge-solution";
    const salt = overrides.salt ?? "challenge-salt";
    const solver = overrides.solver ?? fixture.alice;
    const claimedScoreAtoms = overrides.claimedScoreAtoms ?? 1000;
    const improvementAtoms = overrides.improvementAtoms ?? 1;
    const commitment = await fixture.submissions["computeCommitment(string,address,bytes32,string)"](
      solutionCid,
      solver.address,
      DA_HASH,
      salt
    );
    const bond = overrides.bond ?? (await fixture.submissions.requiredPostingBondNow());

    const tx = await fixture.submissions.connect(solver).commit(commitment, DA_HASH, { value: bond });
    await tx.wait();
    const submissionId = await fixture.submissions.submissionCount();
    await fixture.submissions
      .connect(solver)
      .reveal(submissionId, solutionCid, claimedScoreAtoms, improvementAtoms, salt, "0x");

    return { submissionId, solutionCid, salt, solver, bond };
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

  async function releaseResolverBond(fixture, submissionId) {
    return fixture.challenges.releaseResolverBond(
      submissionId,
      await fixture.challenges.challengeInstanceHashOf(submissionId),
    );
  }

  async function expireChallenge(fixture, signer, submissionId) {
    return fixture.challenges.connect(signer).expireChallenge(
      submissionId,
      await fixture.challenges.challengeInstanceHashOf(submissionId),
    );
  }

  async function slashResolverBond(fixture, submissionId, proofHash) {
    return fixture.challenges.connect(fixture.owner).slashResolverBond(
      submissionId,
      await fixture.challenges.challengeInstanceHashOf(submissionId),
      proofHash,
    );
  }

  it("registers problem metadata anchors and component addresses", async function () {
    const fixture = await deployFixture();
    const config = await registryConfig(fixture);

    await fixture.registry.register(config);
    assert.equal(await fixture.registry.problemCount(), 1n);
    assert.equal(await fixture.registry.isFrozen(1), false);

    const problem = await fixture.registry.problems(1);
    assert.equal(problem.specHash, config.specHash);
    assert.equal(problem.verifierSourceHash, config.verifierSourceHash);
    assert.equal(problem.verifierImageHash, config.verifierImageHash);
    assert.equal(problem.admissionMatrixHash, config.admissionMatrixHash);
    assert.equal(problem.metadataURI, config.metadataURI);
    assert.equal(problem.pool, config.pool);
    assert.equal(problem.ledger, config.ledger);
    assert.equal(problem.submissionManager, config.submissionManager);
    assert.equal(problem.challengeManager, config.challengeManager);
    assert.equal(problem.challengeWindowSeconds, config.challengeWindowSeconds);
    assert.equal(problem.minImprovementAtoms, config.minImprovementAtoms);
  });

  it("rejects incomplete problem registry configs", async function () {
    const fixture = await deployFixture();
    const config = await registryConfig(fixture);

    await expectCustomError(fixture.registry.register({ ...config, specHash: ethers.ZeroHash }), fixture.registry, "P42_ZERO_HASH");
    await expectCustomError(fixture.registry.register({ ...config, metadataURI: "" }), fixture.registry, "P42_EMPTY_URI");
    await expectCustomError(fixture.registry.register({ ...config, pool: ethers.ZeroAddress }), fixture.registry, "P42_ZERO_ADDRESS");
    await expectCustomError(
      fixture.registry.register({ ...config, challengeWindowSeconds: 0 }),
      fixture.registry,
      "P42_BAD_WINDOW"
    );
  });

  it("allows registry metadata repair only before funding", async function () {
    const fixture = await deployFixture();
    const config = await registryConfig(fixture);
    await fixture.registry.register(config);

    const repairedHash = ethers.keccak256(ethers.toUtf8Bytes("hadamard-mini spec v2"));
    await fixture.registry.updateBeforeFunding(1, {
      ...(await registryConfig(fixture)),
      specHash: repairedHash,
      metadataURI: "ipfs://hadamard-mini/problem-v2.yaml",
    });
    assert.equal((await fixture.registry.problems(1)).specHash, repairedHash);
    assert.equal((await fixture.registry.problems(1)).metadataURI, "ipfs://hadamard-mini/problem-v2.yaml");

    await fixture.pool.fund({ value: 1n });
    assert.equal(await fixture.registry.isFrozen(1), true);
    await expectCustomError(
      fixture.registry.updateBeforeFunding(1, { ...(await registryConfig(fixture)), specHash: config.specHash }),
      fixture.registry,
      "P42_ALREADY_FROZEN"
    );
  });

  it("binds a multi-board registration to its expected sequential registry id", async function () {
    const fixture = await deployFixture();
    const config = await registryConfig(fixture);

    await expectCustomError(
      fixture.registry.registerExpected(config, 2),
      fixture.registry,
      "P42_UNEXPECTED_PROBLEM_ID",
    );
    await fixture.registry.registerExpected(config, 1);
    assert.equal(await fixture.registry.problemCount(), 1n);
    await fixture.registry.registerExpected({ ...config, metadataURI: "ipfs://second-board" }, 2);
    assert.equal(await fixture.registry.problemCount(), 2n);
  });

  it("supports explicit registry freeze before funding", async function () {
    const fixture = await deployFixture();
    await fixture.registry.register(await registryConfig(fixture));

    await fixture.registry.freeze(1);
    assert.equal(await fixture.registry.isFrozen(1), true);
    await expectCustomError(fixture.registry.freeze(1), fixture.registry, "P42_ALREADY_FROZEN");
    await expectCustomError(
      fixture.registry.updateBeforeFunding(1, await registryConfig(fixture)),
      fixture.registry,
      "P42_ALREADY_FROZEN"
    );
  });

  it("matches the portal's length-framed CID-bound commit preimage", async function () {
    const { alice, submissions } = await deployFixture();

    const expectedPreimage =
      `p42:v0|cid:9:bafy-test|solver:${alice.address.toLowerCase()}|salt:6:s3cret`;
    assert.equal(await submissions.commitPreimage("bafy-test", alice.address, "s3cret"), expectedPreimage);
    assert.equal(
      await submissions["computeCommitment(string,address,string)"]("bafy-test", alice.address, "s3cret"),
      ethers.keccak256(ethers.toUtf8Bytes(expectedPreimage))
    );
  });

  it("binds commit-time DA hash evidence into the on-chain commitment preimage", async function () {
    const { alice, submissions } = await deployFixture();

    const expectedPreimage =
      `p42:v1|cid:9:bafy-test|solver:${alice.address.toLowerCase()}|da:${DA_HASH}|salt:6:s3cret`;
    assert.equal(
      await submissions.commitPreimageWithDa("bafy-test", alice.address, DA_HASH, "s3cret"),
      expectedPreimage
    );
    assert.equal(
      await submissions["computeCommitment(string,address,bytes32,string)"](
        "bafy-test",
        alice.address,
        DA_HASH,
        "s3cret"
      ),
      ethers.keccak256(ethers.toUtf8Bytes(expectedPreimage))
    );
  });

  it("prices the posting bond from alpha times pool-at-submission", async function () {
    const { alice, pool, submissions } = await deployFixture({ alphaBps: 200n });
    await pool.fund({ value: ethers.parseEther("100") });

    const required = ethers.parseEther("2");
    assert.equal(await submissions.requiredPostingBondNow(), required);
    const commitment = ethers.keccak256(ethers.toUtf8Bytes("cid-bound-commitment"));

    await expectCustomError(
      submissions.connect(alice).commit(commitment, DA_HASH, { value: required - 1n }),
      submissions,
      "P42_INSUFFICIENT_POSTING_BOND"
    );

    await submissions.connect(alice).commit(commitment, DA_HASH, { value: required });
    const submission = await submissions.submissions(1);
    assert.equal(submission.solver, alice.address);
    assert.equal(submission.commitment, commitment);
    assert.equal(submission.commitDaHash, DA_HASH);
    assert.equal(submission.bondWei, required);
    assert.equal(submission.poolAtSubmissionWei, ethers.parseEther("100"));
    assert.equal(submission.requiredBondWei, required);
  });

  it("detects empty-pool bond leverage before finalization", async function () {
    const { alice, pool, submissions } = await deployFixture({ alphaBps: 200n });
    const solutionCid = "bafy-empty-pool";
    const salt = "empty-pool-salt";
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
      solutionCid,
      alice.address,
      DA_HASH,
      salt
    );

    const required = await submissions.requiredPostingBondNow();
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: required });
    await pool.fund({ value: ethers.parseEther("100") });

    assert.equal(await submissions.bondCoversEntitlement(1, ethers.parseEther("100")), true);
    await submissions.requireFinalizeBond(1, ethers.parseEther("100"));
    await submissions.connect(alice).reveal(1, solutionCid, 100, 1, salt, "0x");
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.connect(alice).finalize(1, PERMANENCE_HASH);
  });

  it("requires a commit-time DA hash gate and a valid CID-bound reveal", async function () {
    const { alice, bob, submissions, minBond } = await deployFixture();
    const solutionCid = "bafy-solution-a";
    const salt = "s3cret";
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
      solutionCid,
      alice.address,
      DA_HASH,
      salt
    );

    await expectCustomError(
      submissions.connect(alice).commit(commitment, ethers.ZeroHash, { value: minBond }),
      submissions,
      "P42_EMPTY_DA_HASH"
    );

    await submissions.connect(alice).commit(commitment, DA_HASH, {
      value: await submissions.requiredPostingBondNow(),
    });

    await expectCustomError(
      submissions.connect(bob).reveal(1, solutionCid, 123, 7, salt, "0x"),
      submissions,
      "P42_NOT_SOLVER"
    );
    await expectCustomError(
      submissions.connect(alice).reveal(1, solutionCid, 123, 7, "wrong-salt", "0x"),
      submissions,
      "P42_BAD_COMMITMENT_REVEAL"
    );
    // F1 frontier gate: an ABSOLUTE claimed score that does not strictly beat
    // the current on-chain best is rejected at reveal.
    await expectCustomError(
      submissions.connect(alice).reveal(1, solutionCid, SEED_SCORE_ATOMS, 7, salt, "0x"),
      submissions,
      "P42_NOT_STRICT_IMPROVEMENT"
    );
    await expectCustomError(
      submissions.connect(alice).reveal(1, solutionCid, SEED_SCORE_ATOMS + 1n, 7, salt, "0x"),
      submissions,
      "P42_NOT_STRICT_IMPROVEMENT"
    );

    await submissions.connect(alice).reveal(1, solutionCid, 123, 7, salt, "0x");
    const revealed = await submissions.submissions(1);
    assert.equal(revealed.solutionCid, solutionCid);
    assert.equal(revealed.claimedScoreAtoms, 123n);
    assert.equal(revealed.improvementAtoms, 7n);
    assert.equal(revealed.status, 2n);
    assert.equal(revealed.challengeEndsAt - revealed.revealedAt, CHALLENGE_WINDOW_SECONDS);
  });

  it("finalizes after the challenge window, records credit, then claims after close", async function () {
    const { alice, bob, pool, ledger, submissions } = await deployFixture({ alphaBps: 200n, feeBps: 0 });
    await pool.fund({ value: ethers.parseEther("1") });

    const solutionCid = "bafy-winning-solution";
    const salt = "finalize-salt";
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
      solutionCid,
      alice.address,
      DA_HASH,
      salt
    );
    const required = await submissions.requiredPostingBondNow();
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: required });
    await submissions.connect(alice).reveal(1, solutionCid, 1000, 25, salt, "0x");
    await pool.fund({ value: ethers.parseEther("1") });

    await expectCustomError(
      submissions.connect(alice).finalize(1, PERMANENCE_HASH),
      submissions,
      "P42_CHALLENGE_WINDOW_OPEN"
    );
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await expectCustomError(
      submissions.connect(bob).finalize(1, PERMANENCE_HASH),
      submissions,
      "P42_NOT_SOLVER"
    );
    // The finalize permanence receipt is now OPTIONAL (on-chain-at-reveal DA
    // provides availability; the receipt is only an off-chain mirror). Recording
    // one is still supported and stored on the submission.
    await submissions.connect(alice).finalize(1, PERMANENCE_HASH);
    const finalized = await submissions.submissions(1);
    assert.equal(finalized.status, 4n);
    assert.equal(finalized.permanenceHash, PERMANENCE_HASH);
    assert.equal(finalized.bondWei, required);
    assert.equal(await submissions.openSubmissionCount(), 0n);
    // Credit is the MARGINAL frontier reduction: seed - claimed absolute score.
    assert.equal(await ledger.creditAtomsOf(alice.address), SEED_SCORE_ATOMS - 1000n);
    assert.equal(await submissions.bestScoreAtoms(), 1000n);
    assert.equal(await submissions.claimableBondWei(alice.address), 0n);

    await expectCustomError(
      submissions.connect(alice).finalize(1, PERMANENCE_HASH),
      submissions,
      "P42_BAD_SUBMISSION_STATUS"
    );
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await submissions.releaseFinalizedBond(1);
    const bondContractBefore = await ethers.provider.getBalance(await submissions.getAddress());
    await submissions.connect(alice).claimBond();
    assert.equal(bondContractBefore - (await ethers.provider.getBalance(await submissions.getAddress())), required);
    assert.equal(await submissions.claimableBondWei(alice.address), 0n);
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), ethers.parseEther("2"));
  });

  it("blocks ledger close while committed submissions can still reveal", async function () {
    const { alice, treasury, ledger, submissions } = await deployFixture();
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
      "bafy-abandoned-commit",
      alice.address,
      DA_HASH,
      "abandoned"
    );
    const bond = await submissions.requiredPostingBondNow();
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: bond });
    assert.equal(await submissions.openSubmissionCount(), 1n);

    await expectCustomError(ledger.close(), ledger, "P42_OPEN_SUBMISSIONS");
    await expectCustomError(
      submissions.expireCommitted(1),
      submissions,
      "P42_REVEAL_WINDOW_OPEN"
    );

    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.expireCommitted(1);
    const expired = await submissions.submissions(1);
    assert.equal(expired.status, 5n);
    assert.equal(await submissions.openSubmissionCount(), 0n);
    assert.equal(await submissions.claimableBondWei(treasury.address), bond);
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    assert.equal(await ledger.closed(), true);
  });

  it("blocks ledger close while revealed submissions can still finalize permanence", async function () {
    const fixture = await deployFixture();
    const { treasury, ledger, submissions } = fixture;
    const { submissionId, bond } = await commitAndReveal(fixture, {
      solutionCid: "bafy-abandoned-reveal",
      salt: "abandoned-reveal",
    });
    assert.equal(await submissions.openSubmissionCount(), 1n);

    await expectCustomError(ledger.close(), ledger, "P42_OPEN_SUBMISSIONS");
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await expectCustomError(
      submissions.expireRevealed(submissionId),
      submissions,
      "P42_PERMANENCE_GRACE_OPEN"
    );

    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.expireRevealed(submissionId);
    const expired = await submissions.submissions(submissionId);
    assert.equal(expired.status, 5n);
    assert.equal(await submissions.openSubmissionCount(), 0n);
    assert.equal(await submissions.claimableBondWei(treasury.address), bond);
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    assert.equal(await ledger.closed(), true);
  });

  it("scopes ledger credit recording to the owner before activation and recorder after activation", async function () {
    const { owner, alice, ledger, submissions } = await deployFixture({ activateRecorder: false });

    await expectCustomError(
      ledger.connect(alice).recordCredit(alice.address, 1),
      ledger,
      "P42_NOT_CREDIT_RECORDER"
    );
    await ledger.connect(owner).recordCredit(alice.address, 1);
    assert.equal(await ledger.creditAtomsOf(alice.address), 1n);

    await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());
    await expectCustomError(
      ledger.connect(owner).setCreditRecorder(alice.address),
      ledger,
      "P42_CREDIT_RECORDER_ALREADY_SET"
    );
    await expectCustomError(
      ledger.connect(owner).recordCredit(alice.address, 1),
      ledger,
      "P42_NOT_CREDIT_RECORDER"
    );
  });

  it("escrows payouts until close and caps claims by the final denominator", async function () {
    const { alice, bob, pool, ledger } = await deployFixture({ feeBps: 0, activateRecorder: false });
    await pool.fund({ value: ethers.parseEther("10") });

    await ledger.recordCredit(alice.address, 60);
    assert.equal(await ledger.claimable(alice.address), 0n);
    await expectCustomError(pool.connect(alice).claim(), ledger, "P42_NOT_CLOSED");

    await ledger.recordCredit(bob.address, 10000);
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await ledger.setPausedNewActions(true);

    const expectedAlice = (ethers.parseEther("10") * 60n) / 10060n;
    assert.equal(await ledger.finalEntitlement(alice.address), expectedAlice);
    assert.ok(expectedAlice < ethers.parseEther("0.06"));
    const poolBefore = await ethers.provider.getBalance(await pool.getAddress());
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), expectedAlice);
    assert.equal(poolBefore - (await ethers.provider.getBalance(await pool.getAddress())), expectedAlice);
    assert.equal(await ledger.claimable(alice.address), 0n);
  });

  it("pause blocks new credits but cannot block an already owed claim", async function () {
    const { alice, bob, pool, ledger } = await deployFixture({ feeBps: 0, activateRecorder: false });
    await pool.fund({ value: ethers.parseEther("1") });
    await ledger.recordCredit(alice.address, 1);
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await ledger.setPausedNewActions(true);

    await expectCustomError(
      ledger.recordCredit(bob.address, 1),
      ledger,
      "P42_CLOSED"
    );
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), ethers.parseEther("1"));
  });

  it("pause blocks new submission commits while leaving pool claims out of scope", async function () {
    const { alice, submissions, minBond } = await deployFixture();
    await submissions.setPausedNewActions(true);
    const commitment = ethers.keccak256(ethers.toUtf8Bytes("paused-commitment"));

    await expectCustomError(
      submissions.connect(alice).commit(commitment, DA_HASH, { value: minBond }),
      submissions,
      "P42_PAUSED_NEW_ACTIONS"
    );
  });

  it("sizes counter-bonds from the ledger-derived disputed entitlement, not a caller arg", async function () {
    const fixture = await deployFixture();
    const { challenger, pool, challenges, submissions } = fixture;
    // Fund the pool so the revealed submission has a real on-chain entitlement.
    await pool.fund({ value: ethers.parseEther("10") });
    const { submissionId } = await commitAndReveal(fixture);
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("claimed score disagrees with local verifier"));

    // With no prior credits the sole revealed submission is disputing the whole
    // (fee-free) pool, so beta * 10 ETH dominates the floor and rerun terms.
    const disputedEntitlement = ethers.parseEther("10");
    const required = ethers.parseEther("0.5");
    assert.equal(await submissions.disputedEntitlementWei(submissionId), disputedEntitlement);
    assert.equal(await challenges.requiredChallengeBond(disputedEntitlement), required);

    await expectCustomError(
      openChallenge(fixture, challenger, 999, reasonHash, { value: required }),
      submissions,
      "P42_UNKNOWN_SUBMISSION"
    );
    // A caller can no longer pass 0 to collapse the bond: it is derived on-chain.
    await expectCustomError(
      openChallenge(fixture, challenger, submissionId, reasonHash, { value: required - 1n }),
      challenges,
      "P42_INSUFFICIENT_CHALLENGE_BOND"
    );

    await openChallenge(fixture, challenger, submissionId, reasonHash, { value: required });
    const challenge = await challenges.challenges(submissionId);
    const challenged = await submissions.submissions(submissionId);
    assert.equal(challenged.status, 3n);
    assert.equal(challenge.submissionId, submissionId);
    assert.equal(challenge.challenger, challenger.address);
    assert.equal(challenge.reasonHash, reasonHash);
    assert.equal(challenge.challengeBondWei, required);
    assert.equal(challenge.disputeEndsAt - challenge.challengedAt, CHALLENGE_WINDOW_SECONDS);
  });

  it("caps one active challenge per submission so disputes do not serially extend the window", async function () {
    const fixture = await deployFixture();
    const { alice, challenger, challenges } = fixture;
    const { submissionId } = await commitAndReveal(fixture);
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("first challenge"));
    const required = await challenges.requiredChallengeBond(0);

    await openChallenge(fixture, challenger, submissionId, reasonHash, { value: required });
    const original = await challenges.challenges(submissionId);

    await expectCustomError(
      openChallenge(fixture, alice, submissionId, ethers.keccak256(ethers.toUtf8Bytes("second challenge")), {
        value: required,
      }),
      challenges,
      "P42_ALREADY_CHALLENGED"
    );
    const after = await challenges.challenges(submissionId);
    assert.equal(after.disputeEndsAt, original.disputeEndsAt);
    assert.equal(after.challenger, challenger.address);
  });

  it("binds challenge actions to the reveal and dispute instances they were signed for", async function () {
    const fixture = await deployFixture();
    const { owner, resolver, challenger, submissions, challenges } = fixture;
    const { submissionId } = await commitAndReveal(fixture);
    const reasonHash = ethers.id("instance-bound-evidence");
    const required = await challenges.requiredChallengeBond(0);
    const revealInstanceHash = await submissions.revealInstanceHashOf(submissionId);

    // This models a raw challenge transaction signed on an orphaned branch:
    // same submission id, but a different replacement reveal fingerprint.
    await expectCustomError(
      challenges.connect(challenger).challenge(
        submissionId,
        ethers.id("replacement-reveal-instance"),
        reasonHash,
        { value: required },
      ),
      challenges,
      "P42_REVEAL_INSTANCE_MISMATCH",
    );
    await openChallenge(fixture, challenger, submissionId, reasonHash, { value: required });
    const challengeInstanceHash = await challenges.challengeInstanceHashOf(submissionId);
    assert.notEqual(challengeInstanceHash, ethers.ZeroHash);
    assert.equal(await challenges.challengeRevealInstanceHashOf(submissionId), revealInstanceHash);

    const staleChallengeInstanceHash = ethers.id("orphaned-challenge-instance");
    await expectCustomError(
      challenges.connect(resolver).resolve(
        submissionId,
        staleChallengeInstanceHash,
        false,
        ethers.id("stale-transcript"),
        "ar://stale-transcript",
        ethers.id("stale-verdict"),
        { value: await challenges.resolverDecisionBondWei() },
      ),
      challenges,
      "P42_CHALLENGE_INSTANCE_MISMATCH",
    );
    await expectCustomError(
      challenges.expireChallenge(submissionId, staleChallengeInstanceHash),
      challenges,
      "P42_CHALLENGE_INSTANCE_MISMATCH",
    );
    await expectCustomError(
      challenges.connect(owner).slashResolverBond(
        submissionId,
        staleChallengeInstanceHash,
        ethers.id("stale-proof"),
      ),
      challenges,
      "P42_CHALLENGE_INSTANCE_MISMATCH",
    );
  });

  it("requires resolver transcripts and a bonded resolver decision", async function () {
    const fixture = await deployFixture();
    const { owner, alice, treasury, resolver, challenger, submissions, challenges } = fixture;
    const { submissionId, bond } = await commitAndReveal(fixture);
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("verifier mismatch"));
    const transcriptHash = ethers.keccak256(ethers.toUtf8Bytes("rerun transcript bytes"));
    const verdictHash = ethers.keccak256(ethers.toUtf8Bytes("canonical VerdictReport"));
    const transcriptURI = "ar://transcript-test";
    const required = await challenges.requiredChallengeBond(0);
    const resolverBond = await challenges.resolverDecisionBondWei();

    await openChallenge(fixture, challenger, submissionId, reasonHash, { value: required });
    await expectCustomError(
      submissions.connect(alice).finalize(submissionId, PERMANENCE_HASH),
      submissions,
      "P42_BAD_SUBMISSION_STATUS"
    );

    await expectCustomError(
      resolveChallenge(fixture, alice, submissionId, true, transcriptHash, transcriptURI, verdictHash, { value: resolverBond }),
      challenges,
      "P42_NOT_RESOLVER"
    );
    await expectCustomError(
      resolveChallenge(fixture, resolver, submissionId, true, transcriptHash, transcriptURI, verdictHash, {
        value: resolverBond - 1n,
      }),
      challenges,
      "P42_INSUFFICIENT_RESOLVER_BOND"
    );
    await expectCustomError(
      resolveChallenge(fixture, resolver, submissionId, true, ethers.ZeroHash, transcriptURI, verdictHash, {
        value: resolverBond,
      }),
      challenges,
      "P42_EMPTY_TRANSCRIPT_HASH"
    );
    await expectCustomError(
      resolveChallenge(fixture, resolver, submissionId, true, transcriptHash, "", verdictHash, { value: resolverBond }),
      challenges,
      "P42_EMPTY_TRANSCRIPT_URI"
    );
    await expectCustomError(
      resolveChallenge(fixture, resolver, submissionId, true, transcriptHash, transcriptURI, ethers.ZeroHash, {
        value: resolverBond,
      }),
      challenges,
      "P42_EMPTY_VERDICT_HASH"
    );

    await resolveChallenge(fixture, resolver, submissionId, true, transcriptHash, transcriptURI, verdictHash, {
      value: resolverBond,
    });
    const resolved = await challenges.challenges(submissionId);
    const pending = await submissions.submissions(submissionId);
    assert.equal(pending.status, 3n);
    assert.equal(resolved.resolved, false);
    assert.equal(resolved.decisionPending, true);
    assert.equal(resolved.challengerWins, true);
    assert.equal(resolved.transcriptHash, transcriptHash);
    assert.equal(resolved.transcriptURI, transcriptURI);
    assert.equal(resolved.verdictHash, verdictHash);
    const resolverBondState = await challenges.resolverBonds(submissionId);
    assert.equal(resolverBondState.amountWei, resolverBond);
    assert.equal(resolverBondState.releaseAt < resolved.disputeEndsAt, true);
    assert.equal(resolverBondState.releaseAt <= await submissions.maxDisputeEndsAtOf(submissionId), true);
    assert.equal(resolverBondState.slashProofHash, ethers.ZeroHash);
    assert.equal(await challenges.claimableBondWei(challenger.address), 0n);
    assert.equal(await challenges.claimableBondWei(resolver.address), 0n);
    assert.equal(await submissions.claimableBondWei(challenger.address), 0n);
    assert.equal(await submissions.claimableBondWei(treasury.address), 0n);

    await expectCustomError(
      releaseResolverBond(fixture, submissionId),
      challenges,
      "P42_RESOLVER_BOND_LOCKED"
    );
    await expectCustomError(
      slashResolverBond(fixture, submissionId, ethers.ZeroHash),
      challenges,
      "P42_EMPTY_FRAUD_PROOF_HASH"
    );
    const slashProof = ethers.keccak256(ethers.toUtf8Bytes("resolver transcript fraud proof"));
    await slashResolverBond(fixture, submissionId, slashProof);
    const slashed = await challenges.resolverBonds(submissionId);
    assert.equal(slashed.amountWei, 0n);
    assert.equal(slashed.slashProofHash, slashProof);
    assert.equal(await challenges.claimableBondWei(treasury.address), resolverBond);
    assert.equal(await challenges.claimableBondWei(challenger.address), required);
    assert.equal((await submissions.submissions(submissionId)).status, 2n);
    await expectCustomError(
      releaseResolverBond(fixture, submissionId),
      challenges,
      "P42_UNKNOWN_CHALLENGE"
    );

    await expectCustomError(
      submissions.connect(alice).finalize(submissionId, PERMANENCE_HASH),
      submissions,
      "P42_CHALLENGE_WINDOW_OPEN"
    );
    await expectCustomError(
      resolveChallenge(fixture, resolver, submissionId, true, transcriptHash, transcriptURI, verdictHash, {
        value: resolverBond,
      }),
      challenges,
      "P42_UNKNOWN_CHALLENGE"
    );
  });

  it("routes the losing challenge bond to treasury when the solver wins", async function () {
    const fixture = await deployFixture();
    const { alice, treasury, resolver, challenger, ledger, submissions, challenges } = fixture;
    const { submissionId } = await commitAndReveal(fixture, { improvementAtoms: 5 });
    const required = await challenges.requiredChallengeBond(0);
    await openChallenge(
      fixture,
      challenger,
      submissionId,
      ethers.keccak256(ethers.toUtf8Bytes("bad challenge")),
      { value: required },
    );

    await resolveChallenge(fixture, resolver, submissionId,
      false,
      ethers.keccak256(ethers.toUtf8Bytes("solver wins transcript")),
      "ar://solver-wins",
      ethers.keccak256(ethers.toUtf8Bytes("solver wins verdict")),
      { value: await challenges.resolverDecisionBondWei() }
    );

    assert.equal(await challenges.claimableBondWei(treasury.address), 0n);
    assert.equal(await challenges.claimableBondWei(resolver.address), 0n);
    assert.equal((await submissions.submissions(submissionId)).status, 3n);
    await expectCustomError(
      releaseResolverBond(fixture, submissionId),
      challenges,
      "P42_RESOLVER_BOND_LOCKED"
    );
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await releaseResolverBond(fixture, submissionId);
    assert.equal(await challenges.claimableBondWei(treasury.address), required);
    assert.equal(await challenges.claimableBondWei(resolver.address), await challenges.resolverDecisionBondWei());
    const before = await ethers.provider.getBalance(await challenges.getAddress());
    await challenges.connect(treasury).claimBond();
    assert.equal(before - (await ethers.provider.getBalance(await challenges.getAddress())), required);
    assert.equal(await challenges.claimableBondWei(treasury.address), 0n);
    await challenges.connect(resolver).claimBond();
    assert.equal(await challenges.claimableBondWei(resolver.address), 0n);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.connect(alice).finalize(submissionId, PERMANENCE_HASH);
    assert.equal((await submissions.submissions(submissionId)).status, 4n);
    // Marginal credit: seed frontier minus the claimed absolute score (1000).
    assert.equal(await ledger.creditAtomsOf(alice.address), SEED_SCORE_ATOMS - 1000n);
  });

  it("expires a stalled challenge so the solver can finalize and close can proceed (M1)", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { alice, challenger, pool, ledger, submissions, challenges } = fixture;
    await pool.fund({ value: ethers.parseEther("1") });
    const { submissionId } = await commitAndReveal(fixture, { improvementAtoms: 5 });
    const required = await challenges.requiredChallengeBond(await submissions.disputedEntitlementWei(submissionId));
    await openChallenge(
      fixture,
      challenger,
      submissionId,
      ethers.keccak256(ethers.toUtf8Bytes("stalled dispute")),
      { value: required },
    );
    assert.equal((await submissions.submissions(submissionId)).status, 3n);

    // Before the dispute deadline the permissionless timeout is closed.
    await expectCustomError(
      expireChallenge(fixture, alice, submissionId),
      challenges,
      "P42_DISPUTE_WINDOW_OPEN"
    );

    // The resolver never posts a decision; anyone can time the challenge out.
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await expireChallenge(fixture, alice, submissionId);
    // The one-shot challenge slot is cleared so a fresh challenge stays
    // possible in the re-armed window (F3).
    const expired = await challenges.challenges(submissionId);
    assert.equal(expired.challenger, ethers.ZeroAddress);
    // No adjudication occurred, so the challenger's posted bond is returned.
    assert.equal(await challenges.claimableBondWei(challenger.address), required);

    // The submission is back to Revealed with a re-armed challenge window
    // (F5); once it elapses the solver can finalize and unblock close.
    assert.equal((await submissions.submissions(submissionId)).status, 2n);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.connect(alice).finalize(submissionId, PERMANENCE_HASH);
    assert.equal((await submissions.submissions(submissionId)).status, 4n);
    assert.equal(await submissions.openSubmissionCount(), 0n);
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    assert.equal(await ledger.closed(), true);

    // The cleared slot cannot be re-expired afterwards.
    await expectCustomError(
      expireChallenge(fixture, alice, submissionId),
      challenges,
      "P42_UNKNOWN_CHALLENGE"
    );
  });

  it("pays a winning challenger more than their posted counter-bond (M2)", async function () {
    const fixture = await deployFixture();
    const { treasury, resolver, challenger, submissions, challenges } = fixture;
    const { submissionId, bond } = await commitAndReveal(fixture, { improvementAtoms: 3 });
    const required = await challenges.requiredChallengeBond(await submissions.disputedEntitlementWei(submissionId));
    await openChallenge(
      fixture,
      challenger,
      submissionId,
      ethers.keccak256(ethers.toUtf8Bytes("provable fraud")),
      { value: required },
    );

    await resolveChallenge(fixture, resolver, submissionId,
      true,
      ethers.keccak256(ethers.toUtf8Bytes("challenger wins transcript")),
      "ar://challenger-wins",
      ethers.keccak256(ethers.toUtf8Bytes("challenger wins verdict")),
      { value: await challenges.resolverDecisionBondWei() }
    );
    await increaseTime(RESOLVER_FRAUD_WINDOW_SECONDS + 1n);
    await finalizeChallengeResolution(fixture, submissionId);

    // Own counter-bond refunded on the challenge manager...
    const ownRefund = await challenges.claimableBondWei(challenger.address);
    // ...plus the rejected solver's forfeited posting bond on the submission manager.
    const forfeited = await submissions.claimableBondWei(challenger.address);
    assert.equal(ownRefund, required);
    assert.equal(forfeited, bond);
    assert.equal(await submissions.claimableBondWei(treasury.address), 0n);

    const netClaimable = ownRefund + forfeited;
    assert.equal(netClaimable, required + bond);
    assert.equal(netClaimable > required, true);
  });

  it("sweeps the withheld fee to the treasury exactly once after close (L1)", async function () {
    const { alice, treasury, pool, ledger } = await deployFixture({ feeBps: 250, activateRecorder: false });
    await pool.fund({ value: ethers.parseEther("10") });
    await ledger.recordCredit(alice.address, 1);

    // Nothing to sweep before close.
    await expectCustomError(ledger.sweepFee(), ledger, "P42_NOT_CLOSED");

    await advanceToEffectiveClose(ledger);
    await ledger.close();
    const feeReserve = await ledger.feeReserve();
    assert.equal(feeReserve, (ethers.parseEther("10") * 250n) / 10_000n);

    const treasuryBefore = await ethers.provider.getBalance(treasury.address);
    const poolBefore = await ethers.provider.getBalance(await pool.getAddress());
    await ledger.sweepFee();
    assert.equal((await ethers.provider.getBalance(treasury.address)) - treasuryBefore, feeReserve);
    assert.equal(poolBefore - (await ethers.provider.getBalance(await pool.getAddress())), feeReserve);
    assert.equal(await ledger.feeSwept(), true);
    assert.equal(await pool.totalFeePaid(), feeReserve);

    // The fee cannot be swept twice.
    await expectCustomError(ledger.sweepFee(), ledger, "P42_FEE_ALREADY_SWEPT");

    // The solver still claims the full distributable pool with no underflow.
    const distributable = await ledger.distributablePool();
    const before = await ethers.provider.getBalance(await pool.getAddress());
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), distributable);
    assert.equal(before - (await ethers.provider.getBalance(await pool.getAddress())), distributable);
    assert.equal(await pool.funded(), 0n);
  });

  it("rejects deposits once the ledger has closed (L2)", async function () {
    const { alice, pool, ledger } = await deployFixture({ feeBps: 0, activateRecorder: false });
    await pool.fund({ value: ethers.parseEther("1") });
    await advanceToEffectiveClose(ledger);
    await ledger.close();

    await expectCustomError(pool.fund({ value: 1n }), pool, "P42_POOL_CLOSED");
    await expectCustomError(
      alice.sendTransaction({ to: await pool.getAddress(), value: 1n }),
      pool,
      "P42_POOL_CLOSED"
    );
  });

  it("latches a funded problem frozen so it stays frozen after the pool drains (L5)", async function () {
    const fixture = await deployFixture({ feeBps: 0, activateRecorder: false });
    const { alice, pool, ledger, registry } = fixture;
    await registry.register(await registryConfig(fixture));

    // Cannot latch before the pool is funded.
    await expectCustomError(registry.latchFrozen(1), registry, "P42_NOT_FUNDED");

    // Fund the pool, then permanently latch the freeze (one-way, monotonic).
    await pool.fund({ value: ethers.parseEther("1") });
    await registry.latchFrozen(1);
    assert.equal((await registry.problems(1)).frozen, true);
    assert.equal(await registry.isFrozen(1), true);
    await expectCustomError(registry.latchFrozen(1), registry, "P42_ALREADY_FROZEN");

    // Drain the pool back to zero through a full credit/close/claim cycle.
    await ledger.recordCredit(alice.address, 1);
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await pool.connect(alice).claim();
    assert.equal(await pool.funded(), 0n);

    // The balance-derived fallback would now read unfrozen, but the latch holds,
    // so the anchored spec/verifier hashes remain immutable.
    await expectCustomError(
      registry.updateBeforeFunding(1, await registryConfig(fixture)),
      registry,
      "P42_ALREADY_FROZEN"
    );
  });

  // ===========================================================================
  // F15 — post-close claim deadline + full residual sweep. finalEntitlement
  // floors each share (dust strands) and never-claimed entitlements would
  // strand forever; policy: 365 days to claim after close(), then anyone can
  // sweep the pool's FULL remaining balance to the treasury.
  // ===========================================================================
  const CLAIM_DEADLINE_SECONDS = 365n * 24n * 60n * 60n;

  it("enforces the 365-day claim deadline after close (F15)", async function () {
    const { alice, bob, pool, ledger } = await deployFixture({ feeBps: 0, activateRecorder: false });
    await pool.fund({ value: ethers.parseEther("10") });
    await ledger.recordCredit(alice.address, 60);
    await ledger.recordCredit(bob.address, 40);

    assert.equal(await ledger.CLAIM_DEADLINE_SECONDS(), CLAIM_DEADLINE_SECONDS);
    assert.equal(await ledger.claimDeadline(), 0n); // knowable only after close

    // close() anchors the deadline and publishes it in the Closed event.
    await advanceToEffectiveClose(ledger);
    const tx = await ledger.close();
    const receipt = await tx.wait();
    const closedEvent = receipt.logs
      .map((log) => {
        try {
          return ledger.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed && parsed.name === "Closed");
    assert.ok(closedEvent, "Closed event present");
    const closedAt = await ledger.closedAt();
    assert.ok(closedAt > 0n);
    assert.equal(closedEvent.args.closedAt, closedAt);
    assert.equal(closedEvent.args.claimDeadline, closedAt + CLAIM_DEADLINE_SECONDS);
    assert.equal(await ledger.claimDeadline(), closedAt + CLAIM_DEADLINE_SECONDS);

    // Before the deadline claims flow normally.
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), ethers.parseEther("6"));

    // After the deadline the claim path is shut with a named error.
    await increaseTime(CLAIM_DEADLINE_SECONDS + 1n);
    await expectCustomError(pool.connect(bob).claim(), ledger, "P42_CLAIMS_EXPIRED");
    assert.equal(await ledger.claimedWeiOf(bob.address), 0n);
  });

  it("sweeps the full residual to the treasury only after the claim deadline (F15)", async function () {
    const { alice, bob, treasury, pool, ledger } = await deployFixture({ feeBps: 0, activateRecorder: false });
    await pool.fund({ value: ethers.parseEther("10") });
    await ledger.recordCredit(alice.address, 3);
    await ledger.recordCredit(bob.address, 7);

    // No sweep before close, and none while solvers still own their window.
    await expectCustomError(ledger.sweepResidual(), ledger, "P42_NOT_CLOSED");
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await expectCustomError(ledger.sweepResidual(), ledger, "P42_CLAIMS_NOT_EXPIRED");

    // alice claims in time; bob never does.
    await pool.connect(alice).claim();
    const aliceShare = (ethers.parseEther("10") * 3n) / 10n;
    assert.equal(await ledger.claimedWeiOf(alice.address), aliceShare);

    await increaseTime(CLAIM_DEADLINE_SECONDS + 1n);
    const residual = await pool.funded();
    assert.equal(residual, ethers.parseEther("10") - aliceShare); // bob's stranded share
    const treasuryBefore = await ethers.provider.getBalance(treasury.address);
    // Permissionless: any caller may trigger the sweep.
    await ledger.connect(bob).sweepResidual();
    assert.equal((await ethers.provider.getBalance(treasury.address)) - treasuryBefore, residual);
    assert.equal(await pool.funded(), 0n);
    assert.equal(await ledger.residualSwept(), true);
    // Dedicated accounting: the residual never pollutes the fee counter.
    assert.equal(await pool.totalResidualPaid(), residual);
    assert.equal(await pool.totalFeePaid(), 0n);

    // Late claims stay blocked and the sweep is one-shot.
    await expectCustomError(pool.connect(bob).claim(), ledger, "P42_CLAIMS_EXPIRED");
    await expectCustomError(ledger.sweepResidual(), ledger, "P42_RESIDUAL_ALREADY_SWEPT");
  });

  it("sweeps the whole balance of a pool that closed with zero credited solvers (F15 canary edge)", async function () {
    const { treasury, pool, ledger } = await deployFixture({ feeBps: 0, activateRecorder: false });
    await pool.fund({ value: ethers.parseEther("1") });
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    assert.equal(await ledger.totalCreditAtoms(), 0n);

    await increaseTime(CLAIM_DEADLINE_SECONDS + 1n);
    const treasuryBefore = await ethers.provider.getBalance(treasury.address);
    await ledger.sweepResidual();
    // finalEntitlement is 0 for everyone, yet the FULL balance is recovered.
    assert.equal((await ethers.provider.getBalance(treasury.address)) - treasuryBefore, ethers.parseEther("1"));
    assert.equal(await pool.funded(), 0n);
    assert.equal(await pool.totalResidualPaid(), ethers.parseEther("1"));
  });

  it("keeps payResidual ledger-only and the fee sweep independently available (F15)", async function () {
    const { alice, treasury, pool, ledger } = await deployFixture({ feeBps: 250, activateRecorder: false });
    await pool.fund({ value: ethers.parseEther("10") });
    await ledger.recordCredit(alice.address, 1);
    await advanceToEffectiveClose(ledger);
    await ledger.close();

    // Direct calls to the escrow's residual path are ledger-only.
    await expectCustomError(pool.connect(alice).payResidual(alice.address, 1n), pool, "P42_NOT_LEDGER");

    // sweepFee remains independently available before the residual sweep.
    await ledger.sweepFee();
    const feeReserve = await ledger.feeReserve();
    assert.equal(await pool.totalFeePaid(), feeReserve);

    await increaseTime(CLAIM_DEADLINE_SECONDS + 1n);
    const residual = await pool.funded();
    assert.equal(residual, ethers.parseEther("10") - feeReserve); // alice never claimed
    const treasuryBefore = await ethers.provider.getBalance(treasury.address);
    await ledger.sweepResidual();
    assert.equal((await ethers.provider.getBalance(treasury.address)) - treasuryBefore, residual);
    // Fee and residual counters stay segregated.
    assert.equal(await pool.totalFeePaid(), feeReserve);
    assert.equal(await pool.totalResidualPaid(), residual);
    assert.equal(await pool.funded(), 0n);
  });
});
