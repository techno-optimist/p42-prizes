import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const CHALLENGE_WINDOW_SECONDS = 72n * 60n * 60n;
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

describe("P42 Gate 1 contract scaffold", function () {
  async function deployFixture({ alphaBps = 200n, minBond = ethers.parseEther("0.01"), feeBps = 0 } = {}) {
    const [owner, treasury, resolver, alice, bob, challenger] = await ethers.getSigners();
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
      alphaBps,
      minBond,
      CHALLENGE_WINDOW_SECONDS
    );
    await submissions.waitForDeployment();
    await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());

    const Challenges = await ethers.getContractFactory("P42ChallengeManager");
    const challenges = await Challenges.deploy(
      owner.address,
      resolver.address,
      treasury.address,
      CHALLENGE_WINDOW_SECONDS,
      500,
      ethers.parseEther("0.02"),
      ethers.parseEther("0.01"),
      30000,
      ethers.parseEther("0.005")
    );
    await challenges.waitForDeployment();

    const Registry = await ethers.getContractFactory("P42ProblemRegistry");
    const registry = await Registry.deploy(owner.address);
    await registry.waitForDeployment();

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
      await submissions.computeCommitment("bafy-test", alice.address, "s3cret"),
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
    const { alice, pool, submissions, minBond } = await deployFixture({ alphaBps: 200n });
    const solutionCid = "bafy-empty-pool";
    const salt = "empty-pool-salt";
    const commitment = await submissions.computeCommitment(solutionCid, alice.address, salt);

    await submissions.connect(alice).commit(commitment, DA_HASH, { value: minBond });
    await pool.fund({ value: ethers.parseEther("100") });

    assert.equal(await submissions.bondCoversEntitlement(1, ethers.parseEther("100")), false);
    await expectCustomError(
      submissions.requireFinalizeBond(1, ethers.parseEther("100")),
      submissions,
      "P42_BOND_UNDERCOVERS_ENTITLEMENT"
    );
    await submissions.connect(alice).reveal(1, solutionCid, 100, 1, salt);
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await expectCustomError(
      submissions.connect(alice).finalize(1, PERMANENCE_HASH),
      submissions,
      "P42_BOND_UNDERCOVERS_ENTITLEMENT"
    );
  });

  it("requires commit-time DA evidence and a valid CID-bound reveal", async function () {
    const { alice, bob, submissions, minBond } = await deployFixture();
    const solutionCid = "bafy-solution-a";
    const salt = "s3cret";
    const commitment = await submissions.computeCommitment(solutionCid, alice.address, salt);

    await expectCustomError(
      submissions.connect(alice).commit(commitment, ethers.ZeroHash, { value: minBond }),
      submissions,
      "P42_EMPTY_DA_HASH"
    );

    await submissions.connect(alice).commit(commitment, DA_HASH, { value: minBond });

    await expectCustomError(
      submissions.connect(bob).reveal(1, solutionCid, 123, 7, salt),
      submissions,
      "P42_NOT_SOLVER"
    );
    await expectCustomError(
      submissions.connect(alice).reveal(1, solutionCid, 123, 7, "wrong-salt"),
      submissions,
      "P42_BAD_COMMITMENT_REVEAL"
    );
    await expectCustomError(
      submissions.connect(alice).reveal(1, solutionCid, 123, 0, salt),
      submissions,
      "P42_ZERO_IMPROVEMENT"
    );

    await submissions.connect(alice).reveal(1, solutionCid, 123, 7, salt);
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
    const commitment = await submissions.computeCommitment(solutionCid, alice.address, salt);
    const required = await submissions.requiredPostingBondNow();
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: required });
    await submissions.connect(alice).reveal(1, solutionCid, 1000, 25, salt);

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
    await expectCustomError(
      submissions.connect(alice).finalize(1, ethers.ZeroHash),
      submissions,
      "P42_EMPTY_PERMANENCE_HASH"
    );

    await submissions.connect(alice).finalize(1, PERMANENCE_HASH);
    const finalized = await submissions.submissions(1);
    assert.equal(finalized.status, 3n);
    assert.equal(finalized.permanenceHash, PERMANENCE_HASH);
    assert.equal(await ledger.creditAtomsOf(alice.address), 25n);

    await expectCustomError(
      submissions.connect(alice).finalize(1, PERMANENCE_HASH),
      submissions,
      "P42_BAD_SUBMISSION_STATUS"
    );
    await ledger.close();
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), ethers.parseEther("1"));
  });

  it("scopes ledger credit recording to the owner or submission manager", async function () {
    const { alice, ledger } = await deployFixture();

    await expectCustomError(
      ledger.connect(alice).recordCredit(alice.address, 1),
      ledger,
      "P42_NOT_CREDIT_RECORDER"
    );
  });

  it("escrows payouts until close and caps claims by the final denominator", async function () {
    const { alice, bob, pool, ledger } = await deployFixture({ feeBps: 0 });
    await pool.fund({ value: ethers.parseEther("10") });

    await ledger.recordCredit(alice.address, 60);
    assert.equal(await ledger.claimable(alice.address), 0n);
    await expectCustomError(pool.connect(alice).claim(), ledger, "P42_NOT_CLOSED");

    await ledger.recordCredit(bob.address, 10000);
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
    const { alice, bob, pool, ledger } = await deployFixture({ feeBps: 0 });
    await pool.fund({ value: ethers.parseEther("1") });
    await ledger.recordCredit(alice.address, 1);
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

  it("requires counter-bonds to cover delay value and rerun cost", async function () {
    const { challenger, challenges } = await deployFixture();
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("claimed score disagrees with local verifier"));
    const finalizingEntitlement = ethers.parseEther("10");
    const required = ethers.parseEther("0.5");

    assert.equal(await challenges.requiredChallengeBond(finalizingEntitlement), required);
    await expectCustomError(
      challenges.connect(challenger).challenge(1, reasonHash, finalizingEntitlement, { value: required - 1n }),
      challenges,
      "P42_INSUFFICIENT_CHALLENGE_BOND"
    );

    await challenges.connect(challenger).challenge(1, reasonHash, finalizingEntitlement, { value: required });
    const challenge = await challenges.challenges(1);
    assert.equal(challenge.submissionId, 1n);
    assert.equal(challenge.challenger, challenger.address);
    assert.equal(challenge.reasonHash, reasonHash);
    assert.equal(challenge.challengeBondWei, required);
    assert.equal(challenge.disputeEndsAt - challenge.challengedAt, 72n * 60n * 60n);
  });

  it("caps one active challenge per submission so disputes do not serially extend the window", async function () {
    const { alice, challenger, challenges } = await deployFixture();
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("first challenge"));
    const required = await challenges.requiredChallengeBond(0);

    await challenges.connect(challenger).challenge(42, reasonHash, 0, { value: required });
    const original = await challenges.challenges(42);

    await expectCustomError(
      challenges.connect(alice).challenge(42, ethers.keccak256(ethers.toUtf8Bytes("second challenge")), 0, {
        value: required,
      }),
      challenges,
      "P42_ALREADY_CHALLENGED"
    );
    const after = await challenges.challenges(42);
    assert.equal(after.disputeEndsAt, original.disputeEndsAt);
    assert.equal(after.challenger, challenger.address);
  });

  it("requires resolver transcripts and a bonded resolver decision", async function () {
    const { alice, resolver, challenger, challenges } = await deployFixture();
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("verifier mismatch"));
    const transcriptHash = ethers.keccak256(ethers.toUtf8Bytes("rerun transcript bytes"));
    const verdictHash = ethers.keccak256(ethers.toUtf8Bytes("canonical VerdictReport"));
    const transcriptURI = "ar://transcript-test";
    const required = await challenges.requiredChallengeBond(0);
    const resolverBond = await challenges.resolverDecisionBondWei();

    await challenges.connect(challenger).challenge(7, reasonHash, 0, { value: required });

    await expectCustomError(
      challenges.connect(alice).resolve(7, true, transcriptHash, transcriptURI, verdictHash, { value: resolverBond }),
      challenges,
      "P42_NOT_RESOLVER"
    );
    await expectCustomError(
      challenges.connect(resolver).resolve(7, true, transcriptHash, transcriptURI, verdictHash, {
        value: resolverBond - 1n,
      }),
      challenges,
      "P42_INSUFFICIENT_RESOLVER_BOND"
    );
    await expectCustomError(
      challenges.connect(resolver).resolve(7, true, ethers.ZeroHash, transcriptURI, verdictHash, {
        value: resolverBond,
      }),
      challenges,
      "P42_EMPTY_TRANSCRIPT_HASH"
    );
    await expectCustomError(
      challenges.connect(resolver).resolve(7, true, transcriptHash, "", verdictHash, { value: resolverBond }),
      challenges,
      "P42_EMPTY_TRANSCRIPT_URI"
    );
    await expectCustomError(
      challenges.connect(resolver).resolve(7, true, transcriptHash, transcriptURI, ethers.ZeroHash, {
        value: resolverBond,
      }),
      challenges,
      "P42_EMPTY_VERDICT_HASH"
    );

    await challenges.connect(resolver).resolve(7, true, transcriptHash, transcriptURI, verdictHash, {
      value: resolverBond,
    });
    const resolved = await challenges.challenges(7);
    assert.equal(resolved.resolved, true);
    assert.equal(resolved.challengerWins, true);
    assert.equal(resolved.transcriptHash, transcriptHash);
    assert.equal(resolved.transcriptURI, transcriptURI);
    assert.equal(resolved.verdictHash, verdictHash);
    assert.equal(resolved.resolverBondWei, resolverBond);
    assert.equal(await challenges.claimableBondWei(challenger.address), required);

    await expectCustomError(
      challenges.connect(resolver).resolve(7, true, transcriptHash, transcriptURI, verdictHash, {
        value: resolverBond,
      }),
      challenges,
      "P42_ALREADY_RESOLVED"
    );
  });

  it("routes the losing challenge bond to treasury when the solver wins", async function () {
    const { treasury, resolver, challenger, challenges } = await deployFixture();
    const required = await challenges.requiredChallengeBond(0);
    await challenges
      .connect(challenger)
      .challenge(99, ethers.keccak256(ethers.toUtf8Bytes("bad challenge")), 0, { value: required });

    await challenges.connect(resolver).resolve(
      99,
      false,
      ethers.keccak256(ethers.toUtf8Bytes("solver wins transcript")),
      "ar://solver-wins",
      ethers.keccak256(ethers.toUtf8Bytes("solver wins verdict")),
      { value: await challenges.resolverDecisionBondWei() }
    );

    assert.equal(await challenges.claimableBondWei(treasury.address), required);
    const before = await ethers.provider.getBalance(await challenges.getAddress());
    await challenges.connect(treasury).claimBond();
    assert.equal(before - (await ethers.provider.getBalance(await challenges.getAddress())), required);
    assert.equal(await challenges.claimableBondWei(treasury.address), 0n);
  });
});
