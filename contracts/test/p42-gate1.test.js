import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

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
    const submissions = await Submissions.deploy(await pool.getAddress(), owner.address, alphaBps, minBond);
    await submissions.waitForDeployment();

    const Challenges = await ethers.getContractFactory("P42ChallengeManager");
    const challenges = await Challenges.deploy(
      owner.address,
      resolver.address,
      treasury.address,
      72n * 60n * 60n,
      500,
      ethers.parseEther("0.02"),
      ethers.parseEther("0.01"),
      30000,
      ethers.parseEther("0.005")
    );
    await challenges.waitForDeployment();

    return { owner, treasury, resolver, alice, bob, challenger, pool, ledger, submissions, challenges, minBond };
  }

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
      submissions.connect(alice).commit(commitment, { value: required - 1n }),
      submissions,
      "P42_INSUFFICIENT_POSTING_BOND"
    );

    await submissions.connect(alice).commit(commitment, { value: required });
    const submission = await submissions.submissions(1);
    assert.equal(submission.solver, alice.address);
    assert.equal(submission.commitment, commitment);
    assert.equal(submission.bondWei, required);
    assert.equal(submission.poolAtSubmissionWei, ethers.parseEther("100"));
    assert.equal(submission.requiredBondWei, required);
  });

  it("detects empty-pool bond leverage before finalization", async function () {
    const { alice, pool, submissions, minBond } = await deployFixture({ alphaBps: 200n });
    const commitment = ethers.keccak256(ethers.toUtf8Bytes("empty-pool-commitment"));

    await submissions.connect(alice).commit(commitment, { value: minBond });
    await pool.fund({ value: ethers.parseEther("100") });

    assert.equal(await submissions.bondCoversEntitlement(1, ethers.parseEther("100")), false);
    await expectCustomError(
      submissions.requireFinalizeBond(1, ethers.parseEther("100")),
      submissions,
      "P42_BOND_UNDERCOVERS_ENTITLEMENT"
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
      submissions.connect(alice).commit(commitment, { value: minBond }),
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
