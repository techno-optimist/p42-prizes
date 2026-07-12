import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const CHALLENGE_WINDOW_SECONDS = 72n * 60n * 60n;
const RESOLVER_FRAUD_WINDOW_SECONDS = 24n * 60n * 60n;
const FUNDING_CAP = ethers.parseEther("100");
const MIN_COMPETITION_SECONDS = 30n * 24n * 60n * 60n;

async function nextEarliestClose() {
  const latest = await ethers.provider.getBlock("latest");
  return BigInt(latest.timestamp) + MIN_COMPETITION_SECONDS + 1_000n;
}

async function nextCloseBy() {
  const latest = await ethers.provider.getBlock("latest");
  return BigInt(latest.timestamp) + 181n * 24n * 60n * 60n;
}
// Absolute-score frontier seed (F1): fixtures reveal claimed score 0, which
// strictly beats this and earns the full seed-relative marginal.
const SEED_SCORE_ATOMS = 1_000_000n;
const DA_HASH = ethers.keccak256(ethers.toUtf8Bytes("redteam DA receipt"));
const PERMANENCE_HASH = ethers.keccak256(ethers.toUtf8Bytes("redteam permanence receipt"));

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

async function deployFixture({
  alphaBps = 200n,
  minBond = ethers.parseEther("0.01"),
  feeBps = 0,
  activateRecorder = true,
} = {}) {
  const [owner, treasury, resolver, alice, bob] = await ethers.getSigners();
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
  const submissions = await Submissions.deploy(
    await pool.getAddress(),
    await ledger.getAddress(),
    owner.address,
    treasury.address,
    alphaBps,
    minBond,
    CHALLENGE_WINDOW_SECONDS,
    false, // off-chain DA mode: red-team fixtures exercise economics, not DA binding
    0,
    SEED_SCORE_ATOMS,
    1n // minImprovementAtoms
  );
  await submissions.waitForDeployment();
  let fundingManager = submissions;
  let creditRecorder = submissions;
  if (activateRecorder) {
    await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());
  } else {
    const Mock = await ethers.getContractFactory("MockFundingArmed");
    const mock = await Mock.deploy(true);
    await mock.waitForDeployment();
    fundingManager = mock;
    creditRecorder = mock;
    await ledger.connect(owner).setCreditRecorder(await mock.getAddress());
  }

  // OPEN-WITNESS-PHASE wiring: arm funding up front so the red-team scenarios
  // run in the PAID phase (their credit/payout assertions are unchanged).
  await pool.connect(owner).setSubmissionManager(await fundingManager.getAddress());

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
  await registry.register({
    specHash: ethers.id("redteam-spec"),
    verifierSourceHash: ethers.id("redteam-source"),
    verifierImageHash: ethers.id("redteam-image"),
    admissionMatrixHash: ethers.id("redteam-matrix"),
    metadataURI: "ipfs://redteam-fixture",
    pool: await pool.getAddress(),
    ledger: await ledger.getAddress(),
    submissionManager: await fundingManager.getAddress(),
    challengeManager: await challenges.getAddress(),
    challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS,
    minImprovementAtoms: 1n,
  });
  await registry.freeze(1);
  await pool.connect(owner).setRegistry(await registry.getAddress(), 1);
  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), owner.address);
  await vault.waitForDeployment();
  await ledger.connect(owner).setRolloverDestination(await vault.getAddress());
  await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
  if (activateRecorder) {
    await submissions.connect(treasury).authorizeFunding("0x" + "42".repeat(32));
    await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
  }
  await pool.connect(owner).setAcceptingFunds(true);
  await increaseTime(MIN_COMPETITION_SECONDS + 1_001n);

  const Attacker = await ethers.getContractFactory("ReentrantClaimer");

  return {
    owner,
    treasury,
    resolver,
    alice,
    bob,
    pool,
    ledger,
    submissions,
    challenges,
    creditRecorder,
    vault,
    Attacker,
    minBond,
  };
}

// Drive commit + reveal for a submission whose solver is `solverAddr`, sending
// the transactions from `sender` (either a signer or, via forwardExec, a mock).
async function commitReveal(fixture, { solverAddr, sendCommit, sendReveal, improvementAtoms = 1n, cid = "bafy-redteam", salt = "redteam-salt" }) {
  const { submissions } = fixture;
  const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
    cid,
    solverAddr,
    DA_HASH,
    salt
  );
  const bond = await submissions.requiredPostingBondNow();
  await sendCommit(commitment, bond);
  const submissionId = await submissions.submissionCount();
  await sendReveal(submissionId, cid, improvementAtoms, salt);
  return { submissionId, cid, salt, bond };
}

describe("P42 red-team attack coverage", function () {
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

  // ---------------------------------------------------------------------------
  // Risk 12 — reentrancy against every ETH-outflow path.
  // A concrete malicious receiver (ReentrantClaimer) re-enters the caller mid
  // payout. Each path must (a) block the re-entrant call and (b) pay the
  // attacker its single honest entitlement exactly once — no double-withdraw.
  // ---------------------------------------------------------------------------

  it("risk12: reentrant receiver cannot double-withdraw from P42BountyPool.claim()", async function () {
    const fixture = await deployFixture({ feeBps: 0, activateRecorder: false });
    const { owner, pool, ledger, creditRecorder, Attacker } = fixture;
    const attacker = await Attacker.deploy();
    await attacker.waitForDeployment();
    const attackerAddr = await attacker.getAddress();

    await pool.fund({ value: ethers.parseEther("5") });
    // Attacker is the sole credited solver, so its honest entitlement is the
    // whole distributable pool. A working reentrancy would drain twice.
    await creditRecorder.recordCredit(await ledger.getAddress(), attackerAddr, 1);
    await advanceToEffectiveClose(ledger);
    await ledger.connect(owner).close();
    const entitlement = await ledger.finalEntitlement(attackerAddr);
    assert.equal(entitlement, ethers.parseEther("5"));

    // Arm a one-shot re-entrant claim(), then trigger the honest claim as the
    // attacker contract. The re-entry must fail; the payout must still settle.
    const claimData = pool.interface.encodeFunctionData("claim");
    await attacker.arm(await pool.getAddress(), claimData);
    const poolBefore = await ethers.provider.getBalance(await pool.getAddress());
    await attacker.exec(await pool.getAddress(), 0, claimData);

    assert.equal(await attacker.reentryCallCount(), 1n);
    assert.equal(await attacker.reentrySucceeded(), false); // nonReentrant + CEI held
    assert.equal(await attacker.totalReceivedWei(), entitlement); // paid exactly once
    assert.equal(poolBefore - (await ethers.provider.getBalance(await pool.getAddress())), entitlement);
    assert.equal(await ledger.claimedWeiOf(attackerAddr), entitlement);
    // Nothing left to steal on a second, non-reentrant attempt.
    await expectCustomError(attacker.exec(await pool.getAddress(), 0, claimData), pool, "P42_NOTHING_TO_CLAIM");
  });

  it("risk12: reentrant receiver cannot double-withdraw from P42SubmissionManager.claimBond()", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { ledger, submissions, Attacker } = fixture;
    const attacker = await Attacker.deploy();
    await attacker.waitForDeployment();
    const attackerAddr = await attacker.getAddress();
    const subAddr = await submissions.getAddress();

    // The attacker contract is the solver: commit/reveal/finalize as itself so
    // its posting bond becomes claimable, then re-enter the bond payout.
    const { submissionId, bond } = await commitReveal(fixture, {
      solverAddr: attackerAddr,
      sendCommit: async (commitment, bond) => {
        const data = submissions.interface.encodeFunctionData("commit", [commitment, DA_HASH]);
        await attacker.exec(subAddr, bond, data, { value: bond });
      },
      sendReveal: async (id, cid, improvement, salt) => {
        const data = submissions.interface.encodeFunctionData("reveal", [id, cid, 0, improvement, salt, "0x"]);
        await attacker.exec(subAddr, 0, data);
      },
    });

    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const finalizeData = submissions.interface.encodeFunctionData("finalize", [submissionId, PERMANENCE_HASH]);
    await attacker.exec(subAddr, 0, finalizeData);
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await submissions.releaseFinalizedBond(submissionId);
    assert.equal(await submissions.claimableBondWei(attackerAddr), bond);

    const claimData = submissions.interface.encodeFunctionData("claimBond");
    await attacker.arm(subAddr, claimData);
    const subBefore = await ethers.provider.getBalance(subAddr);
    await attacker.exec(subAddr, 0, claimData);

    assert.equal(await attacker.reentryCallCount(), 1n);
    assert.equal(await attacker.reentrySucceeded(), false);
    assert.equal(await attacker.totalReceivedWei(), bond);
    assert.equal(subBefore - (await ethers.provider.getBalance(subAddr)), bond);
    assert.equal(await submissions.claimableBondWei(attackerAddr), 0n);
    await expectCustomError(attacker.exec(subAddr, 0, claimData), submissions, "P42_NO_BOND_TO_CLAIM");
  });

  it("risk12: reentrant receiver cannot double-withdraw from P42ChallengeManager.claimBond()", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { alice, resolver, submissions, challenges, Attacker } = fixture;
    const attacker = await Attacker.deploy();
    await attacker.waitForDeployment();
    const attackerAddr = await attacker.getAddress();
    const chalAddr = await challenges.getAddress();

    // Honest solver (alice) posts a revealed submission for the attacker to challenge.
    const { submissionId } = await commitReveal(fixture, {
      solverAddr: alice.address,
      sendCommit: async (commitment, bond) => {
        await submissions.connect(alice).commit(commitment, DA_HASH, { value: bond });
      },
      sendReveal: async (id, cid, improvement, salt) => {
        await submissions.connect(alice).reveal(id, cid, 0, improvement, salt, "0x");
      },
    });

    // The attacker contract is the winning challenger, so its counter-bond
    // becomes claimable on the challenge manager.
    const required = await challenges.requiredChallengeBond(await submissions.disputedEntitlementWei(submissionId));
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("attacker challenge"));
    const challengeData = challenges.interface.encodeFunctionData("challenge", [
      submissionId,
      await submissions.revealInstanceHashOf(submissionId),
      reasonHash,
    ]);
    await attacker.exec(chalAddr, required, challengeData, { value: required });

    await resolveChallenge(fixture, resolver, submissionId,
      true,
      ethers.keccak256(ethers.toUtf8Bytes("challenger wins transcript")),
      "ar://redteam-challenger-wins",
      ethers.keccak256(ethers.toUtf8Bytes("challenger wins verdict")),
      { value: await challenges.resolverDecisionBondWei() }
    );
    await increaseTime(RESOLVER_FRAUD_WINDOW_SECONDS + 1n);
    await finalizeChallengeResolution(fixture, submissionId);
    assert.equal(await challenges.claimableBondWei(attackerAddr), required);

    const claimData = challenges.interface.encodeFunctionData("claimBond");
    await attacker.arm(chalAddr, claimData);
    const chalBefore = await ethers.provider.getBalance(chalAddr);
    await attacker.exec(chalAddr, 0, claimData);

    assert.equal(await attacker.reentryCallCount(), 1n);
    assert.equal(await attacker.reentrySucceeded(), false);
    assert.equal(await attacker.totalReceivedWei(), required);
    assert.equal(chalBefore - (await ethers.provider.getBalance(chalAddr)), required);
    assert.equal(await challenges.claimableBondWei(attackerAddr), 0n);
    await expectCustomError(attacker.exec(chalAddr, 0, claimData), challenges, "P42_NO_BOND_TO_CLAIM");
  });

  // ---------------------------------------------------------------------------
  // Risk 5 — bond-leverage "5000x self-deal": commit a cheap bond against an
  // ~empty pool, then fund the pool large and try to capture it. End-to-end:
  // the big payout is unreachable until the solver tops the bond up to
  // alpha * current entitlement (the finalize-time bond gate), which caps the
  // leverage at 1/alpha and puts real capital at risk.
  // ---------------------------------------------------------------------------

  it("risk5: empty-pool bond leverage self-deal is blocked until the bond covers alpha*entitlement", async function () {
    const fixture = await deployFixture({ alphaBps: 200n, feeBps: 0, minBond: ethers.parseEther("0.01") });
    const { alice, pool, ledger, submissions } = fixture;

    // 1) The paid-phase bond is sized against the immutable cap even while the
    // current pool is empty.
    const cid = "bafy-leverage";
    const salt = "leverage-salt";
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](cid, alice.address, DA_HASH, salt);
    const capBond = await submissions.requiredPostingBondNow();
    assert.equal(capBond, ethers.parseEther("2"));
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: capBond });
    await submissions.connect(alice).reveal(1, cid, 0, 1, salt, "0x");

    // 2) Pool is now funded large. Naive payout would be 100 ETH on a 0.01 ETH
    //    bond — a 10,000x self-deal.
    await pool.fund({ value: ethers.parseEther("100") });
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);

    const requiredAtFinalize = await submissions.requiredPostingBondForPool(ethers.parseEther("100"));
    assert.equal(requiredAtFinalize, ethers.parseEther("2")); // alpha (2%) * 100 ETH
    assert.equal(capBond, requiredAtFinalize);

    // 3) Finalize succeeds only because cap-sized collateral was posted up front.
    await submissions.connect(alice).finalize(1, PERMANENCE_HASH);
    assert.equal((await submissions.submissions(1)).status, 4n);

    // The payout is honest, not leveraged: capture (100 ETH) required a 2 ETH
    // bond at risk, i.e. leverage is capped at 1/alpha = 50x, not 10,000x.
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), ethers.parseEther("100"));
    const bondPosted = capBond;
    assert.equal(ethers.parseEther("100") / bondPosted, 50n);
  });

  // ---------------------------------------------------------------------------
  // Risk 6 — mempool front-run / rebind. A watcher who copies the opaque commit
  // hash (and the public commit-time DA hash) cannot reveal or rebind the
  // victim's submission: reveal is gated to the committing solver, and the
  // solver address is bound into the commit preimage, so the copied hash is
  // unrevealable by anyone else even if the CID and salt later leak.
  // ---------------------------------------------------------------------------

  it("risk6: a mempool watcher cannot reveal or rebind another solver's copied commitment", async function () {
    const fixture = await deployFixture();
    const { alice, bob, submissions } = fixture;
    const cid = "bafy-front-run-target";
    const salt = "front-run-salt";

    // Alice commits. The commitment hash and DA hash are now public on-chain.
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](cid, alice.address, DA_HASH, salt);
    const bond = await submissions.requiredPostingBondNow();
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: bond });
    const aliceId = await submissions.submissionCount();

    // (a) Bob cannot reveal Alice's submission — reveal is solver-gated.
    await expectCustomError(
      submissions.connect(bob).reveal(aliceId, cid, 123, 7, salt, "0x"),
      submissions,
      "P42_NOT_SOLVER"
    );

    // (b) Bob copies the identical opaque hash into his own commitment. Even
    //     after the CID and salt leak, his reveal fails: the preimage binds the
    //     solver address, so keccak(preimage(cid, bob, da, salt)) != commitment.
    await submissions.connect(bob).commit(commitment, DA_HASH, { value: bond });
    const bobId = await submissions.submissionCount();
    await expectCustomError(
      submissions.connect(bob).reveal(bobId, cid, 123, 7, salt, "0x"),
      submissions,
      "P42_BAD_COMMITMENT_REVEAL"
    );

    // The rightful solver still reveals normally.
    await submissions.connect(alice).reveal(aliceId, cid, 123, 7, salt, "0x");
    assert.equal((await submissions.submissions(aliceId)).status, 2n);
    assert.equal((await submissions.submissions(aliceId)).solver, alice.address);
  });

  // ---------------------------------------------------------------------------
  // F3 — self-challenge slot burn. A fraudulent solver challenges their own
  // submission to consume the one-shot challenge slot, immunizing the fraud
  // for the whole window, then expires it with both bonds refunded.
  // F5 — stale challengeEndsAt. After the solver prevails in a challenge the
  // submission returned to Revealed with the pre-challenge deadline, letting
  // expireRevealed instantly strip the honest winner's bond.
  // ---------------------------------------------------------------------------

  // Commit + reveal as alice via plain signer transactions.
  async function revealAsAlice(fixture) {
    const { alice, submissions } = fixture;
    return commitReveal(fixture, {
      solverAddr: alice.address,
      sendCommit: async (commitment, bond) => {
        await submissions.connect(alice).commit(commitment, DA_HASH, { value: bond });
      },
      sendReveal: async (id, cid, improvement, salt) => {
        await submissions.connect(alice).reveal(id, cid, 0, improvement, salt, "0x");
      },
    });
  }

  it("f3: a solver cannot self-challenge to burn the challenge slot, but an honest challenger still can", async function () {
    const fixture = await deployFixture();
    const { alice, bob, submissions, challenges } = fixture;
    const { submissionId } = await revealAsAlice(fixture);
    const required = await challenges.requiredChallengeBond(await submissions.disputedEntitlementWei(submissionId));
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("sock-puppet self challenge"));

    // (a) The solver's own challenge is rejected outright.
    await expectCustomError(
      openChallenge(fixture, alice, submissionId, reasonHash, { value: required }),
      challenges,
      "P42_SELF_CHALLENGE"
    );
    assert.equal((await submissions.submissions(submissionId)).status, 2n); // still Revealed

    // (b) A third-party challenger is unaffected by the guard.
    await openChallenge(fixture, bob, submissionId, reasonHash, { value: required });
    assert.equal((await submissions.submissions(submissionId)).status, 3n); // Challenged
    assert.equal((await challenges.challenges(submissionId)).challenger, bob.address);
  });

  it("f3: an expired frivolous challenge frees the slot for a fresh challenger in the re-armed window", async function () {
    const fixture = await deployFixture();
    const { alice, bob, submissions, challenges } = fixture;
    const carol = (await ethers.getSigners())[5];
    const { submissionId } = await revealAsAlice(fixture);
    const required = await challenges.requiredChallengeBond(await submissions.disputedEntitlementWei(submissionId));

    // Bob posts a frivolous challenge and lets it time out unresolved.
    await openChallenge(
      fixture,
      bob,
      submissionId,
      ethers.keccak256(ethers.toUtf8Bytes("frivolous")),
      { value: required },
    );
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await expireChallenge(fixture, submissionId);

    // The slot is cleared, bob's bond is refunded, the submission is Revealed
    // again — and it is NOT immunized: the solver still cannot self-challenge...
    assert.equal((await challenges.challenges(submissionId)).challenger, ethers.ZeroAddress);
    assert.equal(await challenges.claimableBondWei(bob.address), required);
    assert.equal((await submissions.submissions(submissionId)).status, 2n);
    await expectCustomError(
      openChallenge(fixture, alice, submissionId, ethers.keccak256(ethers.toUtf8Bytes("re-burn")), {
        value: required,
      }),
      challenges,
      "P42_SELF_CHALLENGE"
    );

    // ...and a different party can post a fresh challenge in the re-armed window.
    await openChallenge(
      fixture,
      carol,
      submissionId,
      ethers.keccak256(ethers.toUtf8Bytes("real fraud evidence")),
      { value: required },
    );
    assert.equal((await submissions.submissions(submissionId)).status, 3n);
    assert.equal((await challenges.challenges(submissionId)).challenger, carol.address);
  });

  it("f5: a solver-favorable resolution re-arms the window so expireRevealed cannot instantly strip the bond", async function () {
    const fixture = await deployFixture();
    const { alice, bob, resolver, ledger, submissions, challenges } = fixture;
    const { submissionId } = await revealAsAlice(fixture);
    const required = await challenges.requiredChallengeBond(await submissions.disputedEntitlementWei(submissionId));
    await openChallenge(
      fixture,
      bob,
      submissionId,
      ethers.keccak256(ethers.toUtf8Bytes("meritless dispute")),
      { value: required },
    );

    // Resolve near the active dispute deadline. The full fraud window carries
    // finality beyond the original reveal deadline, while remaining inside the
    // submission's immutable cumulative settlement horizon.
    await increaseTime(CHALLENGE_WINDOW_SECONDS - RESOLVER_FRAUD_WINDOW_SECONDS / 2n);
    await resolveChallenge(fixture, resolver, submissionId,
      false,
      ethers.keccak256(ethers.toUtf8Bytes("solver prevails transcript")),
      "ar://solver-prevails",
      ethers.keccak256(ethers.toUtf8Bytes("solver prevails verdict")),
      { value: await challenges.resolverDecisionBondWei() }
    );
    assert.equal((await submissions.submissions(submissionId)).status, 3n); // decision pending
    await increaseTime(RESOLVER_FRAUD_WINDOW_SECONDS + 1n);
    await finalizeChallengeResolution(fixture, submissionId);
    assert.equal((await submissions.submissions(submissionId)).status, 2n); // Revealed again

    // With the stale deadline, expireRevealed would strip the honest winner's
    // bond right now. The re-armed window blocks it (and gates finalize).
    await expectCustomError(submissions.expireRevealed(submissionId), submissions, "P42_PERMANENCE_GRACE_OPEN");
    await expectCustomError(
      submissions.connect(alice).finalize(submissionId, PERMANENCE_HASH),
      submissions,
      "P42_CHALLENGE_WINDOW_OPEN"
    );

    // After the fresh window the solver finalizes and recovers their bond.
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    await submissions.connect(alice).finalize(submissionId, PERMANENCE_HASH);
    assert.equal((await submissions.submissions(submissionId)).status, 4n); // Finalized
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await submissions.releaseFinalizedBond(submissionId);
    assert.equal(await submissions.claimableBondWei(alice.address), await submissions.requiredPostingBondNow());
  });
});
