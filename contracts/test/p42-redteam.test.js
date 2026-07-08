import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const CHALLENGE_WINDOW_SECONDS = 72n * 60n * 60n;
const RESOLVER_FRAUD_WINDOW_SECONDS = 24n * 60n * 60n;
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

async function deployFixture({
  alphaBps = 200n,
  minBond = ethers.parseEther("0.01"),
  feeBps = 0,
  activateRecorder = true,
} = {}) {
  const [owner, treasury, resolver, alice, bob] = await ethers.getSigners();
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
  if (activateRecorder) {
    await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());
  }

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

  const Attacker = await ethers.getContractFactory("ReentrantClaimer");

  return { owner, treasury, resolver, alice, bob, pool, ledger, submissions, challenges, Attacker, minBond };
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
  // ---------------------------------------------------------------------------
  // Risk 12 — reentrancy against every ETH-outflow path.
  // A concrete malicious receiver (ReentrantClaimer) re-enters the caller mid
  // payout. Each path must (a) block the re-entrant call and (b) pay the
  // attacker its single honest entitlement exactly once — no double-withdraw.
  // ---------------------------------------------------------------------------

  it("risk12: reentrant receiver cannot double-withdraw from P42BountyPool.claim()", async function () {
    const fixture = await deployFixture({ feeBps: 0, activateRecorder: false });
    const { owner, pool, ledger, Attacker } = fixture;
    const attacker = await Attacker.deploy();
    await attacker.waitForDeployment();
    const attackerAddr = await attacker.getAddress();

    await pool.fund({ value: ethers.parseEther("5") });
    // Attacker is the sole credited solver, so its honest entitlement is the
    // whole distributable pool. A working reentrancy would drain twice.
    await ledger.connect(owner).recordCredit(attackerAddr, 1);
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
    const { submissions, Attacker, minBond } = fixture;
    const attacker = await Attacker.deploy();
    await attacker.waitForDeployment();
    const attackerAddr = await attacker.getAddress();
    const subAddr = await submissions.getAddress();

    // The attacker contract is the solver: commit/reveal/finalize as itself so
    // its posting bond becomes claimable, then re-enter the bond payout.
    const { submissionId } = await commitReveal(fixture, {
      solverAddr: attackerAddr,
      sendCommit: async (commitment, bond) => {
        const data = submissions.interface.encodeFunctionData("commit", [commitment, DA_HASH]);
        await attacker.exec(subAddr, bond, data, { value: bond });
      },
      sendReveal: async (id, cid, improvement, salt) => {
        const data = submissions.interface.encodeFunctionData("reveal", [id, cid, 0, improvement, salt]);
        await attacker.exec(subAddr, 0, data);
      },
    });

    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    const finalizeData = submissions.interface.encodeFunctionData("finalize", [submissionId, PERMANENCE_HASH]);
    await attacker.exec(subAddr, 0, finalizeData);
    assert.equal(await submissions.claimableBondWei(attackerAddr), minBond);

    const claimData = submissions.interface.encodeFunctionData("claimBond");
    await attacker.arm(subAddr, claimData);
    const subBefore = await ethers.provider.getBalance(subAddr);
    await attacker.exec(subAddr, 0, claimData);

    assert.equal(await attacker.reentryCallCount(), 1n);
    assert.equal(await attacker.reentrySucceeded(), false);
    assert.equal(await attacker.totalReceivedWei(), minBond);
    assert.equal(subBefore - (await ethers.provider.getBalance(subAddr)), minBond);
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
        await submissions.connect(alice).reveal(id, cid, 0, improvement, salt);
      },
    });

    // The attacker contract is the winning challenger, so its counter-bond
    // becomes claimable on the challenge manager.
    const required = await challenges.requiredChallengeBond(await submissions.disputedEntitlementWei(submissionId));
    const reasonHash = ethers.keccak256(ethers.toUtf8Bytes("attacker challenge"));
    const challengeData = challenges.interface.encodeFunctionData("challenge", [submissionId, reasonHash]);
    await attacker.exec(chalAddr, required, challengeData, { value: required });

    await challenges.connect(resolver).resolve(
      submissionId,
      true,
      ethers.keccak256(ethers.toUtf8Bytes("challenger wins transcript")),
      "ar://redteam-challenger-wins",
      ethers.keccak256(ethers.toUtf8Bytes("challenger wins verdict")),
      { value: await challenges.resolverDecisionBondWei() }
    );
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

    // 1) Commit cheaply against a nearly empty pool.
    const cid = "bafy-leverage";
    const salt = "leverage-salt";
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](cid, alice.address, DA_HASH, salt);
    const cheapBond = await submissions.requiredPostingBondNow();
    assert.equal(cheapBond, ethers.parseEther("0.01")); // just the floor
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: cheapBond });
    await submissions.connect(alice).reveal(1, cid, 0, 1, salt);

    // 2) Pool is now funded large. Naive payout would be 100 ETH on a 0.01 ETH
    //    bond — a 10,000x self-deal.
    await pool.fund({ value: ethers.parseEther("100") });
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);

    const requiredAtFinalize = await submissions.requiredPostingBondForPool(ethers.parseEther("100"));
    assert.equal(requiredAtFinalize, ethers.parseEther("2")); // alpha (2%) * 100 ETH
    assert.equal(cheapBond < requiredAtFinalize, true);

    // 3) Finalize is gated: the cheap bond cannot claim the large pool.
    await expectCustomError(
      submissions.connect(alice).finalize(1, PERMANENCE_HASH),
      submissions,
      "P42_BOND_UNDERCOVERS_ENTITLEMENT"
    );

    // 4) The only way through is to risk real capital (top up to >= alpha*entitlement).
    await submissions.connect(alice).topUpBond(1, { value: requiredAtFinalize - cheapBond });
    await submissions.connect(alice).finalize(1, PERMANENCE_HASH);
    assert.equal((await submissions.submissions(1)).status, 4n);

    // The payout is honest, not leveraged: capture (100 ETH) required a 2 ETH
    // bond at risk, i.e. leverage is capped at 1/alpha = 50x, not 10,000x.
    await ledger.close();
    await pool.connect(alice).claim();
    assert.equal(await ledger.claimedWeiOf(alice.address), ethers.parseEther("100"));
    const bondPosted = requiredAtFinalize; // 2 ETH
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
    const { alice, bob, submissions, minBond } = fixture;
    const cid = "bafy-front-run-target";
    const salt = "front-run-salt";

    // Alice commits. The commitment hash and DA hash are now public on-chain.
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](cid, alice.address, DA_HASH, salt);
    await submissions.connect(alice).commit(commitment, DA_HASH, { value: minBond });
    const aliceId = await submissions.submissionCount();

    // (a) Bob cannot reveal Alice's submission — reveal is solver-gated.
    await expectCustomError(
      submissions.connect(bob).reveal(aliceId, cid, 123, 7, salt),
      submissions,
      "P42_NOT_SOLVER"
    );

    // (b) Bob copies the identical opaque hash into his own commitment. Even
    //     after the CID and salt leak, his reveal fails: the preimage binds the
    //     solver address, so keccak(preimage(cid, bob, da, salt)) != commitment.
    await submissions.connect(bob).commit(commitment, DA_HASH, { value: minBond });
    const bobId = await submissions.submissionCount();
    await expectCustomError(
      submissions.connect(bob).reveal(bobId, cid, 123, 7, salt),
      submissions,
      "P42_BAD_COMMITMENT_REVEAL"
    );

    // The rightful solver still reveals normally.
    await submissions.connect(alice).reveal(aliceId, cid, 123, 7, salt);
    assert.equal((await submissions.submissions(aliceId)).status, 2n);
    assert.equal((await submissions.submissions(aliceId)).solver, alice.address);
  });
});
