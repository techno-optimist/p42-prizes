import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { deployActiveObjectiveProofCapability } from "../test-support/objective-proof-capability.js";

const { ethers } = await network.create();

const CHALLENGE_WINDOW = 72n * 60n * 60n;
const MIN_COMPETITION_SECONDS = 30n * 24n * 60n * 60n;
const MIN_CLOSE_DELAY_SECONDS = 180n * 24n * 60n * 60n;
const FUNDING_CAP = ethers.parseEther("100");
const MIN_BOND = ethers.parseEther("0.01");
const SEED_SCORE = 1_000_000n;
const DA_HASH = ethers.keccak256(ethers.toUtf8Bytes("pause-liveness-da"));

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

async function deployFixture() {
  const [owner, treasury, solver, outsider, productionLaunch, independentSecurity, governance] = await ethers.getSigners();
  const latest = await ethers.provider.getBlock("latest");
  const earliestClose = BigInt(latest.timestamp) + MIN_COMPETITION_SECONDS + 1_000n;
  const closeBy = BigInt(latest.timestamp) + MIN_CLOSE_DELAY_SECONDS + 1_000n;

  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address, FUNDING_CAP);
  await pool.waitForDeployment();

  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasury.address, 0, earliestClose, closeBy
  );
  await ledger.waitForDeployment();
  await pool.connect(owner).setLedger(await ledger.getAddress());

  const Submissions = await ethers.getContractFactory("P42SubmissionManager");
  const capability = await deployActiveObjectiveProofCapability(ethers);
  const submissions = await Submissions.deploy({
    pool: await pool.getAddress(), ledger: await ledger.getAddress(), owner: owner.address,
    treasury: treasury.address, alphaBps: 200, minPostingBondWei: MIN_BOND,
    challengeWindowSeconds: CHALLENGE_WINDOW, onchainDa: false, maxSolutionBytes: 0,
    seedScoreAtoms: SEED_SCORE, minImprovementAtoms: 1,
  }, {
    boardSetDigest: ethers.id("pause-liveness-board-set"),
    releaseBindingDigest: ethers.id("pause-liveness-release"),
    objectiveVerifier: capability.objectiveVerifier,
    objectiveVerifierCodehash: capability.objectiveVerifierCodehash,
    productionLaunchAuthority: productionLaunch.address,
    independentSecurityAuthority: independentSecurity.address,
    governanceAuthority: governance.address,
  });
  await submissions.waitForDeployment();
  await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());
  const Registry = await ethers.getContractFactory("MockProblemRegistry");
  const registry = await Registry.deploy();
  await registry.waitForDeployment();
  await registry.setProblem(1, await pool.getAddress(), true);
  await pool.connect(owner).setRegistry(await registry.getAddress(), 1);
  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), owner.address);
  await vault.waitForDeployment();
  await ledger.connect(owner).setRolloverDestination(await vault.getAddress());

  return { owner, treasury, solver, outsider, pool, ledger, submissions, vault };
}

async function commitAndReveal(fixture) {
  const { submissions, solver } = fixture;
  const cid = "bafy-pause-liveness";
  const salt = "pause-liveness-salt";
  const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
    cid, solver.address, DA_HASH, salt
  );
  await submissions.connect(solver).commit(commitment, DA_HASH, { value: MIN_BOND });
  const submissionId = await submissions.submissionCount();
  await submissions.connect(solver).reveal(submissionId, cid, 1n, SEED_SCORE - 1n, salt, "0x");
  return submissionId;
}

async function commitOnly(fixture, cid, salt) {
  const { submissions, solver } = fixture;
  const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
    cid, solver.address, DA_HASH, salt
  );
  await submissions.connect(solver).commit(commitment, DA_HASH, { value: MIN_BOND });
  return { submissionId: await submissions.submissionCount(), cid, salt };
}

async function revealCommitted(fixture, committed) {
  const { submissions, solver } = fixture;
  await submissions.connect(solver).reveal(
    committed.submissionId, committed.cid, 1n, SEED_SCORE - 1n, committed.salt, "0x"
  );
}

describe("P42 pausedAll settlement liveness", function () {
  it("keeps the recovery deadline fixed and rejects premature permissionless recovery", async function () {
    const { owner, outsider, submissions } = await deployFixture();
    await submissions.connect(owner).setPausedAll(true);
    const pausedAt = await submissions.pausedAllAt();

    await increaseTime(24n * 60n * 60n);
    await submissions.connect(owner).setPausedAll(true);
    assert.equal(await submissions.pausedAllAt(), pausedAt);

    await expectCustomError(
      submissions.connect(outsider).recoverPausedAll(),
      submissions,
      "P42_PAUSED_ALL_RECOVERY_OPEN"
    );
    await expectCustomError(
      submissions.connect(outsider).setPausedAll(false),
      submissions,
      "P42_NOT_OWNER"
    );

    const delay = await submissions.PAUSED_ALL_RECOVERY_DELAY();
    await increaseTime(delay - 24n * 60n * 60n);
    const tx = await submissions.connect(outsider).recoverPausedAll();
    const receipt = await tx.wait();
    const block = await ethers.provider.getBlock(receipt.blockNumber);
    assert.equal(await submissions.pausedAll(), false);
    assert.equal(await submissions.expiryGraceUntil(), BigInt(block.timestamp) + CHALLENGE_WINDOW);

    const graceUntil = await submissions.expiryGraceUntil();
    await increaseTime(1n);
    await expectCustomError(
      submissions.connect(owner).setPausedAll(false),
      submissions,
      "P42_NOT_PAUSED_ALL"
    );
    assert.equal(await submissions.expiryGraceUntil(), graceUntil);

    await expectCustomError(
      submissions.connect(owner).setPausedAll(true),
      submissions,
      "P42_PAUSED_ALL_REARM_OPEN"
    );
    await advanceTo(graceUntil);
    await submissions.connect(owner).setPausedAll(true);
    const nextPausedAt = await submissions.pausedAllAt();
    assert.ok(nextPausedAt > pausedAt);
    await expectCustomError(
      submissions.connect(outsider).recoverPausedAll(),
      submissions,
      "P42_PAUSED_ALL_RECOVERY_OPEN"
    );
  });

  it("tolls a live commit and preserves its bond through reveal and finalize", async function () {
    const fixture = await deployFixture();
    const { owner, treasury, solver, outsider, submissions } = fixture;
    const committed = await commitOnly(fixture, "bafy-tolled-commit", "tolled-commit");
    const committedAt = (await submissions.submissions(committed.submissionId)).committedAt;
    const activeDeadline = (await submissions.committedActiveAtOf(committed.submissionId)) + CHALLENGE_WINDOW;
    assert.equal(await ethers.provider.getBalance(await submissions.getAddress()), MIN_BOND);

    await submissions.connect(owner).setPausedAll(true);
    const activeAtPause = await submissions.activeTimestamp();
    await increaseTime(await submissions.PAUSED_ALL_RECOVERY_DELAY());
    assert.equal(await submissions.activeTimestamp(), activeAtPause);
    await submissions.connect(outsider).recoverPausedAll();

    const latest = await ethers.provider.getBlock("latest");
    assert.ok(BigInt(latest.timestamp) > committedAt + CHALLENGE_WINDOW);
    assert.ok(activeDeadline - (await submissions.activeTimestamp()) > CHALLENGE_WINDOW - 10n);

    await revealCommitted(fixture, committed);
    assert.equal((await submissions.submissions(committed.submissionId)).bondWei, MIN_BOND);
    assert.equal(await submissions.claimableBondWei(treasury.address), 0n);

    await increaseTime(CHALLENGE_WINDOW + 1n);
    await submissions.connect(solver).finalize(committed.submissionId, ethers.ZeroHash);
    assert.equal(await submissions.claimableBondWei(solver.address), MIN_BOND);
    assert.equal(await submissions.claimableBondWei(treasury.address), 0n);
    assert.equal(await ethers.provider.getBalance(await submissions.getAddress()), MIN_BOND);
    assert.equal(
      await submissions.claimableBondWei(solver.address)
        + await submissions.claimableBondWei(treasury.address),
      await ethers.provider.getBalance(await submissions.getAddress())
    );

    await submissions.connect(solver).claimBond();
    assert.equal(await ethers.provider.getBalance(await submissions.getAddress()), 0n);
  });

  it("does not resurrect a commit that expired before the full pause", async function () {
    const fixture = await deployFixture();
    const { owner, treasury, outsider, submissions } = fixture;
    const committed = await commitOnly(fixture, "bafy-prepause-expired", "prepause-expired");

    await increaseTime(CHALLENGE_WINDOW);
    await submissions.connect(owner).setPausedAll(true);
    await increaseTime(await submissions.PAUSED_ALL_RECOVERY_DELAY());
    await submissions.connect(outsider).recoverPausedAll();

    await expectCustomError(revealCommitted(fixture, committed), submissions, "P42_COMMIT_EXPIRED");
    assert.ok((await submissions.activeTimestamp()) >=
      (await submissions.committedActiveAtOf(committed.submissionId)) + CHALLENGE_WINDOW);
    assert.equal(await ethers.provider.getBalance(await submissions.getAddress()), MIN_BOND);
    assert.equal(await submissions.claimableBondWei(treasury.address), 0n);

    await expectCustomError(
      submissions.connect(outsider).expireCommitted(committed.submissionId),
      submissions,
      "P42_REVEAL_WINDOW_OPEN"
    );
    await advanceTo(await submissions.expiryGraceUntil());
    await submissions.connect(outsider).expireCommitted(committed.submissionId);
    assert.equal(await submissions.claimableBondWei(treasury.address), MIN_BOND);
    assert.equal(await ethers.provider.getBalance(await submissions.getAddress()), MIN_BOND);
  });

  it("requires a usable interval between full-pause episodes, including same-block cycles", async function () {
    const { owner, outsider, submissions } = await deployFixture();
    await submissions.connect(owner).setPausedAll(true);

    for (let cycle = 0; cycle < 2; cycle += 1) {
      const pausedAt = await submissions.pausedAllAt();
      await submissions.connect(owner).setPausedAll(false);
      const rearmAt = await submissions.expiryGraceUntil();

      await expectCustomError(
        submissions.connect(owner).setPausedAll(true),
        submissions,
        "P42_PAUSED_ALL_REARM_OPEN"
      );
      await advanceTo(rearmAt + 1n);
      await submissions.connect(owner).setPausedAll(true);
      assert.ok((await submissions.pausedAllAt()) > pausedAt);
    }

    await submissions.connect(owner).setPausedAll(false);
    await submissions.connect(owner).setPausedNewActions(true);
    assert.equal(await submissions.pausedNewActions(), true);
    const commitment = ethers.keccak256(ethers.toUtf8Bytes("incident-brake"));
    await expectCustomError(
      submissions.connect(outsider).commit(commitment, DA_HASH, { value: MIN_BOND }),
      submissions,
      "P42_PAUSED_NEW_ACTIONS"
    );
  });

  it("unblocks a matured settlement without reopening new submissions", async function () {
    const fixture = await deployFixture();
    const { owner, solver, outsider, ledger, submissions } = fixture;
    const submissionId = await commitAndReveal(fixture);
    await submissions.connect(owner).setPausedNewActions(true);
    await submissions.connect(owner).setPausedAll(true);

    await advanceTo(await ledger.closeByTimestamp());
    await expectCustomError(ledger.close(), ledger, "P42_OPEN_SUBMISSIONS");

    await submissions.connect(outsider).recoverPausedAll();
    const newCommitment = ethers.keccak256(ethers.toUtf8Bytes("must-stay-paused"));
    await expectCustomError(
      submissions.connect(outsider).commit(newCommitment, DA_HASH, { value: MIN_BOND }),
      submissions,
      "P42_PAUSED_NEW_ACTIONS"
    );

    await submissions.connect(solver).finalize(submissionId, ethers.ZeroHash);
    assert.equal(await submissions.openSubmissionCount(), 0n);
    await increaseTime((await submissions.CREDIT_FINALIZE_RECOVERY_DELAY()) + 1n);
    await ledger.connect(owner).close();
    assert.equal(await ledger.closed(), true);
  });
});
