import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

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

async function deployFixture() {
  const [owner, treasury, solver, outsider] = await ethers.getSigners();
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
  const submissions = await Submissions.deploy(
    await pool.getAddress(),
    await ledger.getAddress(),
    owner.address,
    treasury.address,
    200,
    MIN_BOND,
    CHALLENGE_WINDOW,
    false,
    0,
    SEED_SCORE,
    1
  );
  await submissions.waitForDeployment();
  await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());

  return { owner, treasury, solver, outsider, ledger, submissions };
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
  await submissions.connect(solver).reveal(submissionId, cid, 1n, 1n, salt, "0x");
  return submissionId;
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
  });

  it("unblocks a matured settlement without reopening new submissions", async function () {
    const fixture = await deployFixture();
    const { owner, solver, outsider, ledger, submissions } = fixture;
    const submissionId = await commitAndReveal(fixture);
    await submissions.connect(owner).setPausedNewActions(true);
    await submissions.connect(owner).setPausedAll(true);

    await increaseTime((await submissions.PAUSED_ALL_RECOVERY_DELAY()) + 1_000n);
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
    await ledger.connect(owner).close();
    assert.equal(await ledger.closed(), true);
  });
});
