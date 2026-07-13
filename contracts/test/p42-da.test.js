import assert from "node:assert/strict";
import { increaseTime as advanceTimeBy } from "../test-support/time.js";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

// On-chain-at-reveal data availability.
//
// Replaces the (unfundable, unverifiable) Arweave permanence dependency: for
// on-chain-DA problems the solver posts the raw solution bytes in the reveal
// tx, and the contract enforces sha256(bytes) == the commit-bound anchor
// (commitDaHash) — a consensus-enforced proof the exact committed bytes were
// made available for the challenge window. Large-certificate problems
// (autoconvolution) deploy with onchainDa=false and keep bytes off-chain,
// gated by the same anchor.

const CHALLENGE_WINDOW = 90n;
const ALPHA_BPS = 200n;
const MIN_BOND = ethers.parseEther("0.0001");
const ONE_MIB = 1024 * 1024;
// Absolute-score frontier seed (F1): fixtures reveal claimed score 0, which
// strictly beats this.
const SEED_SCORE_ATOMS = 1_000_000n;
const MIN_IMPROVEMENT_ATOMS = 1n;
const FUNDING_CAP = ethers.parseEther("1");
const CLOSE_BY_TIMESTAMP = 4_102_444_800n;
const MIN_COMPETITION_SECONDS = 30n * 24n * 60n * 60n;

async function nextEarliestClose() {
  const latest = await ethers.provider.getBlock("latest");
  return BigInt(latest.timestamp) + MIN_COMPETITION_SECONDS + 1_000n;
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
  for (const nested of [value.cause, value.error, value.info?.error]) {
    const data = findErrorData(nested);
    if (data !== undefined) return data;
  }
  return undefined;
}

async function increaseTime(seconds) {
  await advanceTimeBy(ethers.provider, seconds);
}

// Deploy the full pool/ledger/submission stack for a given DA config.
async function deploy(onchainDa, maxSolutionBytes) {
  const [owner, treasury, solver, other] = await ethers.getSigners();

  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address, FUNDING_CAP);
  await pool.waitForDeployment();

  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasury.address, 0,
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
    ALPHA_BPS,
    MIN_BOND,
    CHALLENGE_WINDOW,
    onchainDa,
    maxSolutionBytes,
    SEED_SCORE_ATOMS,
    MIN_IMPROVEMENT_ATOMS
  );
  await submissions.waitForDeployment();
  await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());

  // OPEN-WITNESS-PHASE wiring: arm funding up front so these DA fixtures run
  // in the PAID phase and the pool accepts deposits.
  await pool.connect(owner).setSubmissionManager(await submissions.getAddress());
  const Registry = await ethers.getContractFactory("P42ProblemRegistry");
  const registry = await Registry.deploy(owner.address);
  await registry.waitForDeployment();
  await registry.register({
    specHash: ethers.id("da-spec"),
    verifierSourceHash: ethers.id("da-source"),
    verifierImageHash: ethers.id("da-image"),
    admissionMatrixHash: ethers.id("da-matrix"),
    metadataURI: "ipfs://da-fixture",
    pool: await pool.getAddress(),
    ledger: await ledger.getAddress(),
    submissionManager: await submissions.getAddress(),
    challengeManager: owner.address,
    challengeWindowSeconds: CHALLENGE_WINDOW,
    minImprovementAtoms: MIN_IMPROVEMENT_ATOMS,
  });
  await registry.freeze(1);
  await pool.connect(owner).setRegistry(await registry.getAddress(), 1);
  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), owner.address);
  await vault.waitForDeployment();
  await ledger.connect(owner).setRolloverDestination(await vault.getAddress());
  await increaseTime(CHALLENGE_WINDOW + 1n);
  await submissions.connect(treasury).authorizeFunding("0x" + "42".repeat(32), 2n ** 64n - 1n);
  await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
  await pool.connect(owner).setAcceptingFunds(true);

  return { owner, treasury, solver, other, pool, ledger, submissions };
}

// Build a commit whose DA anchor is sha256(solutionBytes) — mirrors the agent:
// cid = "sha256:<hex>", commitDaHash = 0x<hex> (the same digest as bytes32).
async function makeCommit(submissions, solver, solutionBytes, salt) {
  const digest = ethers.sha256(solutionBytes); // 0x-prefixed 32-byte hex
  const cid = "sha256:" + digest.slice(2);
  const commitDaHash = digest; // bytes32 anchor == the sha256 of the bytes
  const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
    cid,
    solver.address,
    commitDaHash,
    salt
  );
  return { cid, commitDaHash, commitment, digest };
}

async function commitReveal(fixture, solutionBytes, salt, improvement, revealBytes) {
  const { solver, submissions } = fixture;
  const { cid, commitDaHash, commitment } = await makeCommit(submissions, solver, solutionBytes, salt);
  const bond = await submissions.requiredPostingBondNow();
  await submissions.connect(solver).commit(commitment, commitDaHash, { value: bond });
  const id = await submissions.submissionCount();
  const revealTx = submissions.connect(solver).reveal(id, cid, 0, improvement, salt, revealBytes);
  return { id, cid, commitDaHash, revealTx };
}

describe("P42 on-chain-at-reveal data availability", function () {
  describe("configuration", function () {
    it("rejects on-chain DA with a zero cap", async function () {
      const { submissions } = await deploy(false, 0); // deploy something to get a factory-bound instance
      const Submissions = await ethers.getContractFactory("P42SubmissionManager");
      const [owner, treasury] = await ethers.getSigners();
      const Pool = await ethers.getContractFactory("P42BountyPool");
      const pool = await Pool.deploy(owner.address, FUNDING_CAP);
      const Ledger = await ethers.getContractFactory("P42PayoutLedger");
      const ledger = await Ledger.deploy(
        await pool.getAddress(), owner.address, treasury.address, 0,
        await nextEarliestClose(), CLOSE_BY_TIMESTAMP
      );
      await expectCustomError(
        Submissions.deploy(
          await pool.getAddress(), await ledger.getAddress(), owner.address, treasury.address,
          ALPHA_BPS, MIN_BOND, CHALLENGE_WINDOW, true, 0, SEED_SCORE_ATOMS, MIN_IMPROVEMENT_ATOMS
        ),
        submissions,
        "P42_BAD_ONCHAIN_DA_CONFIG"
      );
    });

    it("rejects on-chain DA with a cap above the 1 MiB calldata ceiling", async function () {
      const { submissions } = await deploy(false, 0);
      const Submissions = await ethers.getContractFactory("P42SubmissionManager");
      const [owner, treasury] = await ethers.getSigners();
      const Pool = await ethers.getContractFactory("P42BountyPool");
      const pool = await Pool.deploy(owner.address, FUNDING_CAP);
      const Ledger = await ethers.getContractFactory("P42PayoutLedger");
      const ledger = await Ledger.deploy(
        await pool.getAddress(), owner.address, treasury.address, 0,
        await nextEarliestClose(), CLOSE_BY_TIMESTAMP
      );
      await expectCustomError(
        Submissions.deploy(
          await pool.getAddress(), await ledger.getAddress(), owner.address, treasury.address,
          ALPHA_BPS, MIN_BOND, CHALLENGE_WINDOW, true, ONE_MIB + 1, SEED_SCORE_ATOMS, MIN_IMPROVEMENT_ATOMS
        ),
        submissions,
        "P42_BAD_ONCHAIN_DA_CONFIG"
      );
    });

    it("allows off-chain DA with a zero cap", async function () {
      const { submissions } = await deploy(false, 0);
      assert.equal(await submissions.onchainDa(), false);
      assert.equal(await submissions.maxSolutionBytes(), 0n);
    });

    it("exposes the 1 MiB on-chain ceiling constant", async function () {
      const { submissions } = await deploy(true, 4096);
      assert.equal(await submissions.MAX_ONCHAIN_SOLUTION_BYTES(), BigInt(ONE_MIB));
    });
  });

  describe("on-chain mode: bytes ride the reveal tx and bind to the anchor", function () {
    it("accepts a reveal whose bytes hash to the anchor, recoverable from calldata", async function () {
      const fixture = await deploy(true, 4096);
      await fixture.pool.fund({ value: ethers.parseEther("0.01") });
      const solutionBytes = ethers.toUtf8Bytes(JSON.stringify({ witness: [1, -1, 1, -1], claim: "1/1" }));
      const { id, commitDaHash, revealTx } = await commitReveal(fixture, solutionBytes, "s-ok", 1, solutionBytes);
      const receipt = await (await revealTx).wait();

      // Bytes are recoverable from the reveal tx calldata and re-hash to the anchor.
      const fullTx = await ethers.provider.getTransaction(receipt.hash);
      const decoded = fixture.submissions.interface.parseTransaction({ data: fullTx.data, value: fullTx.value });
      assert.equal(ethers.sha256(decoded.args.solution), commitDaHash);

      const sub = await fixture.submissions.submissions(id);
      assert.equal(sub.status, 2n); // Revealed
    });

    it("emits the on-chain solution byte length in Revealed", async function () {
      const fixture = await deploy(true, 4096);
      await fixture.pool.fund({ value: ethers.parseEther("0.01") });
      const solutionBytes = ethers.toUtf8Bytes("abcdefghij"); // 10 bytes
      const { revealTx } = await commitReveal(fixture, solutionBytes, "s-len", 1, solutionBytes);
      const receipt = await (await revealTx).wait();
      const evt = receipt.logs
        .map((l) => { try { return fixture.submissions.interface.parseLog(l); } catch { return null; } })
        .find((p) => p && p.name === "Revealed");
      assert.ok(evt, "Revealed event present");
      assert.equal(evt.args.solutionBytesLength, 10n);
    });

    it("rejects reveal bytes that do not hash to the anchor (fraud caught on-chain)", async function () {
      const fixture = await deploy(true, 4096);
      await fixture.pool.fund({ value: ethers.parseEther("0.01") });
      const committedBytes = ethers.toUtf8Bytes("the real solution");
      const differentBytes = ethers.toUtf8Bytes("a DIFFERENT solution");
      const { revealTx } = await commitReveal(fixture, committedBytes, "s-mismatch", 1, differentBytes);
      await expectCustomError(revealTx, fixture.submissions, "P42_SOLUTION_HASH_MISMATCH");
    });

    it("rejects an empty reveal in on-chain mode", async function () {
      const fixture = await deploy(true, 4096);
      await fixture.pool.fund({ value: ethers.parseEther("0.01") });
      const solutionBytes = ethers.toUtf8Bytes("solution");
      const { revealTx } = await commitReveal(fixture, solutionBytes, "s-empty", 1, "0x");
      await expectCustomError(revealTx, fixture.submissions, "P42_EMPTY_SOLUTION_BYTES");
    });

    it("rejects reveal bytes above the per-problem cap (calldata-bomb guard)", async function () {
      const cap = 64;
      const fixture = await deploy(true, cap);
      await fixture.pool.fund({ value: ethers.parseEther("0.01") });
      const solutionBytes = ethers.toUtf8Bytes("x".repeat(cap + 1)); // 65 > 64
      const { revealTx } = await commitReveal(fixture, solutionBytes, "s-big", 1, solutionBytes);
      await expectCustomError(revealTx, fixture.submissions, "P42_SOLUTION_TOO_LARGE");
    });

    it("finalizes with a zero permanence hash (Arweave receipt no longer required)", async function () {
      const fixture = await deploy(true, 4096);
      await fixture.pool.fund({ value: ethers.parseEther("0.01") });
      const solutionBytes = ethers.toUtf8Bytes("winning solution");
      const { id, revealTx } = await commitReveal(fixture, solutionBytes, "s-final", 1, solutionBytes);
      await (await revealTx).wait();
      await increaseTime(CHALLENGE_WINDOW + 1n);
      await fixture.submissions.connect(fixture.solver).finalize(id, ethers.ZeroHash);
      const sub = await fixture.submissions.submissions(id);
      assert.equal(sub.status, 4n); // Finalized
      assert.equal(sub.permanenceHash, ethers.ZeroHash);
    });
  });

  describe("off-chain mode: bytes stay off-chain, anchor still binds", function () {
    it("accepts an empty reveal; the anchor still binds the off-chain bytes", async function () {
      const fixture = await deploy(false, 0);
      await fixture.pool.fund({ value: ethers.parseEther("0.01") });
      const solutionBytes = ethers.toUtf8Bytes("a big autoconvolution certificate");
      const { id, commitDaHash, revealTx } = await commitReveal(fixture, solutionBytes, "s-off", 1, "0x");
      await (await revealTx).wait();
      const sub = await fixture.submissions.submissions(id);
      assert.equal(sub.status, 2n); // Revealed
      assert.equal(sub.commitDaHash, commitDaHash); // fetchers re-check sha256(off-chain bytes) == this
    });

    it("rejects non-empty calldata bytes in off-chain mode (no bloat)", async function () {
      const fixture = await deploy(false, 0);
      await fixture.pool.fund({ value: ethers.parseEther("0.01") });
      const solutionBytes = ethers.toUtf8Bytes("should have gone off-chain");
      const { revealTx } = await commitReveal(fixture, solutionBytes, "s-off2", 1, solutionBytes);
      await expectCustomError(revealTx, fixture.submissions, "P42_UNEXPECTED_ONCHAIN_BYTES");
    });
  });
});
