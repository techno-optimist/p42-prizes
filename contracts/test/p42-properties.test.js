import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const CHALLENGE_WINDOW_SECONDS = 72n * 60n * 60n;
// Absolute-score frontier seed (F1). Each scenario submission claims
// claimed = previousBest - improvementAtoms, so the on-chain marginal credit
// equals the scenario's improvementAtoms and the seeded credit bookkeeping
// below stays exact.
const SEED_SCORE_ATOMS = 1_000_000n;
const PERMANENCE_HASH = ethers.keccak256(ethers.toUtf8Bytes("property permanence receipt"));
const FUNDING_CAP = ethers.parseEther("100");
const MIN_COMPETITION_SECONDS = 30n * 24n * 60n * 60n;
const BOARD_SET_DIGEST = ethers.id("p42-properties-board-set");
const RELEASE_BINDING_DIGEST = ethers.id("p42-properties-release-binding");
const FUNDING_ROLES = [ethers.id("production-launch-authority"), ethers.id("independent-security-authority"), ethers.id("governance-authority")];
const FUNDING_TYPES = { FundingAuthorization: [
  { name: "role", type: "bytes32" }, { name: "boardSetDigest", type: "bytes32" },
  { name: "releaseBindingDigest", type: "bytes32" }, { name: "authorizationDigest", type: "bytes32" },
  { name: "expiresAt", type: "uint64" }, { name: "nonce", type: "uint256" },
] };

function fundingAuthorizationConfig(authorities) {
  return { boardSetDigest: BOARD_SET_DIGEST, releaseBindingDigest: RELEASE_BINDING_DIGEST,
    productionLaunchAuthority: authorities[0].address, independentSecurityAuthority: authorities[1].address,
    governanceAuthority: authorities[2].address };
}

async function authorizeFunding(submissions, treasury, authorities, digest, expiresAt) {
  const nonce = await submissions.fundingAuthorizationNonce();
  const { chainId } = await ethers.provider.getNetwork();
  const domain = { name: "P42SubmissionManager", version: "2", chainId, verifyingContract: await submissions.getAddress() };
  const common = { boardSetDigest: BOARD_SET_DIGEST, releaseBindingDigest: RELEASE_BINDING_DIGEST,
    authorizationDigest: digest, expiresAt, nonce };
  const signatures = await Promise.all(authorities.slice(0, 3).map((authority, index) =>
    authority.signTypedData(domain, FUNDING_TYPES, { ...common, role: FUNDING_ROLES[index] })));
  return submissions.connect(treasury).authorizeFunding(digest, expiresAt, nonce, signatures);
}

async function nextEarliestClose() {
  const latest = await ethers.provider.getBlock("latest");
  return BigInt(latest.timestamp) + MIN_COMPETITION_SECONDS + 1_000n;
}

async function nextCloseBy() {
  const latest = await ethers.provider.getBlock("latest");
  return BigInt(latest.timestamp) + 181n * 24n * 60n * 60n;
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

function rng(seed) {
  let state = BigInt(seed);
  return () => {
    state = (state * 1103515245n + 12345n) % 2147483648n;
    return state;
  };
}

function scenarioFromSeed(seed) {
  const next = rng(seed);
  const submissionCount = 3 + Number(next() % 4n);
  const submissions = [];
  for (let index = 0; index < submissionCount; index += 1) {
    submissions.push({
      solverIndex: Number(next() % 5n),
      improvementAtoms: 1n + next() % 29n,
      donationBeforeFinalizeWei: index === 0 ? 2000n + (next() % 5000n) : next() % 400n
    });
  }
  return {
    seed,
    feeBps: [0, 50, 125, 250][seed % 4],
    alphaBps: [100, 500, 2_000][seed % 3],
    initialPoolWei: seed === 1 ? 0n : 100n + (next() % 10_000n),
    finalDonationWei: next() % 3000n,
    submissions
  };
}

async function deployFixture({ alphaBps = 200n, minBond = 1n, feeBps = 0 } = {}) {
  const [owner, treasury, resolver, productionLaunch, independentSecurity, governance, ...participants] = await ethers.getSigners();
  const authorities = [productionLaunch, independentSecurity, governance];
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
  const submissions = await Submissions.deploy({
    pool: await pool.getAddress(), ledger: await ledger.getAddress(), owner: owner.address,
    treasury: treasury.address, alphaBps, minPostingBondWei: minBond,
    challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS, onchainDa: false, maxSolutionBytes: 0,
    seedScoreAtoms: SEED_SCORE_ATOMS, minImprovementAtoms: 1n,
  }, fundingAuthorizationConfig(authorities));
  await submissions.waitForDeployment();
  await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());

  // OPEN-WITNESS-PHASE wiring: arm funding up front so the property scenarios
  // run in the PAID phase (credit bookkeeping unchanged) and can fund the pool.
  await pool.connect(owner).setSubmissionManager(await submissions.getAddress());
  const Registry = await ethers.getContractFactory("P42ProblemRegistry");
  const registry = await Registry.deploy(owner.address);
  await registry.waitForDeployment();
  await registry.register({
    specHash: ethers.id("properties-spec"),
    verifierSourceHash: ethers.id("properties-source"),
    verifierImageHash: ethers.id("properties-image"),
    admissionMatrixHash: ethers.id("properties-matrix"),
    metadataURI: "ipfs://properties-fixture",
    pool: await pool.getAddress(),
    ledger: await ledger.getAddress(),
    submissionManager: await submissions.getAddress(),
    challengeManager: owner.address,
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
  await authorizeFunding(submissions, treasury, authorities, "0x" + "42".repeat(32), 2n ** 64n - 1n);
  await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
  await pool.connect(owner).setAcceptingFunds(true);
  await increaseTime(MIN_COMPETITION_SECONDS + 1_001n);

  return { owner, treasury, resolver, participants, pool, ledger, submissions, vault };
}

async function submitAndFinalize(fixture, solver, scenarioSeed, index, claimedScoreAtoms, improvementAtoms, donationBeforeFinalizeWei) {
  const { pool, ledger, submissions } = fixture;
  const solutionCid = `sha256:property-${scenarioSeed}-${index}`;
  const salt = `salt-${scenarioSeed}-${index}`;
  const commitDaHash = ethers.keccak256(ethers.toUtf8Bytes(`da:${scenarioSeed}:${index}`));
  const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
    solutionCid,
    solver.address,
    commitDaHash,
    salt
  );
  const postingBond = await submissions.requiredPostingBondNow();

  await submissions.connect(solver).commit(commitment, commitDaHash, { value: postingBond });
  const submissionId = await submissions.submissionCount();
  await submissions.connect(solver).reveal(submissionId, solutionCid, claimedScoreAtoms, improvementAtoms, salt, "0x");

  if (donationBeforeFinalizeWei > 0n) {
    await pool.fund({ value: donationBeforeFinalizeWei });
  }
  await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);

  const entitlement = await ledger.provisionalEntitlement(solver.address, improvementAtoms);
  const requiredAtFinalize = await submissions.requiredPostingBondForPool(entitlement);
  const posted = (await submissions.submissions(submissionId)).bondWei;
  let undercovered = false;
  if (posted < requiredAtFinalize) {
    undercovered = true;
    await expectCustomError(
      submissions.connect(solver).finalize(submissionId, PERMANENCE_HASH),
      submissions,
      "P42_BOND_UNDERCOVERS_ENTITLEMENT"
    );
    await submissions.connect(solver).topUpBond(submissionId, { value: requiredAtFinalize - posted });
  }

  assert.equal(await submissions.bondCoversEntitlement(submissionId, entitlement), true);
  await submissions.connect(solver).finalize(submissionId, PERMANENCE_HASH);
  assert.equal((await submissions.submissions(submissionId)).status, 4n);
  return undercovered;
}

describe("P42 contract property checks", function () {
  it("preserves final-denominator payouts under seeded funding and submission sequences", async function () {
    let undercoveredCases = 0;
    for (let seed = 1; seed <= 8; seed += 1) {
      const scenario = scenarioFromSeed(seed);
      const fixture = await deployFixture({
        alphaBps: BigInt(scenario.alphaBps),
        minBond: 1n,
        feeBps: scenario.feeBps
      });
      const { participants, pool, ledger, submissions } = fixture;
      if (scenario.initialPoolWei > 0n) {
        await pool.fund({ value: scenario.initialPoolWei });
      }

      const expectedCredits = new Map();
      // Track the descending absolute-score frontier: each submission claims
      // exactly improvementAtoms below the current best, so its finalized
      // marginal credit equals improvementAtoms (F1).
      let frontierScoreAtoms = SEED_SCORE_ATOMS;
      for (const [index, submission] of scenario.submissions.entries()) {
        const solver = participants[submission.solverIndex];
        const claimedScoreAtoms = frontierScoreAtoms - submission.improvementAtoms;
        const undercovered = await submitAndFinalize(
          fixture,
          solver,
          seed,
          index,
          claimedScoreAtoms,
          submission.improvementAtoms,
          submission.donationBeforeFinalizeWei
        );
        frontierScoreAtoms = claimedScoreAtoms;
        if (undercovered) undercoveredCases += 1;
        expectedCredits.set(
          solver.address,
          (expectedCredits.get(solver.address) ?? 0n) + submission.improvementAtoms
        );
      }

      if (scenario.finalDonationWei > 0n) {
        await pool.fund({ value: scenario.finalDonationWei });
      }
      assert.equal(await submissions.openSubmissionCount(), 0n);
      await advanceToEffectiveClose(ledger);
      await ledger.connect(fixture.owner).close();

      const closedPoolBalance = await ledger.closedPoolBalance();
      const totalCredit = [...expectedCredits.values()].reduce((sum, atoms) => sum + atoms, 0n);
      assert.equal(await ledger.totalCreditAtoms(), totalCredit);

      let expectedTotalClaimed = 0n;
      let expectedTotalFee = 0n;
      for (const [solverAddress, creditAtoms] of expectedCredits.entries()) {
        const expected = closedPoolBalance * creditAtoms / totalCredit;
        const fee = expected * BigInt(scenario.feeBps) / 10_000n;
        assert.equal(await ledger.creditAtomsOf(solverAddress), creditAtoms);
        assert.equal(await ledger.finalEntitlement(solverAddress), expected);
        assert.equal(await ledger.claimable(solverAddress), expected);

        const solver = participants.find((participant) => participant.address === solverAddress);
        await pool.connect(solver).claim();
        expectedTotalClaimed += expected - fee;
        expectedTotalFee += fee;
        assert.equal(await pool.totalClaimed(), expectedTotalClaimed);
        assert.equal(await pool.totalFeeAccrued(), expectedTotalFee);
        assert.equal(await ledger.claimedWeiOf(solverAddress), expected);
        await expectCustomError(pool.connect(solver).claim(), pool, "P42_NOTHING_TO_CLAIM");
      }

      const dust = closedPoolBalance - (await ledger.totalGrossClaimed());
      assert.equal(dust >= 0n, true);
      assert.equal(dust < BigInt(expectedCredits.size), true);
    }
    assert.equal(undercoveredCases, 0);
  });

  it("keeps sybil-split payout less than or equal to equivalent combined credit", async function () {
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const [owner, treasury, combined, splitA, splitB, honestA, honestB] = await ethers.getSigners();

    async function entitlements(credits) {
      const pool = await Pool.deploy(owner.address, FUNDING_CAP);
      await pool.waitForDeployment();
      const ledger = await Ledger.deploy(
        await pool.getAddress(), owner.address, treasury.address, 0,
        await nextEarliestClose(), await nextCloseBy()
      );
      await ledger.waitForDeployment();
      await pool.connect(owner).setLedger(await ledger.getAddress());
      // This helper exercises ledger arithmetic only (credits are recorded
      // directly by the owner), so satisfy the pool's armed-funding gate with
      // the pre-armed mock submission manager.
      const Mock = await ethers.getContractFactory("MockFundingArmed");
      const mock = await Mock.deploy(true);
      await mock.waitForDeployment();
      await ledger.connect(owner).setCreditRecorder(await mock.getAddress());
      await pool.connect(owner).setSubmissionManager(await mock.getAddress());
      const Registry = await ethers.getContractFactory("P42ProblemRegistry");
      const registry = await Registry.deploy(owner.address);
      await registry.waitForDeployment();
      await registry.register({
        specHash: ethers.id("ledger-spec"),
        verifierSourceHash: ethers.id("ledger-source"),
        verifierImageHash: ethers.id("ledger-image"),
        admissionMatrixHash: ethers.id("ledger-matrix"),
        metadataURI: "ipfs://ledger-fixture",
        pool: await pool.getAddress(),
        ledger: await ledger.getAddress(),
        submissionManager: await mock.getAddress(),
        challengeManager: owner.address,
        challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS,
        minImprovementAtoms: 1n,
      });
      await registry.freeze(1);
      await pool.connect(owner).setRegistry(await registry.getAddress(), 1);
      const Vault = await ethers.getContractFactory("P42RolloverVault");
      const vault = await Vault.deploy(await registry.getAddress(), owner.address);
      await vault.waitForDeployment();
      await ledger.connect(owner).setRolloverDestination(await vault.getAddress());
      await pool.connect(owner).setAcceptingFunds(true);
      await pool.fund({ value: 10_003n });
      for (const [solver, atoms] of credits) {
        await mock.recordCredit(await ledger.getAddress(), solver.address, atoms);
      }
      await increaseTime(MIN_COMPETITION_SECONDS + 1_001n);
      await advanceToEffectiveClose(ledger);
      await ledger.connect(owner).close();
      const result = new Map();
      for (const [solver] of credits) {
        result.set(solver.address, await ledger.finalEntitlement(solver.address));
      }
      return result;
    }

    for (let seed = 10; seed < 30; seed += 1) {
      const next = rng(seed);
      const left = 1n + next() % 97n;
      const right = 1n + next() % 97n;
      const honestLeft = 1n + next() % 97n;
      const honestRight = 1n + next() % 97n;

      const split = await entitlements([
        [splitA, left],
        [splitB, right],
        [honestA, honestLeft],
        [honestB, honestRight]
      ]);
      const oneIdentity = await entitlements([
        [combined, left + right],
        [honestA, honestLeft],
        [honestB, honestRight]
      ]);

      const splitTotal = split.get(splitA.address) + split.get(splitB.address);
      assert.equal(splitTotal <= oneIdentity.get(combined.address), true);
    }
  });

  it("caps the protocol fee at the advertised 2.5% (250 bps)", async function () {
    const Pool = await ethers.getContractFactory("P42BountyPool");
    const Ledger = await ethers.getContractFactory("P42PayoutLedger");
    const [owner, treasury] = await ethers.getSigners();
    const pool = await Pool.deploy(owner.address, FUNDING_CAP);
    await pool.waitForDeployment();

    // 250 bps (2.5%) is the maximum accepted fee.
    const capped = await Ledger.deploy(
      await pool.getAddress(), owner.address, treasury.address, 250,
      await nextEarliestClose(), await nextCloseBy()
    );
    await capped.waitForDeployment();
    assert.equal(await capped.feeBps(), 250n);
    assert.equal(await capped.MAX_FEE_BPS(), 250n);

    // Anything above the cap is rejected at construction.
    await expectCustomError(
      Ledger.deploy(
        await pool.getAddress(), owner.address, treasury.address, 251,
        await nextEarliestClose(), await nextCloseBy()
      ),
      Ledger,
      "P42_FEE_TOO_HIGH"
    );
  });
});
