import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { deployActiveObjectiveProofCapability } from "../test-support/objective-proof-capability.js";

const { ethers } = await network.create();
const CHALLENGE_WINDOW_SECONDS = 72n * 60n * 60n;
const RESOLVER_FRAUD_WINDOW_SECONDS = 24n * 60n * 60n;
const FUNDING_CAP = ethers.parseEther("100");
const MIN_COMPETITION_SECONDS = 30n * 24n * 60n * 60n;
const BOARD_SET_DIGEST = ethers.id("p42-gate1-board-set");
const RELEASE_BINDING_DIGEST = ethers.id("p42-gate1-release-binding");
const FUNDING_ROLES = [ethers.id("production-launch-authority"), ethers.id("independent-security-authority"), ethers.id("governance-authority")];
const FUNDING_TYPES = { FundingAuthorization: [
  { name: "role", type: "bytes32" }, { name: "boardSetDigest", type: "bytes32" },
  { name: "releaseBindingDigest", type: "bytes32" }, { name: "authorizationDigest", type: "bytes32" },
  { name: "expiresAt", type: "uint64" }, { name: "nonce", type: "uint256" },
] };

function fundingAuthorizationConfig(authorities, capability) {
  return { boardSetDigest: BOARD_SET_DIGEST, releaseBindingDigest: RELEASE_BINDING_DIGEST,
    objectiveVerifier: capability.objectiveVerifier, objectiveVerifierCodehash: capability.objectiveVerifierCodehash,
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
      return parsed;
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

describe("P42 Gate 1 contract scaffold", function () {
  async function deployFixture({
    alphaBps = 200n,
    minBond = ethers.parseEther("0.01"),
    feeBps = 0,
    activateRecorder = true,
    mockRecorder = false,
  } = {}) {
    const [owner, treasury, resolver, alice, bob, challenger, ...authorities] = await ethers.getSigners();
    const capability = await deployActiveObjectiveProofCapability(ethers);
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
    }, fundingAuthorizationConfig(authorities, capability));
    await submissions.waitForDeployment();
    let fundingManager = submissions;
    let creditRecorder = submissions;
    if (mockRecorder) {
      const Mock = await ethers.getContractFactory("MockFundingArmed");
      const mock = await Mock.deploy(true);
      await mock.waitForDeployment();
      fundingManager = mock;
      creditRecorder = mock;
      await ledger.connect(owner).setCreditRecorder(await mock.getAddress());
    } else if (activateRecorder) {
      await ledger.connect(owner).setCreditRecorder(await submissions.getAddress());
    }

    // OPEN-WITNESS-PHASE wiring is completed after the required frozen
    // registry binding below.
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
      submissionManager: await fundingManager.getAddress(),
      challengeManager: await challenges.getAddress(),
      challengeWindowSeconds: CHALLENGE_WINDOW_SECONDS,
      minImprovementAtoms: 1n,
    });
    await fundingRegistry.freeze(1);
    await pool.connect(owner).setRegistry(await fundingRegistry.getAddress(), 1);
    const Vault = await ethers.getContractFactory("P42RolloverVault");
    const vault = await Vault.deploy(await fundingRegistry.getAddress(), owner.address);
    await vault.waitForDeployment();
    await ledger.connect(owner).setRolloverDestination(await vault.getAddress());
    await increaseTime(CHALLENGE_WINDOW_SECONDS + 1n);
    if (activateRecorder && !mockRecorder) {
      await authorizeFunding(submissions, treasury, authorities, "0x" + "42".repeat(32), 2n ** 64n - 1n);
      await submissions.connect(owner).armFunding("0x" + "42".repeat(32));
    }
    if (activateRecorder || mockRecorder) await pool.connect(owner).setAcceptingFunds(true);
    await increaseTime(MIN_COMPETITION_SECONDS + 1_001n);

    return {
      owner,
      treasury,
      resolver,
      alice,
      bob,
      challenger,
      pool,
      ledger,
      submissions,
      challenges,
      registry,
      vault,
      creditRecorder,
      minBond,
    };
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
    const improvementAtoms = overrides.improvementAtoms
      ?? SEED_SCORE_ATOMS - BigInt(claimedScoreAtoms);
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
    return fixture.challenges.connect(fixture.resolver).slashResolverBond(
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
    await submissions.connect(alice).reveal(1, solutionCid, 100, SEED_SCORE_ATOMS - 100n, salt, "0x");
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
      submissions.connect(bob).reveal(1, solutionCid, 123, SEED_SCORE_ATOMS - 123n, salt, "0x"),
      submissions,
      "P42_NOT_SOLVER"
    );
    await expectCustomError(
      submissions.connect(alice).reveal(1, solutionCid, 123, SEED_SCORE_ATOMS - 123n, "wrong-salt", "0x"),
      submissions,
      "P42_BAD_COMMITMENT_REVEAL"
    );
    assert.equal(await submissions.MAX_SOLUTION_CID_BYTES(), 512n);
    await expectCustomError(
      submissions.connect(alice).reveal(1, "c".repeat(513), 123, 7, salt, "0x"),
      submissions,
      "P42_SOLUTION_CID_TOO_LARGE"
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

    const canonicalImprovement = SEED_SCORE_ATOMS - 123n;
    await submissions.connect(alice).reveal(1, solutionCid, 123, canonicalImprovement, salt, "0x");
    const revealed = await submissions.submissions(1);
    assert.equal(revealed.solutionCid, solutionCid);
    assert.equal(revealed.claimedScoreAtoms, 123n);
    assert.equal(revealed.improvementAtoms, canonicalImprovement);
    assert.equal(revealed.status, 2n);
    assert.equal(revealed.challengeEndsAt - revealed.revealedAt, CHALLENGE_WINDOW_SECONDS);
  });

  it("requires the exact immutable-seed display delta and preserves reveal-hash conformance", async function () {
    const { alice, submissions } = await deployFixture();
    const solutionCid = "bafy-canonical-improvement";
    const salt = "canonical-improvement-salt";
    const claimedScoreAtoms = 123n;
    const exactImprovementAtoms = SEED_SCORE_ATOMS - claimedScoreAtoms;
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
      solutionCid,
      alice.address,
      DA_HASH,
      salt
    );
    await submissions.connect(alice).commit(commitment, DA_HASH, {
      value: await submissions.requiredPostingBondNow(),
    });

    for (const mutatedImprovementAtoms of [0n, exactImprovementAtoms + 1n, ethers.MaxUint256]) {
      const parsed = await expectCustomError(
        submissions.connect(alice).reveal(
          1,
          solutionCid,
          claimedScoreAtoms,
          mutatedImprovementAtoms,
          salt,
          "0x"
        ),
        submissions,
        "P42_IMPROVEMENT_ATOMS_MISMATCH"
      );
      assert.equal(parsed.args.expected, exactImprovementAtoms);
      assert.equal(parsed.args.actual, mutatedImprovementAtoms);
    }

    await submissions.connect(alice).reveal(
      1,
      solutionCid,
      claimedScoreAtoms,
      exactImprovementAtoms,
      salt,
      "0x"
    );
    const revealed = await submissions.submissions(1);
    const { chainId } = await ethers.provider.getNetwork();
    const expectedRevealHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "uint256", "address", "bytes32", "bytes32", "bytes32", "int256", "uint256", "uint64"],
      [
        await submissions.getAddress(),
        chainId,
        1n,
        alice.address,
        commitment,
        DA_HASH,
        ethers.keccak256(ethers.toUtf8Bytes(solutionCid)),
        claimedScoreAtoms,
        exactImprovementAtoms,
        revealed.challengeEndsAt,
      ]
    ));
    assert.equal(await submissions.revealInstanceHashOf(1), expectedRevealHash);
  });

  it("allows an unverified claimed score when its seed-relative display delta is honest", async function () {
    const fixture = await deployFixture();
    const claimedScoreAtoms = 42n;
    const { submissionId } = await commitAndReveal(fixture, { claimedScoreAtoms });
    const submission = await fixture.submissions.submissions(submissionId);

    assert.equal(submission.claimedScoreAtoms, claimedScoreAtoms);
    assert.equal(submission.improvementAtoms, SEED_SCORE_ATOMS - claimedScoreAtoms);
    assert.equal(submission.status, 2n);
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
    await submissions.connect(alice).reveal(1, solutionCid, 1000, SEED_SCORE_ATOMS - 1000n, salt, "0x");
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

    await advanceToEffectiveClose(ledger);
    await expectCustomError(ledger.close(), ledger, "P42_OPEN_SUBMISSIONS");
    await submissions.expireCommitted(1);
    const expired = await submissions.submissions(1);
    assert.equal(expired.status, 5n);
    assert.equal(await submissions.openSubmissionCount(), 0n);
    assert.equal(await submissions.claimableBondWei(treasury.address), bond);
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

    await advanceToEffectiveClose(ledger);
    await expectCustomError(ledger.close(), ledger, "P42_OPEN_SUBMISSIONS");
    await submissions.expireRevealed(submissionId);
    const expired = await submissions.submissions(submissionId);
    assert.equal(expired.status, 5n);
    assert.equal(await submissions.openSubmissionCount(), 0n);
    assert.equal(await submissions.claimableBondWei(treasury.address), bond);
    await ledger.close();
    assert.equal(await ledger.closed(), true);
  });

  it("closes the commit gate at the funding deadline while preserving lifecycle cleanup", async function () {
    const fixture = await deployFixture();
    const { alice, bob, ledger, submissions } = fixture;
    const deadline = await ledger.fundingDeadline();
    const bond = await submissions.requiredPostingBondNow();
    const first = await submissions["computeCommitment(string,address,bytes32,string)"](
      "bafy-deadline-front-run", alice.address, DA_HASH, "deadline"
    );
    const recycled = await submissions["computeCommitment(string,address,bytes32,string)"](
      "bafy-zero-marginal-recycle", bob.address, DA_HASH, "recycle"
    );

    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(deadline)]);
    await submissions.connect(alice).commit(first, DA_HASH, { value: bond });
    assert.equal(await submissions.openSubmissionCount(), 1n);

    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(deadline + 1n)]);
    await ethers.provider.send("evm_mine", []);
    await expectCustomError(
      submissions.connect(bob).commit(recycled, DA_HASH, { value: bond }),
      submissions,
      "P42_SUBMISSION_WINDOW_CLOSED"
    );
    assert.equal(await submissions.submissionCount(), 1n);

    await advanceToEffectiveClose(ledger);
    await expectCustomError(ledger.close(), ledger, "P42_OPEN_SUBMISSIONS");
    await submissions.expireCommitted(1);
    await ledger.connect(bob).close();
    assert.equal(await ledger.closed(), true);
    await expectCustomError(
      submissions.connect(bob).commit(recycled, DA_HASH, { value: bond }),
      submissions,
      "P42_LEDGER_CLOSED"
    );
  });

  it("rolls back atomic finalize-close-claim and leaves a permissionless recovery window", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { owner, alice, pool, ledger, submissions } = fixture;
    await pool.fund({ value: ethers.parseEther("1") });
    const Attacker = await ethers.getContractFactory("AtomicSettlementAttacker");
    const attacker = await Attacker.deploy();
    await attacker.waitForDeployment();
    const cid = "bafy-atomic-settlement-poison";
    const salt = "atomic-settlement-poison";
    const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
      cid, await attacker.getAddress(), DA_HASH, salt
    );
    const bond = await submissions.requiredPostingBondNow();
    await attacker.connect(alice).commit(await submissions.getAddress(), commitment, DA_HASH, { value: bond });
    await attacker.reveal(
      await submissions.getAddress(),
      1,
      cid,
      1,
      SEED_SCORE_ATOMS - 1n,
      salt
    );
    await advanceToEffectiveClose(ledger);

    await expectCustomError(
      attacker.finalizeCloseClaim(
        await submissions.getAddress(), await ledger.getAddress(), await pool.getAddress(), 1
      ),
      ledger,
      "P42_CREDIT_RECOVERY_WINDOW_OPEN"
    );
    assert.equal((await submissions.submissions(1)).status, 2n);
    assert.equal(await ledger.totalCreditAtoms(), 0n);
    assert.equal(await ledger.closed(), false);

    await attacker.finalize(await submissions.getAddress(), 1);
    const recoveryEndsAt = await submissions.creditRecoveryEndsAt();
    assert.equal(recoveryEndsAt > BigInt((await ethers.provider.getBlock("latest")).timestamp), true);
    await submissions.connect(owner).setPausedAll(true);
    await submissions.connect(owner).voidFinalize(1);
    assert.equal(await submissions.creditRecoveryEndsAt(), 0n);
    await submissions.connect(owner).setPausedAll(false);
    await ledger.connect(alice).close();
    assert.equal(await ledger.closed(), true);
    assert.equal(await ledger.totalCreditAtoms(), 0n);
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
    const { alice, bob, pool, ledger, creditRecorder } = await deployFixture({ feeBps: 0, mockRecorder: true });
    await pool.fund({ value: ethers.parseEther("10") });

    await creditRecorder.recordCredit(await ledger.getAddress(), alice.address, 60);
    assert.equal(await ledger.claimable(alice.address), 0n);
    await expectCustomError(pool.connect(alice).claim(), ledger, "P42_NOT_CLOSED");

    await creditRecorder.recordCredit(await ledger.getAddress(), bob.address, 10000);
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
    const { alice, bob, pool, ledger, creditRecorder } = await deployFixture({ feeBps: 0, mockRecorder: true });
    await pool.fund({ value: ethers.parseEther("1") });
    await creditRecorder.recordCredit(await ledger.getAddress(), alice.address, 1);
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    await ledger.setPausedNewActions(true);

    await expectCustomError(
      creditRecorder.recordCredit(await ledger.getAddress(), bob.address, 1),
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
      challenges.connect(resolver).slashResolverBond(
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
    assert.equal(await challenges.MAX_TRANSCRIPT_URI_BYTES(), 512n);
    await expectCustomError(
      resolveChallenge(fixture, resolver, submissionId, true, transcriptHash, "u".repeat(513), verdictHash, {
        value: resolverBond,
      }),
      challenges,
      "P42_TRANSCRIPT_URI_TOO_LARGE"
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
    await expectCustomError(
      challenges.connect(owner).slashResolverBond(
        submissionId,
        await challenges.challengeInstanceHashOf(submissionId),
        slashProof,
      ),
      challenges,
      "P42_NOT_RESOLVER",
    );
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
    const { submissionId } = await commitAndReveal(fixture);
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

  it("rejects an unadjudicated submission on resolver timeout so close can proceed safely (M1)", async function () {
    const fixture = await deployFixture({ feeBps: 0 });
    const { alice, challenger, pool, ledger, submissions, challenges } = fixture;
    await pool.fund({ value: ethers.parseEther("1") });
    const { submissionId } = await commitAndReveal(fixture);
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

    // At closeBy an unresolved challenge still blocks the permissionless close.
    await advanceToEffectiveClose(ledger);
    await expectCustomError(ledger.close(), ledger, "P42_OPEN_SUBMISSIONS");

    // The resolver never posts a decision; anyone can time the challenge out.
    await expireChallenge(fixture, alice, submissionId);
    // The challenge record is cleared and the challenger recovers its bond.
    const expired = await challenges.challenges(submissionId);
    assert.equal(expired.challenger, ethers.ZeroAddress);
    // No adjudication occurred, so the challenger's posted bond is returned.
    assert.equal(await challenges.claimableBondWei(challenger.address), required);

    // No adjudication means no credit: the submission is rejected while the
    // solver recovers its own posting bond. Resolver outage cannot accept fraud.
    assert.equal((await submissions.submissions(submissionId)).status, 5n);
    assert.equal(
      await submissions.claimableBondWei(alice.address),
      (await submissions.submissions(submissionId)).requiredBondWei,
    );
    assert.equal(await submissions.openSubmissionCount(), 0n);
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
    const { submissionId, bond } = await commitAndReveal(fixture);
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

  it("pays the protocol fee only with a successful solver claim (L1)", async function () {
    const { alice, treasury, pool, ledger, creditRecorder } = await deployFixture({ feeBps: 250, mockRecorder: true });
    await pool.fund({ value: ethers.parseEther("10") });
    await creditRecorder.recordCredit(await ledger.getAddress(), alice.address, 1);

    await expectCustomError(ledger.sweepFee(), ledger, "P42_FEE_CLAIM_ONLY");

    await advanceToEffectiveClose(ledger);
    await ledger.close();
    const poolBefore = await ethers.provider.getBalance(await pool.getAddress());
    await pool.connect(alice).claim();
    const fee = ethers.parseEther("10") * 250n / 10_000n;
    assert.equal(await pool.accruedFeeBalance(), fee);
    const treasuryBefore = await ethers.provider.getBalance(treasury.address);
    await pool.claimFees();
    assert.equal((await ethers.provider.getBalance(treasury.address)) - treasuryBefore, fee);
    assert.equal(poolBefore - (await ethers.provider.getBalance(await pool.getAddress())), ethers.parseEther("10"));
    assert.equal(await ledger.claimedWeiOf(alice.address), ethers.parseEther("10"));
    assert.equal(await pool.totalFeePaid(), fee);
    assert.equal(await pool.funded(), 0n);
  });

  it("rejects deposits once the ledger has closed (L2)", async function () {
    const { alice, pool, ledger } = await deployFixture({ feeBps: 0, mockRecorder: true });
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
    const fixture = await deployFixture({ feeBps: 0, mockRecorder: true });
    const { alice, pool, ledger, registry, creditRecorder } = fixture;
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
    await creditRecorder.recordCredit(await ledger.getAddress(), alice.address, 1);
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
    const { alice, bob, pool, ledger, creditRecorder } = await deployFixture({ feeBps: 0, mockRecorder: true });
    await pool.fund({ value: ethers.parseEther("10") });
    await creditRecorder.recordCredit(await ledger.getAddress(), alice.address, 60);
    await creditRecorder.recordCredit(await ledger.getAddress(), bob.address, 40);

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

  it("sweeps positive-credit residual only to the rollover vault after the claim deadline (F15)", async function () {
    const { alice, bob, vault, pool, ledger, creditRecorder } = await deployFixture({ feeBps: 0, mockRecorder: true });
    await pool.fund({ value: ethers.parseEther("10") });
    await creditRecorder.recordCredit(await ledger.getAddress(), alice.address, 3);
    await creditRecorder.recordCredit(await ledger.getAddress(), bob.address, 7);

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
    const vaultBefore = await ethers.provider.getBalance(await vault.getAddress());
    // Permissionless: any caller may trigger the sweep.
    await ledger.connect(bob).sweepResidual();
    assert.equal((await ethers.provider.getBalance(await vault.getAddress())) - vaultBefore, residual);
    assert.equal(await pool.funded(), 0n);
    assert.equal(await ledger.residualSwept(), true);
    // Dedicated accounting: the residual never pollutes the fee counter.
    assert.equal(await pool.totalResidualPaid(), residual);
    assert.equal(await pool.totalFeePaid(), 0n);

    // Late claims stay blocked and the sweep is one-shot.
    await expectCustomError(pool.connect(bob).claim(), ledger, "P42_CLAIMS_EXPIRED");
    await expectCustomError(ledger.sweepResidual(), ledger, "P42_ROLLOVER_ALREADY_SWEPT");
  });

  it("keeps zero-credit principal available only to its sponsor (F15 canary edge)", async function () {
    const { pool, ledger } = await deployFixture({ feeBps: 0, mockRecorder: true });
    await pool.fund({ value: ethers.parseEther("1") });
    await advanceToEffectiveClose(ledger);
    await ledger.close();
    assert.equal(await ledger.totalCreditAtoms(), 0n);

    await expectCustomError(ledger.sweepResidual(), ledger, "P42_ROLLOVER_NOT_AVAILABLE");
    await pool.sponsorRefund();
    assert.equal(await pool.funded(), 0n);
    assert.equal(await pool.totalResidualPaid(), 0n);
  });

  it("disables legacy residual and fee sweep surfaces (F15)", async function () {
    const { alice, vault, pool, ledger, creditRecorder } = await deployFixture({ feeBps: 250, mockRecorder: true });
    await pool.fund({ value: ethers.parseEther("10") });
    await creditRecorder.recordCredit(await ledger.getAddress(), alice.address, 1);
    await advanceToEffectiveClose(ledger);
    await ledger.close();

    await expectCustomError(pool.connect(alice).payResidual(alice.address, 1n), pool, "P42_RESIDUAL_DISABLED");
    await expectCustomError(ledger.sweepFee(), ledger, "P42_FEE_CLAIM_ONLY");

    await increaseTime(CLAIM_DEADLINE_SECONDS + 1n);
    const residual = await pool.funded();
    const vaultBefore = await ethers.provider.getBalance(await vault.getAddress());
    await ledger.sweepResidual();
    assert.equal((await ethers.provider.getBalance(await vault.getAddress())) - vaultBefore, residual);
    assert.equal(await pool.totalFeePaid(), 0n);
    assert.equal(await pool.totalResidualPaid(), residual);
    assert.equal(await pool.funded(), 0n);
  });
});
