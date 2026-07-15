import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import {
  buildQuorumResolveCallPolicy,
} from "../../agent/resolver.mjs";
import {
  buildResolverQuorumDecisionPacket,
  buildResolverQuorumSignatureArtifact,
  collectResolverQuorumSignatures,
} from "../../agent/resolver-quorum.mjs";
import { challengeManagerEffectiveSalt } from "../scripts/deployment-ceremony-helper.js";

const { ethers } = await network.create();
const CHALLENGE_WINDOW = 72n * 60n * 60n;
const FRAUD_WINDOW = 24n * 60n * 60n;
const MANAGER_COUNT = 10;
const RESOLVER_BOND = ethers.parseEther("0.005");
const CHALLENGE_BOND = ethers.parseEther("0.03");
const DA_HASH = ethers.id("resolver-quorum-da");
const OBJECTIVE_PROGRAM = ethers.id("p42-objective-program-v1");
const SHA = (digit) => `sha256:${digit.repeat(64)}`;
const BOARD_SET_DIGEST = ethers.id("p42-resolver-quorum-board-set");
const RELEASE_BINDING_DIGEST = ethers.id("p42-resolver-quorum-release-binding");

function fundingAuthorizationConfig(authorities) {
  return {
    boardSetDigest: BOARD_SET_DIGEST,
    releaseBindingDigest: RELEASE_BINDING_DIGEST,
    productionLaunchAuthority: authorities[0].address,
    independentSecurityAuthority: authorities[1].address,
    governanceAuthority: authorities[2].address,
  };
}

const DECISION_TYPES = {
  Decision: [
    { name: "chainId", type: "uint256" },
    { name: "adapter", type: "address" },
    { name: "manager", type: "address" },
    { name: "submissionId", type: "uint256" },
    { name: "challengeInstanceHash", type: "bytes32" },
    { name: "challengerWins", type: "bool" },
    { name: "transcriptHash", type: "bytes32" },
    { name: "transcriptURIHash", type: "bytes32" },
    { name: "verdictHash", type: "bytes32" },
    { name: "bondBeneficiary", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "expiry", type: "uint64" },
    { name: "signerEpoch", type: "uint64" },
  ],
};

function findErrorData(value) {
  if (value == null) return undefined;
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

async function latestTimestamp() {
  return BigInt((await ethers.provider.getBlock("latest")).timestamp);
}

async function mineAt(timestamp) {
  await ethers.provider.send("evm_setNextBlockTimestamp", [Number(timestamp)]);
  await ethers.provider.send("evm_mine", []);
}

async function setNextTimestamp(timestamp) {
  await ethers.provider.send("evm_setNextBlockTimestamp", [Number(timestamp)]);
}

function objectivePackageHash(registry, problemId, binding) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ["string", "uint256", "address", "uint256", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      "P42_OBJECTIVE_PACKAGE_V2", 31337n, registry, BigInt(problemId), binding.specHash,
      binding.verifierSourceHash, binding.verifierImageHash, binding.admissionMatrixHash,
      binding.objectiveGuestElfSha256, binding.objectiveProgramVKey,
    ],
  ));
}

async function deployFixture(options = {}) {
  const [owner, treasury, signerA, signerB, signerC, solver, challenger, relayer, beneficiary, outsider] =
    await ethers.getSigners();

  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(owner.address, ethers.parseEther("100"));
  await pool.waitForDeployment();
  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const now = await latestTimestamp();
  const ledger = await Ledger.deploy(
    await pool.getAddress(), owner.address, treasury.address, 0, now + 31n * 24n * 60n * 60n,
    now + 181n * 24n * 60n * 60n,
  );
  await ledger.waitForDeployment();
  await pool.connect(owner).setLedger(await ledger.getAddress());
  const Registry = await ethers.getContractFactory("P42ProblemRegistry");
  const registry = await Registry.deploy(owner.address);
  await registry.waitForDeployment();

  const Submissions = await ethers.getContractFactory("P42SubmissionManager");
  const SubmissionFactory = await ethers.getContractFactory("P42SubmissionManagerFactory");
  const submissionFactory = await SubmissionFactory.deploy();
  await submissionFactory.waitForDeployment();
  const submissionManagers = [];
  const fundingAuthorities = [signerA, signerB, signerC];
  for (let i = 0; i < MANAGER_COUNT; i += 1) {
    const tx = await submissionFactory.deploySubmissionManager(
      ethers.id(`submission-manager-${i}`),
      {
        deployment: {
          pool: await pool.getAddress(), ledger: await ledger.getAddress(), owner: owner.address,
          treasury: treasury.address, alphaBps: 200, minPostingBondWei: ethers.parseEther("0.01"),
          challengeWindowSeconds: CHALLENGE_WINDOW, onchainDa: false, maxSolutionBytes: 0,
          seedScoreAtoms: 1_000_000, minImprovementAtoms: 1,
        },
        fundingAuthorization: fundingAuthorizationConfig(fundingAuthorities),
      },
      Submissions.bytecode,
    );
    const receipt = await tx.wait();
    const deployed = receipt.logs.map((log) => {
      try { return submissionFactory.interface.parseLog(log); } catch { return null; }
    }).find((log) => log?.name === "CanonicalSubmissionManagerDeployed");
    assert.ok(deployed);
    submissionManagers.push(new ethers.Contract(deployed.args.submissionManager, Submissions.interface, owner));
  }
  const submissions = submissionManagers[0];

  const Quorum = await ethers.getContractFactory("P42ResolverQuorum");
  const Factory = await ethers.getContractFactory("P42ChallengeManagerFactory");
  const factory = await Factory.deploy();
  await factory.waitForDeployment();
  const Manager = await ethers.getContractFactory("P42ChallengeManager");
  const ObjectiveVerifier = await ethers.getContractFactory("MockObjectiveVerifierGateway");
  const objectiveVerifier = await ObjectiveVerifier.deploy();
  await objectiveVerifier.waitForDeployment();
  const objectiveVerifierCodehash = ethers.keccak256(
    await ethers.provider.getCode(await objectiveVerifier.getAddress()),
  );
  const startNonce = await ethers.provider.getTransactionCount(owner.address);
  const predictedQuorum = ethers.getCreateAddress({ from: owner.address, nonce: startNonce + MANAGER_COUNT * 2 });
  const managers = [];
  const objectiveBindings = [];
  for (let i = 0; i < MANAGER_COUNT; i += 1) {
    const objectiveBinding = {
      specHash: ethers.id(`p42-spec-${i}`),
      verifierSourceHash: ethers.id(`p42-source-${i}`),
      verifierImageHash: ethers.id(`p42-image-${i}`),
      admissionMatrixHash: ethers.id(`p42-admission-${i}`),
      objectiveGuestElfSha256: ethers.sha256(ethers.toUtf8Bytes(`p42-objective-guest-${i}`)),
      objectiveProgramVKey: ethers.id(`p42-objective-program-${i}`),
    };
    objectiveBindings.push(objectiveBinding);
    const tx = await factory.deployManager(
      ethers.id(`resolver-manager-${i}`),
      await submissionFactory.getAddress(),
      {
        owner: owner.address, resolver: predictedQuorum, treasury: treasury.address,
        submissionManager: await submissionManagers[i].getAddress(), challengeWindowSeconds: CHALLENGE_WINDOW,
        betaBps: 500, minCounterBondWei: CHALLENGE_BOND, rerunCostWei: ethers.parseEther("0.01"),
        rerunCostMultiplierBps: 30_000, resolverDecisionBondWei: RESOLVER_BOND,
        resolverFraudWindowSeconds: FRAUD_WINDOW,
        problemRegistry: await registry.getAddress(), problemId: i + 1,
        objectivePackageHash: objectivePackageHash(await registry.getAddress(), i + 1, objectiveBinding),
        objectiveGuestElfSha256: objectiveBinding.objectiveGuestElfSha256,
        objectiveProgramVKey: objectiveBinding.objectiveProgramVKey,
      },
    );
    const receipt = await tx.wait();
    const deployed = receipt.logs.map((log) => {
      try { return factory.interface.parseLog(log); } catch { return null; }
    }).find((log) => log?.name === "CanonicalManagerDeployed");
    assert.ok(deployed);
    managers.push(new ethers.Contract(deployed.args.manager, Manager.interface, owner));
  }
  for (let i = 0; i < MANAGER_COUNT; i += 1) {
    await submissionManagers[i].connect(owner).setChallengeManager(await managers[i].getAddress());
  }
  const managerAddresses = await Promise.all(managers.map((entry) => entry.getAddress()));
  if (options.substituteManager) managerAddresses[0] = await factory.getAddress();
  const quorum = await Quorum.deploy(
    owner.address,
    treasury.address,
    RESOLVER_BOND,
    await factory.getAddress(),
    [signerA.address, signerB.address, signerC.address],
    2,
    managerAddresses,
    await objectiveVerifier.getAddress(),
    objectiveVerifierCodehash,
  );
  await quorum.waitForDeployment();
  assert.equal(await quorum.getAddress(), predictedQuorum);
  if (options.rotationReady) await mineAt(await quorum.nextSignerRotationAt());

  const solutionCid = "ipfs://resolver-quorum-solution";
  const salt = "resolver-quorum-salt";
  const commitment = await submissions["computeCommitment(string,address,bytes32,string)"](
    solutionCid, solver.address, DA_HASH, salt,
  );
  await submissions.connect(solver).commit(commitment, DA_HASH, { value: ethers.parseEther("0.01") });
  const submissionId = await submissions.submissionCount();
  await submissions.connect(solver).reveal(submissionId, solutionCid, 999_000, 1_000, salt, "0x");
  await managers[0].connect(challenger).challenge(
    submissionId, await submissions.revealInstanceHashOf(submissionId), ethers.id("hostile challenge"),
    { value: CHALLENGE_BOND },
  );

  return {
    owner, treasury, signerA, signerB, signerC, solver, challenger, relayer, beneficiary, outsider,
    quorum, factory, submissionFactory, objectiveVerifier, objectiveBindings, registry, pool, ledger, managers, submissions, submissionId,
  };
}

async function decisionFor(fixture, overrides = {}) {
  const manager = overrides.manager ?? fixture.managers[0];
  const transcriptURI = overrides.transcriptURI ?? "ipfs://canonical-resolver-transcript";
  const decision = {
    chainId: (await ethers.provider.getNetwork()).chainId,
    adapter: await fixture.quorum.getAddress(),
    manager: await manager.getAddress(),
    submissionId: fixture.submissionId,
    challengeInstanceHash: await fixture.managers[0].challengeInstanceHashOf(fixture.submissionId),
    challengerWins: overrides.challengerWins ?? true,
    transcriptHash: overrides.transcriptHash ?? ethers.id("canonical transcript bytes"),
    transcriptURIHash: ethers.keccak256(ethers.toUtf8Bytes(transcriptURI)),
    verdictHash: overrides.verdictHash ?? ethers.id("canonical verdict report"),
    bondBeneficiary: overrides.bondBeneficiary ?? await fixture.quorum.getAddress(),
    nonce: overrides.nonce ?? 1n,
    expiry: overrides.expiry ?? (await latestTimestamp()) + 3_600n,
    signerEpoch: overrides.signerEpoch ?? await fixture.quorum.signerEpoch(),
    ...overrides.fields,
  };
  return { decision, transcriptURI };
}

async function signaturesFor(fixture, decision, selected = [fixture.signerA, fixture.signerB]) {
  const domain = {
    name: "P42ResolverQuorum",
    version: "1",
    chainId: decision.chainId,
    verifyingContract: await fixture.quorum.getAddress(),
  };
  const signed = await Promise.all(selected.map(async (signer) => ({
    address: signer.address.toLowerCase(),
    signature: await signer.signTypedData(domain, DECISION_TYPES, decision),
  })));
  return signed.sort((left, right) => left.address.localeCompare(right.address)).map((entry) => entry.signature);
}

async function objectiveProofFor(fixture, { correctedChallengerWins, proofBeneficiary = fixture.beneficiary.address } = {}) {
  const manager = fixture.managers[0];
  const managerAddress = await manager.getAddress();
  const challengeInstanceHash = await manager.challengeInstanceHashOf(fixture.submissionId);
  const [contextHash] = await manager.objectiveProofContext(fixture.submissionId, challengeInstanceHash);
  const guestElfSha256 = await fixture.quorum.objectiveGuestElfSha256Of(managerAddress);
  const programVKey = await fixture.quorum.objectiveProgramVKeyOf(managerAddress);
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const journalDigest = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ["string", "uint256", "address", "address", "bytes32", "bytes32", "bytes32", "bool", "address"],
    [
      "P42_OBJECTIVE_VERDICT_JOURNAL_V2", chainId, await fixture.quorum.getAddress(), managerAddress,
      guestElfSha256, programVKey, contextHash, correctedChallengerWins, proofBeneficiary,
    ],
  ));
  return {
    claim: {
      manager: managerAddress,
      submissionId: fixture.submissionId,
      challengeInstanceHash,
      correctedChallengerWins,
      proofBeneficiary,
    },
    proof: ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32"], [programVKey, journalDigest]),
    journalDigest,
  };
}

describe("P42ResolverQuorum", function () {
  it("requires a strict-majority immutable signer quorum and an exact constructor-frozen manager set", async function () {
    const [owner, a, b, c, d, outsider] = await ethers.getSigners();
    const Quorum = await ethers.getContractFactory("P42ResolverQuorum");
    await expectCustomError(
      Quorum.deploy(owner.address, outsider.address, RESOLVER_BOND, outsider.address, [a.address, b.address], 2, [], outsider.address, ethers.id("verifier-code")),
      Quorum,
      "BadSigner",
    );
    await expectCustomError(
      Quorum.deploy(owner.address, outsider.address, RESOLVER_BOND, outsider.address, [a.address, b.address, c.address], 1, [], outsider.address, ethers.id("verifier-code")), Quorum, "BadThreshold",
    );
    await expectCustomError(
      Quorum.deploy(
        owner.address, outsider.address, RESOLVER_BOND,
        outsider.address, [a.address, b.address, c.address, d.address, outsider.address], 2, [], outsider.address, ethers.id("verifier-code"),
      ),
      Quorum, "BadThreshold",
    );
    const Factory = await ethers.getContractFactory("P42ChallengeManagerFactory");
    const factory = await Factory.deploy();
    await factory.waitForDeployment();
    const ObjectiveVerifier = await ethers.getContractFactory("MockObjectiveVerifierGateway");
    const objectiveVerifier = await ObjectiveVerifier.deploy();
    await objectiveVerifier.waitForDeployment();
    const objectiveVerifierCodehash = ethers.keccak256(
      await ethers.provider.getCode(await objectiveVerifier.getAddress()),
    );
    await expectCustomError(
      Quorum.deploy(
        owner.address, outsider.address, RESOLVER_BOND, await factory.getAddress(), [a.address, b.address, c.address], 2, [],
        await objectiveVerifier.getAddress(),
        objectiveVerifierCodehash,
      ),
      Quorum,
      "WrongManagerCount",
    );
  });

  it("starts with an immutable exact-ten manager topology", async function () {
    const fixture = await deployFixture();
    assert.equal(await fixture.quorum.managerCount(), 10n);
    assert.equal(await fixture.quorum.managersFrozen(), true);
    assert.equal(
      ethers.keccak256(await ethers.provider.getCode(await fixture.factory.getAddress())),
      await fixture.quorum.CANONICAL_MANAGER_FACTORY_CODEHASH(),
    );
    assert.equal(
      ethers.keccak256(await ethers.provider.getCode(await fixture.submissionFactory.getAddress())),
      await fixture.factory.CANONICAL_SUBMISSION_MANAGER_FACTORY_CODEHASH(),
    );
    for (const manager of fixture.managers) assert.equal(await fixture.quorum.isManager(await manager.getAddress()), true);
    const binding = fixture.objectiveBindings[0];
    await fixture.registry.connect(fixture.owner).register({
      specHash: binding.specHash,
      verifierSourceHash: binding.verifierSourceHash,
      verifierImageHash: binding.verifierImageHash,
      admissionMatrixHash: binding.admissionMatrixHash,
      metadataURI: "ipfs://resolver-quorum-board-1",
      pool: await fixture.pool.getAddress(),
      ledger: await fixture.ledger.getAddress(),
      submissionManager: await fixture.submissions.getAddress(),
      challengeManager: await fixture.managers[0].getAddress(),
      challengeWindowSeconds: CHALLENGE_WINDOW,
      minImprovementAtoms: 1,
    });
    assert.equal(await fixture.registry.problemCount(), 1n);
    await expectCustomError(
      fixture.registry.connect(fixture.owner).updateBeforeFunding(1, {
        specHash: ethers.id("wrong-spec"),
        verifierSourceHash: binding.verifierSourceHash,
        verifierImageHash: binding.verifierImageHash,
        admissionMatrixHash: binding.admissionMatrixHash,
        metadataURI: "ipfs://resolver-quorum-board-1",
        pool: await fixture.pool.getAddress(),
        ledger: await fixture.ledger.getAddress(),
        submissionManager: await fixture.submissions.getAddress(),
        challengeManager: await fixture.managers[0].getAddress(),
        challengeWindowSeconds: CHALLENGE_WINDOW,
        minImprovementAtoms: 1,
      }),
      fixture.registry,
      "P42_ZERO_HASH",
    );
  });

  it("rejects a manager set containing a contract not created by the pinned factory", async function () {
    const Quorum = await ethers.getContractFactory("P42ResolverQuorum");
    await expectCustomError(deployFixture({ substituteManager: true }), Quorum, "BadManager");
  });

  it("binds every objective field into the effective CREATE2 salt", async function () {
    const fixture = await deployFixture();
    const manager = fixture.managers[0];
    const requestedSalt = ethers.id("resolver-manager-0");
    const canonical = {
      owner: fixture.owner.address, resolver: await fixture.quorum.getAddress(), treasury: fixture.treasury.address,
      submissionManager: await fixture.submissions.getAddress(), challengeWindowSeconds: CHALLENGE_WINDOW,
      betaBps: 500, minCounterBondWei: CHALLENGE_BOND, rerunCostWei: ethers.parseEther("0.01"),
      rerunCostMultiplierBps: 30_000, resolverDecisionBondWei: RESOLVER_BOND,
      resolverFraudWindowSeconds: FRAUD_WINDOW,
      problemRegistry: await fixture.registry.getAddress(), problemId: 1,
      objectivePackageHash: (await manager.objectiveBinding())[2],
      objectiveGuestElfSha256: fixture.objectiveBindings[0].objectiveGuestElfSha256,
      objectiveProgramVKey: fixture.objectiveBindings[0].objectiveProgramVKey,
    };
    const substituted = {
      ...canonical,
      objectivePackageHash: ethers.id("attacker-package"),
      objectiveGuestElfSha256: ethers.id("attacker-guest"),
      objectiveProgramVKey: ethers.id("attacker-program"),
    };
    const canonicalSalt = await fixture.factory.effectiveSalt(
      requestedSalt, await fixture.submissionFactory.getAddress(), canonical,
    );
    assert.equal(
      challengeManagerEffectiveSalt(ethers, requestedSalt, await fixture.submissionFactory.getAddress(), canonical),
      canonicalSalt,
    );
    const substitutedSalt = await fixture.factory.effectiveSalt(
      requestedSalt, await fixture.submissionFactory.getAddress(), substituted,
    );
    assert.notEqual(canonicalSalt, substitutedSalt);
    const receipt = await (await fixture.factory.deployManager(
      requestedSalt, await fixture.submissionFactory.getAddress(), substituted,
    )).wait();
    const deployed = receipt.logs.map((log) => {
      try { return fixture.factory.interface.parseLog(log); } catch { return null; }
    }).find((log) => log?.name === "CanonicalManagerDeployed");
    assert.ok(deployed);
    assert.equal(deployed.args.salt, substitutedSalt);
    assert.notEqual(deployed.args.manager, await manager.getAddress());
  });

  it("rejects a genuine manager deployment attempt bound to a noncanonical submission manager", async function () {
    const fixture = await deployFixture();
    const Submissions = await ethers.getContractFactory("P42SubmissionManager");
    const spoof = await Submissions.deploy({
      pool: await fixture.pool.getAddress(), ledger: await fixture.ledger.getAddress(),
      owner: fixture.owner.address, treasury: fixture.treasury.address, alphaBps: 200,
      minPostingBondWei: ethers.parseEther("0.01"), challengeWindowSeconds: CHALLENGE_WINDOW,
      onchainDa: false, maxSolutionBytes: 0, seedScoreAtoms: 1_000_000, minImprovementAtoms: 1,
    }, fundingAuthorizationConfig([fixture.signerA, fixture.signerB, fixture.signerC]));
    await spoof.waitForDeployment();
    await expectCustomError(
      fixture.factory.deployManager(
        ethers.id("spoof-submission-manager"),
        await fixture.submissionFactory.getAddress(),
        {
          owner: fixture.owner.address, resolver: await fixture.quorum.getAddress(), treasury: fixture.treasury.address,
          submissionManager: await spoof.getAddress(), challengeWindowSeconds: CHALLENGE_WINDOW,
          betaBps: 500, minCounterBondWei: CHALLENGE_BOND, rerunCostWei: ethers.parseEther("0.01"),
          rerunCostMultiplierBps: 30_000, resolverDecisionBondWei: RESOLVER_BOND,
          resolverFraudWindowSeconds: FRAUD_WINDOW,
          problemRegistry: await fixture.registry.getAddress(), problemId: 11,
          objectivePackageHash: ethers.id("spoof-objective-package"),
          objectiveGuestElfSha256: ethers.id("spoof-objective-guest"),
          objectiveProgramVKey: OBJECTIVE_PROGRAM,
        },
      ),
      fixture.factory,
      "P42_FACTORY_BAD_SUBMISSION_MANAGER",
    );
  });

  it("rejects a factory-recorded submission manager with mismatched escrow governance", async function () {
    const fixture = await deployFixture();
    const tx = await fixture.submissionFactory.deploySubmissionManager(
      ethers.id("wrong-submission-governance"),
      {
        deployment: {
          pool: await fixture.pool.getAddress(), ledger: await fixture.ledger.getAddress(), owner: fixture.outsider.address,
          treasury: fixture.treasury.address, alphaBps: 200, minPostingBondWei: ethers.parseEther("0.01"),
          challengeWindowSeconds: CHALLENGE_WINDOW, onchainDa: false, maxSolutionBytes: 0,
          seedScoreAtoms: 1_000_000, minImprovementAtoms: 1,
        },
        fundingAuthorization: fundingAuthorizationConfig([fixture.signerA, fixture.signerB, fixture.signerC]),
      },
      (await ethers.getContractFactory("P42SubmissionManager")).bytecode,
    );
    const receipt = await tx.wait();
    const deployed = receipt.logs.map((log) => {
      try { return fixture.submissionFactory.interface.parseLog(log); } catch { return null; }
    }).find((log) => log?.name === "CanonicalSubmissionManagerDeployed");
    assert.ok(deployed);
    await expectCustomError(
      fixture.factory.deployManager(
        ethers.id("wrong-submission-governance-manager"),
        await fixture.submissionFactory.getAddress(),
        {
          owner: fixture.owner.address, resolver: await fixture.quorum.getAddress(), treasury: fixture.treasury.address,
          submissionManager: deployed.args.submissionManager, challengeWindowSeconds: CHALLENGE_WINDOW,
          betaBps: 500, minCounterBondWei: CHALLENGE_BOND, rerunCostWei: ethers.parseEther("0.01"),
          rerunCostMultiplierBps: 30_000, resolverDecisionBondWei: RESOLVER_BOND,
          resolverFraudWindowSeconds: FRAUD_WINDOW,
          problemRegistry: await fixture.registry.getAddress(), problemId: 11,
          objectivePackageHash: ethers.id("wrong-governance-objective-package"),
          objectiveGuestElfSha256: ethers.id("wrong-governance-objective-guest"),
          objectiveProgramVKey: OBJECTIVE_PROGRAM,
        },
      ),
      fixture.factory,
      "P42_FACTORY_BAD_SUBMISSION_CONFIGURATION",
    );
  });

  it("forwards the exact bond through resolveFor and blocks replay", async function () {
    const fixture = await deployFixture();
    const { decision, transcriptURI } = await decisionFor(fixture);
    const signatures = await signaturesFor(fixture, decision);
    await expectCustomError(fixture.quorum.connect(fixture.outsider).fundStake({ value: 1n }), fixture.quorum, "NotSigner");
    await expectCustomError(
      fixture.quorum.resolve(decision, transcriptURI, signatures), fixture.quorum, "InsufficientStake",
    );
    await fixture.quorum.connect(fixture.signerA).fundStake({ value: RESOLVER_BOND * 2n });
    await expectCustomError(
      fixture.quorum.connect(fixture.relayer).resolve(decision, transcriptURI, signatures, { value: 1n }),
      fixture.quorum, "UnexpectedValue",
    );
    await fixture.quorum.connect(fixture.relayer).resolve(decision, transcriptURI, signatures);

    const bond = await fixture.managers[0].resolverBonds(fixture.submissionId);
    assert.equal(bond.amountWei, RESOLVER_BOND);
    assert.equal(await fixture.managers[0].resolverBondBeneficiaryOf(fixture.submissionId), await fixture.quorum.getAddress());
    assert.equal(await ethers.provider.getBalance(await fixture.quorum.getAddress()), RESOLVER_BOND);
    await expectCustomError(
      fixture.quorum.resolve(decision, transcriptURI, signatures),
      fixture.quorum, "NonceAlreadyUsed",
    );
    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(bond.releaseAt)]);
    await ethers.provider.send("evm_mine", []);
    await fixture.managers[0].finalizeResolution(fixture.submissionId, decision.challengeInstanceHash);
    assert.equal(await fixture.managers[0].claimableBondWei(await fixture.quorum.getAddress()), RESOLVER_BOND);
    assert.equal(await fixture.managers[0].resolverBondBeneficiaryOf(fixture.submissionId), ethers.ZeroAddress);
    await fixture.quorum.connect(fixture.outsider).reclaimStake(await fixture.managers[0].getAddress());
    assert.equal(await ethers.provider.getBalance(await fixture.quorum.getAddress()), RESOLVER_BOND * 2n);
  });

  it("executes the production agent quorum packet, independent signatures, and zero-value relay end to end", async function () {
    const fixture = await deployFixture();
    await fixture.quorum.connect(fixture.signerA).fundStake({ value: RESOLVER_BOND });
    const source = await decisionFor(fixture, { nonce: 901n });
    const packet = buildResolverQuorumDecisionPacket({
      chainId: source.decision.chainId,
      adapter: source.decision.adapter,
      manager: source.decision.manager,
      submissionId: source.decision.submissionId,
      challengeInstanceHash: source.decision.challengeInstanceHash,
      challengerWins: source.decision.challengerWins,
      transcriptHash: source.decision.transcriptHash,
      transcriptURI: source.transcriptURI,
      verdictHash: source.decision.verdictHash,
      nonce: source.decision.nonce,
      expiry: source.decision.expiry,
      signerEpoch: source.decision.signerEpoch,
    });
    const artifacts = await Promise.all([
      buildResolverQuorumSignatureArtifact(packet, fixture.signerB),
      buildResolverQuorumSignatureArtifact(packet, fixture.signerA),
    ]);
    const collected = await collectResolverQuorumSignatures({
      packet,
      artifacts,
      quorum: fixture.quorum,
    });
    assert.equal(collected.ready, true);
    assert.deepEqual(collected.signers, [...collected.signers].sort());
    const policy = buildQuorumResolveCallPolicy({
      quorumInterface: fixture.quorum.interface,
      packet,
      signatures: collected.signatures,
      problemId: "fixture-board",
      revealInstanceHash: await fixture.submissions.revealInstanceHashOf(fixture.submissionId),
      candidateHash: SHA("a"),
      sourceEventHash: SHA("b"),
    });
    const replay = buildQuorumResolveCallPolicy({
      quorumInterface: fixture.quorum.interface,
      packet,
      signatures: collected.signatures,
      problemId: "fixture-board",
      revealInstanceHash: await fixture.submissions.revealInstanceHashOf(fixture.submissionId),
      candidateHash: SHA("a"),
      sourceEventHash: SHA("b"),
    });
    assert.equal(policy.policy_hash, replay.policy_hash);
    assert.equal(policy.call_value_wei, "0");
    await fixture.relayer.sendTransaction({ to: policy.target, data: policy.calldata, value: 0n });
    const challenge = await fixture.managers[0].challenges(fixture.submissionId);
    assert.equal(challenge.decisionPending, true);
    assert.equal(challenge.challengerWins, true);
    assert.equal(challenge.transcriptHash, source.decision.transcriptHash);
    assert.equal(await fixture.quorum.nonceUsed(source.decision.manager, 901n), true);
    assert.equal(
      await fixture.quorum.challengeDecided(source.decision.manager, source.decision.challengeInstanceHash),
      true,
    );
  });

  it("rejects undersigned, unsorted, expired, URI-forged, and cross-manager decisions", async function () {
    const fixture = await deployFixture();
    await fixture.quorum.connect(fixture.signerA).fundStake({ value: RESOLVER_BOND });
    const { decision, transcriptURI } = await decisionFor(fixture);
    const sorted = await signaturesFor(fixture, decision);
    await expectCustomError(
      fixture.quorum.resolve(decision, transcriptURI, sorted.slice(0, 1)),
      fixture.quorum, "InsufficientSignatures",
    );
    await expectCustomError(
      fixture.quorum.resolve(decision, transcriptURI, [...sorted].reverse()),
      fixture.quorum, "SignersNotStrictlySorted",
    );
    await expectCustomError(
      fixture.quorum.resolve(decision, "ipfs://forged", sorted),
      fixture.quorum, "TranscriptURIMismatch",
    );
    const expired = (await decisionFor(fixture, { nonce: 2n, expiry: (await latestTimestamp()) - 1n })).decision;
    await expectCustomError(
      fixture.quorum.resolve(expired, transcriptURI, await signaturesFor(fixture, expired)),
      fixture.quorum, "DecisionExpired",
    );
    const crossManager = { ...decision, manager: await fixture.managers[1].getAddress(), nonce: 3n };
    await expectCustomError(
      fixture.quorum.resolve(crossManager, transcriptURI, sorted),
      fixture.quorum, "BadSignature",
    );
  });

  it("permissionlessly proves canonical equivocation and forwards resolver-only slashing once", async function () {
    const fixture = await deployFixture();
    await fixture.quorum.connect(fixture.signerA).fundStake({ value: RESOLVER_BOND });
    const first = await decisionFor(fixture, { nonce: 11n, challengerWins: true });
    const renewal = await decisionFor(fixture, { nonce: 13n, challengerWins: true });
    const second = await decisionFor(fixture, { nonce: 12n, challengerWins: false, verdictHash: ethers.id("conflicting verdict") });
    const firstSignatures = await signaturesFor(fixture, first.decision);
    const renewalSignatures = await signaturesFor(fixture, renewal.decision);
    const secondSignatures = await signaturesFor(fixture, second.decision);
    await fixture.quorum.resolve(first.decision, first.transcriptURI, firstSignatures);

    await expectCustomError(
      fixture.quorum.proveEquivocation(first.decision, firstSignatures, renewal.decision, renewalSignatures),
      fixture.quorum, "NotEquivocation",
    );

    await fixture.quorum.connect(fixture.outsider).proveEquivocation(
      first.decision, firstSignatures, second.decision, secondSignatures,
    );
    const bond = await fixture.managers[0].resolverBonds(fixture.submissionId);
    assert.equal(bond.amountWei, 0n);
    assert.notEqual(bond.slashProofHash, ethers.ZeroHash);
    await expectCustomError(
      fixture.quorum.proveEquivocation(first.decision, firstSignatures, second.decision, secondSignatures),
      fixture.quorum, "EquivocationAlreadyProven",
    );
  });

  it("permissionlessly corrects a wrong quorum verdict and closes the proved reveal instance", async function () {
    const fixture = await deployFixture();
    await fixture.quorum.connect(fixture.signerA).fundStake({ value: RESOLVER_BOND });
    const pending = await decisionFor(fixture, { nonce: 14n, challengerWins: true });
    await fixture.quorum.resolve(
      pending.decision, pending.transcriptURI, await signaturesFor(fixture, pending.decision),
    );

    const objective = await objectiveProofFor(fixture, { correctedChallengerWins: false });
    await expectCustomError(
      fixture.quorum.connect(fixture.outsider).proveObjectiveFraud(
        objective.claim, ethers.hexlify(ethers.randomBytes(64)),
      ),
      fixture.quorum,
      "BadObjectiveProof",
    );
    const copied = { ...objective.claim, proofBeneficiary: fixture.outsider.address };
    await expectCustomError(
      fixture.quorum.connect(fixture.outsider).proveObjectiveFraud(copied, objective.proof),
      fixture.quorum,
      "BadObjectiveProof",
    );

    await fixture.quorum.connect(fixture.outsider).proveObjectiveFraud(objective.claim, objective.proof);
    const resolverBond = await fixture.managers[0].resolverBonds(fixture.submissionId);
    assert.equal(resolverBond.amountWei, 0n);
    assert.notEqual(resolverBond.slashProofHash, ethers.ZeroHash);
    assert.equal(
      await fixture.managers[0].claimableBondWei(fixture.beneficiary.address), RESOLVER_BOND,
    );
    assert.equal(
      await fixture.managers[0].claimableBondWei(fixture.treasury.address), CHALLENGE_BOND,
    );
    assert.equal(
      await fixture.submissions.objectiveClearedRevealInstanceHashOf(fixture.submissionId),
      await fixture.submissions.revealInstanceHashOf(fixture.submissionId),
    );
    await expectCustomError(
      fixture.managers[0].connect(fixture.outsider).challenge(
        fixture.submissionId,
        await fixture.submissions.revealInstanceHashOf(fixture.submissionId),
        ethers.id("repeat challenge after objective proof"),
        { value: CHALLENGE_BOND },
      ),
      fixture.submissions,
      "P42_OBJECTIVE_CHALLENGE_ALREADY_CLEARED",
    );
    await fixture.submissions.connect(fixture.solver).finalize(fixture.submissionId, ethers.ZeroHash);
  });

  it("applies an objective challenger win and rewards the proof-bound beneficiary", async function () {
    const fixture = await deployFixture();
    await fixture.quorum.connect(fixture.signerA).fundStake({ value: RESOLVER_BOND });
    const pending = await decisionFor(fixture, { nonce: 15n, challengerWins: false });
    await fixture.quorum.resolve(
      pending.decision, pending.transcriptURI, await signaturesFor(fixture, pending.decision),
    );
    const objective = await objectiveProofFor(fixture, { correctedChallengerWins: true });
    await fixture.quorum.connect(fixture.outsider).proveObjectiveFraud(objective.claim, objective.proof);
    assert.equal(
      await fixture.managers[0].claimableBondWei(fixture.challenger.address), CHALLENGE_BOND,
    );
    assert.equal(
      await fixture.managers[0].claimableBondWei(fixture.beneficiary.address), RESOLVER_BOND,
    );
    assert.equal(
      await fixture.submissions.claimableBondWei(fixture.challenger.address), ethers.parseEther("0.01"),
    );
    const submission = await fixture.submissions.submissions(fixture.submissionId);
    assert.equal(submission.status, 5n);
  });

  it("rotates strict-majority signer sets monotonically and rejects stale-epoch execution", async function () {
    const fixture = await deployFixture();
    const old = await decisionFor(fixture, { nonce: 21n });
    const oldSignatures = await signaturesFor(fixture, old.decision);

    await expectCustomError(
      fixture.quorum.connect(fixture.outsider).rotateSigners(
        [fixture.signerC.address, fixture.beneficiary.address, fixture.outsider.address], 2,
      ),
      fixture.quorum,
      "NotOwner",
    );
    await expectCustomError(
      fixture.quorum.connect(fixture.owner).rotateSigners(
        [fixture.signerC.address, fixture.beneficiary.address, fixture.outsider.address], 1,
      ),
      fixture.quorum,
      "RotationCooldownActive",
    );
    const firstRotationAt = await fixture.quorum.nextSignerRotationAt();
    assert.equal(firstRotationAt - await latestTimestamp() <= await fixture.quorum.SIGNER_ROTATION_COOLDOWN(), true);
    await setNextTimestamp(firstRotationAt - 1n);
    await expectCustomError(
      fixture.quorum.connect(fixture.owner).rotateSigners(
        [fixture.signerC.address, fixture.beneficiary.address, fixture.outsider.address], 2,
      ),
      fixture.quorum,
      "RotationCooldownActive",
    );
    await setNextTimestamp(firstRotationAt);
    await expectCustomError(
      fixture.quorum.connect(fixture.owner).rotateSigners(
        [fixture.signerC.address, fixture.beneficiary.address, fixture.outsider.address], 1,
      ),
      fixture.quorum,
      "BadThreshold",
    );
    await fixture.quorum.connect(fixture.owner).rotateSigners(
      [fixture.signerC.address, fixture.beneficiary.address, fixture.outsider.address], 2,
    );

    const secondRotationAt = await fixture.quorum.nextSignerRotationAt();
    assert.equal(secondRotationAt, BigInt((await ethers.provider.getBlock("latest")).timestamp) + 7n * 24n * 60n * 60n);
    await setNextTimestamp(secondRotationAt - 1n);
    await expectCustomError(
      fixture.quorum.connect(fixture.owner).rotateSigners(
        [fixture.signerA.address, fixture.signerB.address, fixture.signerC.address], 2,
      ),
      fixture.quorum,
      "RotationCooldownActive",
    );
    await setNextTimestamp(secondRotationAt);
    await fixture.quorum.connect(fixture.owner).rotateSigners(
      [fixture.signerA.address, fixture.signerB.address, fixture.signerC.address], 2,
    );

    assert.equal(await fixture.quorum.signerEpoch(), 3n);
    assert.equal(await fixture.quorum.threshold(), 2n);
    assert.equal(await fixture.quorum.epochThreshold(1), 2n);
    assert.equal(await fixture.quorum.epochThreshold(2), 2n);
    assert.equal(await fixture.quorum.epochSignerCount(1), 3n);
    assert.equal(await fixture.quorum.isEpochSigner(1, fixture.signerA.address), true);
    assert.equal(await fixture.quorum.isEpochSigner(2, fixture.signerA.address), false);
    assert.equal(await fixture.quorum.isSigner(fixture.signerA.address), true);
    assert.equal(await fixture.quorum.isSigner(fixture.outsider.address), false);

    await expectCustomError(
      fixture.quorum.resolve(old.decision, old.transcriptURI, oldSignatures), fixture.quorum, "StaleSignerEpoch",
    );
  });

  it("retains historical signer epochs for same-epoch proofs after rotation", async function () {
    const fixture = await deployFixture({ rotationReady: true });
    await fixture.quorum.connect(fixture.signerA).fundStake({ value: RESOLVER_BOND });
    const first = await decisionFor(fixture, { nonce: 31n, challengerWins: true });
    const second = await decisionFor(fixture, {
      nonce: 32n,
      challengerWins: false,
      verdictHash: ethers.id("same-epoch conflicting verdict"),
    });
    const firstSignatures = await signaturesFor(fixture, first.decision);
    const secondSignatures = await signaturesFor(fixture, second.decision);
    await fixture.quorum.resolve(first.decision, first.transcriptURI, firstSignatures);

    await fixture.quorum.connect(fixture.owner).rotateSigners(
      [fixture.signerC.address, fixture.beneficiary.address, fixture.outsider.address], 2,
    );
    await fixture.quorum.proveEquivocation(
      first.decision, firstSignatures, second.decision, secondSignatures,
    );
    const bond = await fixture.managers[0].resolverBonds(fixture.submissionId);
    assert.equal(bond.amountWei, 0n);
    assert.notEqual(bond.slashProofHash, ethers.ZeroHash);
  });

  it("does not slash validly signed conflicts from different signer epochs", async function () {
    const fixture = await deployFixture({ rotationReady: true });
    await fixture.quorum.connect(fixture.signerA).fundStake({ value: RESOLVER_BOND });
    const first = await decisionFor(fixture, { nonce: 41n, challengerWins: true });
    const firstSignatures = await signaturesFor(fixture, first.decision);
    await fixture.quorum.resolve(first.decision, first.transcriptURI, firstSignatures);

    await fixture.quorum.connect(fixture.owner).rotateSigners(
      [fixture.signerC.address, fixture.beneficiary.address, fixture.outsider.address], 2,
    );
    const second = await decisionFor(fixture, {
      nonce: 42n,
      challengerWins: false,
      verdictHash: ethers.id("cross-epoch conflicting verdict"),
    });
    const secondSignatures = await signaturesFor(
      fixture, second.decision, [fixture.signerC, fixture.beneficiary],
    );
    await expectCustomError(
      fixture.quorum.proveEquivocation(
        first.decision, firstSignatures, second.decision, secondSignatures,
      ),
      fixture.quorum,
      "NotEquivocation",
    );
    const bond = await fixture.managers[0].resolverBonds(fixture.submissionId);
    assert.equal(bond.amountWei, RESOLVER_BOND);
    assert.equal(bond.slashProofHash, ethers.ZeroHash);
  });

  it("bounds pauses, auto-expires them, and prevents extension or continuous repause", async function () {
    const fixture = await deployFixture();
    const { decision, transcriptURI } = await decisionFor(fixture, {
      expiry: (await latestTimestamp()) + 3n * 24n * 60n * 60n,
    });
    const signatures = await signaturesFor(fixture, decision);
    await fixture.quorum.connect(fixture.signerA).fundStake({ value: RESOLVER_BOND });

    await expectCustomError(
      fixture.quorum.connect(fixture.outsider).setPaused(true), fixture.quorum, "NotOwner",
    );
    await fixture.quorum.connect(fixture.owner).setPaused(true);
    const pauseUntil = await fixture.quorum.pauseUntil();
    assert.equal(await fixture.quorum.paused(), true);
    await expectCustomError(
      fixture.quorum.connect(fixture.owner).setPaused(true), fixture.quorum, "PauseAlreadyActive",
    );
    await expectCustomError(
      fixture.quorum.resolve(decision, transcriptURI, signatures), fixture.quorum, "Paused",
    );

    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(pauseUntil)]);
    await ethers.provider.send("evm_mine", []);
    assert.equal(await fixture.quorum.paused(), false);
    await expectCustomError(
      fixture.quorum.connect(fixture.owner).setPaused(true), fixture.quorum, "PauseCooldownActive",
    );
    await fixture.quorum.resolve(decision, transcriptURI, signatures);

    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(await fixture.quorum.pauseCooldownUntil())]);
    await ethers.provider.send("evm_mine", []);
    await fixture.quorum.connect(fixture.owner).setPaused(true);
    assert.equal(await fixture.quorum.paused(), true);
  });
});
