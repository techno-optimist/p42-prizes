import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const CHALLENGE_WINDOW = 72n * 60n * 60n;
const FRAUD_WINDOW = 24n * 60n * 60n;
const MANAGER_COUNT = 10;
const RESOLVER_BOND = ethers.parseEther("0.005");
const CHALLENGE_BOND = ethers.parseEther("0.03");
const DA_HASH = ethers.id("resolver-quorum-da");

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

  const Submissions = await ethers.getContractFactory("P42SubmissionManager");
  const SubmissionFactory = await ethers.getContractFactory("P42SubmissionManagerFactory");
  const submissionFactory = await SubmissionFactory.deploy();
  await submissionFactory.waitForDeployment();
  const submissionManagers = [];
  for (let i = 0; i < MANAGER_COUNT; i += 1) {
    const tx = await submissionFactory.deploySubmissionManager(
      ethers.id(`submission-manager-${i}`),
      {
        pool: await pool.getAddress(), ledger: await ledger.getAddress(), owner: owner.address,
        treasury: treasury.address, alphaBps: 200, minPostingBondWei: ethers.parseEther("0.01"),
        challengeWindowSeconds: CHALLENGE_WINDOW, onchainDa: false, maxSolutionBytes: 0,
        seedScoreAtoms: 1_000_000, minImprovementAtoms: 1,
      },
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
  const startNonce = await ethers.provider.getTransactionCount(owner.address);
  const predictedQuorum = ethers.getCreateAddress({ from: owner.address, nonce: startNonce + MANAGER_COUNT * 2 });
  const managers = [];
  for (let i = 0; i < MANAGER_COUNT; i += 1) {
    const tx = await factory.deployManager(
      ethers.id(`resolver-manager-${i}`),
      await submissionFactory.getAddress(),
      {
        owner: owner.address, resolver: predictedQuorum, treasury: treasury.address,
        submissionManager: await submissionManagers[i].getAddress(), challengeWindowSeconds: CHALLENGE_WINDOW,
        betaBps: 500, minCounterBondWei: CHALLENGE_BOND, rerunCostWei: ethers.parseEther("0.01"),
        rerunCostMultiplierBps: 30_000, resolverDecisionBondWei: RESOLVER_BOND,
        resolverFraudWindowSeconds: FRAUD_WINDOW,
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
    quorum, factory, submissionFactory, pool, ledger, managers, submissions, submissionId,
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

describe("P42ResolverQuorum", function () {
  it("requires a strict-majority immutable signer quorum and an exact constructor-frozen manager set", async function () {
    const [owner, a, b, c, d, outsider] = await ethers.getSigners();
    const Quorum = await ethers.getContractFactory("P42ResolverQuorum");
    await expectCustomError(
      Quorum.deploy(owner.address, outsider.address, RESOLVER_BOND, outsider.address, [a.address, b.address], 2, []),
      Quorum,
      "BadSigner",
    );
    await expectCustomError(
      Quorum.deploy(owner.address, outsider.address, RESOLVER_BOND, outsider.address, [a.address, b.address, c.address], 1, []), Quorum, "BadThreshold",
    );
    await expectCustomError(
      Quorum.deploy(
        owner.address, outsider.address, RESOLVER_BOND,
        outsider.address, [a.address, b.address, c.address, d.address, outsider.address], 2, [],
      ),
      Quorum, "BadThreshold",
    );
    const Factory = await ethers.getContractFactory("P42ChallengeManagerFactory");
    const factory = await Factory.deploy();
    await factory.waitForDeployment();
    await expectCustomError(
      Quorum.deploy(
        owner.address, outsider.address, RESOLVER_BOND, await factory.getAddress(), [a.address, b.address, c.address], 2, [],
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
  });

  it("rejects a manager set containing a contract not created by the pinned factory", async function () {
    const Quorum = await ethers.getContractFactory("P42ResolverQuorum");
    await expectCustomError(deployFixture({ substituteManager: true }), Quorum, "BadManager");
  });

  it("rejects a genuine manager deployment attempt bound to a noncanonical submission manager", async function () {
    const fixture = await deployFixture();
    const Submissions = await ethers.getContractFactory("P42SubmissionManager");
    const spoof = await Submissions.deploy(
      await fixture.pool.getAddress(), await fixture.ledger.getAddress(), fixture.owner.address,
      fixture.treasury.address, 200, ethers.parseEther("0.01"), CHALLENGE_WINDOW,
      false, 0, 1_000_000, 1,
    );
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
        pool: await fixture.pool.getAddress(), ledger: await fixture.ledger.getAddress(), owner: fixture.outsider.address,
        treasury: fixture.treasury.address, alphaBps: 200, minPostingBondWei: ethers.parseEther("0.01"),
        challengeWindowSeconds: CHALLENGE_WINDOW, onchainDa: false, maxSolutionBytes: 0,
        seedScoreAtoms: 1_000_000, minImprovementAtoms: 1,
      },
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
