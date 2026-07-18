import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

const CHALLENGE_WINDOW = 60n;
const BOARD_SET_DIGEST = ethers.id("p42-exact-ten-board-set");
const RELEASE_BINDING_DIGEST = ethers.id("p42-release-binding-v2");
const AUTHORIZATION_DIGEST = ethers.id("p42-production-launch-authorization");
const ROLES = {
  productionLaunch: ethers.id("production-launch-authority"),
  independentSecurity: ethers.id("independent-security-authority"),
  governance: ethers.id("governance-authority"),
};
const TYPES = {
  FundingAuthorization: [
    { name: "role", type: "bytes32" },
    { name: "boardSetDigest", type: "bytes32" },
    { name: "releaseBindingDigest", type: "bytes32" },
    { name: "authorizationDigest", type: "bytes32" },
    { name: "expiresAt", type: "uint64" },
    { name: "nonce", type: "uint256" },
  ],
};
const SECP256K1_ORDER = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

function findErrorData(value) {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string") return /^0x[0-9a-fA-F]+$/.test(value) ? value : undefined;
  if (typeof value !== "object") return undefined;
  if (typeof value.data === "string" && /^0x[0-9a-fA-F]+$/.test(value.data)) return value.data;
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

async function fixture(overrides = {}) {
  const [owner, treasury, productionLaunch, independentSecurity, governance, outsider, pool, ledger] =
    await ethers.getSigners();
  const Factory = await ethers.getContractFactory("P42SubmissionManagerFactory");
  const Manager = await ethers.getContractFactory("P42SubmissionManager");
  const ObjectiveVerifier = await ethers.getContractFactory("MockObjectiveVerifierGateway");
  const objectiveVerifier = await ObjectiveVerifier.deploy();
  await objectiveVerifier.waitForDeployment();
  const objectiveVerifierAddress = await objectiveVerifier.getAddress();
  const objectiveVerifierCodehash = ethers.keccak256(await ethers.provider.getCode(objectiveVerifierAddress));
  const factory = await Factory.deploy();
  await factory.waitForDeployment();
  const parameters = {
    deployment: {
      pool: pool.address,
      ledger: ledger.address,
      owner: owner.address,
      treasury: treasury.address,
      alphaBps: 200,
      minPostingBondWei: 1,
      challengeWindowSeconds: CHALLENGE_WINDOW,
      onchainDa: false,
      maxSolutionBytes: 0,
      seedScoreAtoms: 1_000_000,
      minImprovementAtoms: 1,
    },
    fundingAuthorization: {
      boardSetDigest: BOARD_SET_DIGEST,
      releaseBindingDigest: RELEASE_BINDING_DIGEST,
      objectiveVerifier: objectiveVerifierAddress,
      objectiveVerifierCodehash,
      productionLaunchAuthority: productionLaunch.address,
      independentSecurityAuthority: independentSecurity.address,
      governanceAuthority: governance.address,
    },
    ...overrides,
  };
  const tx = await factory.deploySubmissionManager(
    ethers.id(`manager-${crypto.randomUUID()}`), parameters, Manager.bytecode,
  );
  const receipt = await tx.wait();
  const deployed = receipt.logs.map((log) => {
    try { return factory.interface.parseLog(log); } catch { return null; }
  }).find((log) => log?.name === "CanonicalSubmissionManagerDeployed");
  assert.ok(deployed);
  const manager = Manager.attach(deployed.args.submissionManager);
  return {
    owner, treasury, productionLaunch, independentSecurity, governance, outsider,
    factory, manager, objectiveVerifier, parameters, managerCreationCode: Manager.bytecode,
  };
}

async function signatures(f, authorizationDigest, expiresAt, nonce, overrides = {}) {
  const networkInfo = await ethers.provider.getNetwork();
  const domain = {
    name: "P42SubmissionManager",
    version: "2",
    chainId: overrides.chainId ?? networkInfo.chainId,
    verifyingContract: overrides.verifyingContract ?? await f.manager.getAddress(),
  };
  const common = {
    boardSetDigest: overrides.boardSetDigest ?? BOARD_SET_DIGEST,
    releaseBindingDigest: overrides.releaseBindingDigest ?? RELEASE_BINDING_DIGEST,
    authorizationDigest,
    expiresAt,
    nonce,
  };
  return {
    productionLaunch: await f.productionLaunch.signTypedData(domain, TYPES, {
      ...common, role: overrides.productionLaunchRole ?? ROLES.productionLaunch,
    }),
    independentSecurity: await f.independentSecurity.signTypedData(domain, TYPES, {
      ...common, role: overrides.independentSecurityRole ?? ROLES.independentSecurity,
    }),
    governance: await f.governance.signTypedData(domain, TYPES, {
      ...common, role: overrides.governanceRole ?? ROLES.governance,
    }),
  };
}

function authorize(manager, treasury, digest, expiresAt, nonce, signed) {
  return manager.connect(treasury).authorizeFunding(
    digest, expiresAt, nonce, [signed.productionLaunch, signed.independentSecurity, signed.governance],
  );
}

function withHighS(signature) {
  const parsed = ethers.Signature.from(signature);
  const highS = SECP256K1_ORDER - BigInt(parsed.s);
  const v = parsed.v === 27 ? 28 : 27;
  return ethers.concat([parsed.r, ethers.toBeHex(highS, 32), ethers.toBeHex(v, 1)]);
}

describe("P42 production funding authorization v2", function () {
  it("verifies all three role-bound signatures through the treasury relayer and preserves timelock arming", async function () {
    const f = await fixture();
    const latest = await ethers.provider.getBlock("latest");
    const expiresAt = BigInt(latest.timestamp) + 1_000n;
    const signed = await signatures(f, AUTHORIZATION_DIGEST, expiresAt, 0n);

    await expectCustomError(
      authorize(f.manager, f.outsider, AUTHORIZATION_DIGEST, expiresAt, 0n, signed),
      f.manager,
      "P42_NOT_FUNDING_AUTHORIZER",
    );
    const authorizationTx = await authorize(
      f.manager, f.treasury, AUTHORIZATION_DIGEST, expiresAt, 0n, signed,
    );
    const authorizationReceipt = await authorizationTx.wait();
    const verified = authorizationReceipt.logs.map((log) => {
      try { return f.manager.interface.parseLog(log); } catch { return null; }
    }).find((log) => log?.name === "FundingAuthorizationVerified");
    assert.ok(verified);
    assert.equal(verified.args.authorizationDigest, AUTHORIZATION_DIGEST);
    assert.equal(verified.args.nonce, 0n);
    assert.equal(verified.args.boardSetDigest, BOARD_SET_DIGEST);
    assert.equal(verified.args.releaseBindingDigest, RELEASE_BINDING_DIGEST);
    assert.equal(await f.manager.authorizedFundingDigest(), AUTHORIZATION_DIGEST);
    assert.equal(await f.manager.fundingAuthorizationNonce(), 1n);
    assert.equal(await f.manager.boardSetDigest(), BOARD_SET_DIGEST);
    assert.equal(await f.manager.releaseBindingDigest(), RELEASE_BINDING_DIGEST);

    await expectCustomError(
      f.manager.connect(f.treasury).armFunding(AUTHORIZATION_DIGEST),
      f.manager,
      "P42_NOT_OWNER",
    );
    await ethers.provider.send("evm_increaseTime", [Number(CHALLENGE_WINDOW + 1n)]);
    await ethers.provider.send("evm_mine", []);
    await f.manager.connect(f.owner).armFunding(AUTHORIZATION_DIGEST);
    assert.equal(await f.manager.fundingArmed(), true);
  });

  it("binds chain, manager, exact-ten set, release, role, digest, expiry, and exact nonce", async function () {
    const cases = [
      { chainId: 1n },
      { verifyingContract: ethers.Wallet.createRandom().address },
      { boardSetDigest: ethers.id("other-board-set") },
      { releaseBindingDigest: ethers.id("other-release") },
      { productionLaunchRole: ROLES.independentSecurity },
    ];
    for (const override of cases) {
      const f = await fixture();
      const latest = await ethers.provider.getBlock("latest");
      const expiresAt = BigInt(latest.timestamp) + 1_000n;
      const signed = await signatures(f, AUTHORIZATION_DIGEST, expiresAt, 0n, override);
      await expectCustomError(
        authorize(f.manager, f.treasury, AUTHORIZATION_DIGEST, expiresAt, 0n, signed),
        f.manager,
        "P42_INVALID_FUNDING_SIGNATURE",
      );
    }

    const f = await fixture();
    const latest = await ethers.provider.getBlock("latest");
    const expiresAt = BigInt(latest.timestamp) + 1_000n;
    const signed = await signatures(f, AUTHORIZATION_DIGEST, expiresAt, 0n);
    await expectCustomError(
      authorize(f.manager, f.treasury, ethers.id("other-authorization"), expiresAt, 0n, signed),
      f.manager,
      "P42_INVALID_FUNDING_SIGNATURE",
    );
    await expectCustomError(
      authorize(f.manager, f.treasury, AUTHORIZATION_DIGEST, expiresAt, 1n, signed),
      f.manager,
      "P42_FUNDING_AUTHORIZATION_NONCE",
    );
    await expectCustomError(
      authorize(f.manager, f.treasury, AUTHORIZATION_DIGEST, BigInt(latest.timestamp) - 1n, 0n, signed),
      f.manager,
      "P42_FUNDING_AUTHORIZATION_EXPIRED",
    );
  });

  it("rejects short, invalid-v, and high-s signatures", async function () {
    for (const mutation of [
      (signature) => signature.slice(0, -2),
      (signature) => `${signature.slice(0, -2)}1d`,
      withHighS,
    ]) {
      const f = await fixture();
      const latest = await ethers.provider.getBlock("latest");
      const expiresAt = BigInt(latest.timestamp) + 1_000n;
      const signed = await signatures(f, AUTHORIZATION_DIGEST, expiresAt, 0n);
      signed.productionLaunch = mutation(signed.productionLaunch);
      await expectCustomError(
        authorize(f.manager, f.treasury, AUTHORIZATION_DIGEST, expiresAt, 0n, signed),
        f.manager,
        "P42_INVALID_FUNDING_SIGNATURE",
      );
    }
  });

  it("consumes a nonce on cancellation so a pre-signed replacement cannot replay", async function () {
    const f = await fixture();
    const latest = await ethers.provider.getBlock("latest");
    const expiresAt = BigInt(latest.timestamp) + 1_000n;
    const initial = await signatures(f, AUTHORIZATION_DIGEST, expiresAt, 0n);
    await authorize(f.manager, f.treasury, AUTHORIZATION_DIGEST, expiresAt, 0n, initial);

    const replacementDigest = ethers.id("pre-signed-replacement");
    const replacement = await signatures(f, replacementDigest, expiresAt, 1n);
    await f.manager.connect(f.owner).cancelFundingAuthorization(AUTHORIZATION_DIGEST);
    assert.equal(await f.manager.fundingAuthorizationNonce(), 2n);
    await expectCustomError(
      authorize(f.manager, f.treasury, replacementDigest, expiresAt, 1n, replacement),
      f.manager,
      "P42_FUNDING_AUTHORIZATION_NONCE",
    );
    await expectCustomError(
      authorize(f.manager, f.treasury, AUTHORIZATION_DIGEST, expiresAt, 0n, initial),
      f.manager,
      "P42_FUNDING_AUTHORIZATION_NONCE",
    );
  });

  it("permits replacement only after expiry and refuses cancellation of an expired authorization", async function () {
    const f = await fixture();
    const latest = await ethers.provider.getBlock("latest");
    const expiresAt = BigInt(latest.timestamp) + 10n;
    const initial = await signatures(f, AUTHORIZATION_DIGEST, expiresAt, 0n);
    await authorize(f.manager, f.treasury, AUTHORIZATION_DIGEST, expiresAt, 0n, initial);

    await ethers.provider.send("evm_setNextBlockTimestamp", [Number(expiresAt + 1n)]);
    await ethers.provider.send("evm_mine", []);
    await expectCustomError(
      f.manager.connect(f.owner).cancelFundingAuthorization(AUTHORIZATION_DIGEST),
      f.manager,
      "P42_FUNDING_AUTHORIZATION_NOT_ACTIVE",
    );

    const replacementDigest = ethers.id("post-expiry-replacement");
    const replacementExpiresAt = expiresAt + 1_000n;
    const replacement = await signatures(f, replacementDigest, replacementExpiresAt, 1n);
    await authorize(f.manager, f.treasury, replacementDigest, replacementExpiresAt, 1n, replacement);
    assert.equal(await f.manager.authorizedFundingDigest(), replacementDigest);
    assert.equal(await f.manager.fundingAuthorizationNonce(), 2n);
  });

  it("rejects zero bindings and non-distinct signing authorities", async function () {
    const valid = await fixture();
    const Manager = await ethers.getContractFactory("P42SubmissionManager");
    await expectCustomError(
      Manager.deploy(valid.parameters.deployment, {
        ...valid.parameters.fundingAuthorization, boardSetDigest: ethers.ZeroHash,
      }),
      valid.manager,
      "P42_FUNDING_BINDING_ZERO",
    );
    await expectCustomError(
      Manager.deploy(valid.parameters.deployment, {
        ...valid.parameters.fundingAuthorization, objectiveVerifier: ethers.ZeroAddress,
      }),
      valid.manager,
      "P42_OBJECTIVE_VERIFIER_ZERO",
    );
    await expectCustomError(
      Manager.deploy(valid.parameters.deployment, {
        ...valid.parameters.fundingAuthorization, objectiveVerifierCodehash: ethers.id("wrong-runtime"),
      }),
      valid.manager,
      "P42_OBJECTIVE_VERIFIER_RUNTIME",
    );
    await expectCustomError(
      Manager.deploy(valid.parameters.deployment, {
        ...valid.parameters.fundingAuthorization,
        independentSecurityAuthority: valid.productionLaunch.address,
      }),
      valid.manager,
      "P42_FUNDING_AUTHORITIES_NOT_DISTINCT",
    );
    await expectCustomError(
      Manager.deploy(valid.parameters.deployment, {
        ...valid.parameters.fundingAuthorization, governanceAuthority: ethers.ZeroAddress,
      }),
      valid.manager,
      "P42_FUNDING_AUTHORITY_ZERO",
    );
    await expectCustomError(
      Manager.deploy(valid.parameters.deployment, {
        ...valid.parameters.fundingAuthorization,
        governanceAuthority: await valid.factory.getAddress(),
      }),
      valid.manager,
      "P42_FUNDING_AUTHORITY_NOT_EOA",
    );
    for (const authorityField of [
      "productionLaunchAuthority", "independentSecurityAuthority", "governanceAuthority",
    ]) {
      for (const authority of [valid.owner.address, valid.treasury.address]) {
        await expectCustomError(
          Manager.deploy(valid.parameters.deployment, {
            ...valid.parameters.fundingAuthorization, [authorityField]: authority,
          }),
          valid.manager,
          "P42_FUNDING_AUTHORITIES_NOT_DISTINCT",
        );
      }
    }
  });

  it("keeps the inactive production proof topology non-fundable even with every valid authority signature", async function () {
    const valid = await fixture();
    const Manager = await ethers.getContractFactory("P42SubmissionManager");
    const Gateway = await ethers.getContractFactory("P42SP1VerifierGateway");
    const gateway = await Gateway.deploy();
    await gateway.waitForDeployment();
    const gatewayAddress = await gateway.getAddress();
    const manager = await Manager.deploy(valid.parameters.deployment, {
      ...valid.parameters.fundingAuthorization,
      objectiveVerifier: gatewayAddress,
      objectiveVerifierCodehash: ethers.keccak256(await ethers.provider.getCode(gatewayAddress)),
    });
    await manager.waitForDeployment();
    const f = { ...valid, manager };
    const latest = await ethers.provider.getBlock("latest");
    const expiresAt = BigInt(latest.timestamp) + 1_000n;
    const signed = await signatures(f, AUTHORIZATION_DIGEST, expiresAt, 0n);

    assert.equal(await manager.objectiveProofCapabilityActive(), false);
    await expectCustomError(
      authorize(manager, valid.treasury, AUTHORIZATION_DIGEST, expiresAt, 0n, signed),
      manager,
      "P42_OBJECTIVE_PROOF_CAPABILITY_INACTIVE",
    );
    assert.equal(await manager.authorizedFundingDigest(), ethers.ZeroHash);
    assert.equal(await manager.fundingAuthorizationNonce(), 0n);
    assert.equal(await manager.fundingArmed(), false);
  });

  it("treats reverting and malformed capability probes as inactive without state changes", async function () {
    for (const contractName of ["RevertingObjectiveProofCapability", "MalformedObjectiveProofCapability"]) {
      const valid = await fixture();
      const Manager = await ethers.getContractFactory("P42SubmissionManager");
      const Capability = await ethers.getContractFactory(contractName);
      const capability = await Capability.deploy();
      await capability.waitForDeployment();
      const capabilityAddress = await capability.getAddress();
      const manager = await Manager.deploy(valid.parameters.deployment, {
        ...valid.parameters.fundingAuthorization,
        objectiveVerifier: capabilityAddress,
        objectiveVerifierCodehash: ethers.keccak256(await ethers.provider.getCode(capabilityAddress)),
      });
      await manager.waitForDeployment();
      const f = { ...valid, manager };
      const latest = await ethers.provider.getBlock("latest");
      const expiresAt = BigInt(latest.timestamp) + 1_000n;
      const signed = await signatures(f, AUTHORIZATION_DIGEST, expiresAt, 0n);

      assert.equal(await manager.objectiveProofCapabilityActive(), false);
      await expectCustomError(
        authorize(manager, valid.treasury, AUTHORIZATION_DIGEST, expiresAt, 0n, signed),
        manager,
        "P42_OBJECTIVE_PROOF_CAPABILITY_INACTIVE",
      );
      assert.equal(await manager.authorizedFundingDigest(), ethers.ZeroHash);
      assert.equal(await manager.fundingAuthorizationNonce(), 0n);
    }
  });

  it("pins externally supplied manager creation code in the compact CREATE2 factory", async function () {
    const valid = await fixture();
    assert.equal(
      await valid.factory.MANAGER_CREATION_CODE_HASH(),
      ethers.keccak256(valid.managerCreationCode),
    );
    await expectCustomError(
      valid.factory.deploySubmissionManager(
        ethers.id("wrong-manager-code"), valid.parameters, `${valid.managerCreationCode}00`,
      ),
      valid.factory,
      "P42_FACTORY_BAD_MANAGER_CREATION_CODE",
    );
  });
});
