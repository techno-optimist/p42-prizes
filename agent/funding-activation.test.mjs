import assert from "node:assert/strict";
import { test } from "node:test";
import { ethers } from "ethers";
import { chmodSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildFundingActivationPlan, runProductionAuthorizationValidator, serializeFundingActivationPlan, writePrivateActivationPlan } from "./funding-activation.mjs";
import {
  assertCanonicalActivationPlanArtifact,
  buildActivationRpcProviders,
  destroyActivationRpcProviders,
} from "./funding-activation-run.mjs";
import { sha256Canonical } from "./lib.mjs";

const hash = (char) => `sha256:${char.repeat(64)}`;
const rpcAuthority = () => ({
  schema: "p42-activation-rpc-authority/v1", registryDigest: hash("9"),
  primary: { operatorId: "operator-primary", endpointOrigin: "https://primary.example", endpointProfileDigest: sha256Canonical({ operatorId: "operator-primary", endpointOrigin: "https://primary.example" }) },
  secondary: { operatorId: "operator-secondary", endpointOrigin: "https://secondary.example", endpointProfileDigest: sha256Canonical({ operatorId: "operator-secondary", endpointOrigin: "https://secondary.example" }) },
});
const rpcRegistry = () => ({ schema: "p42-activation-rpc-operator-registry/v1", registryDigest: hash("9"), profiles: [rpcAuthority().primary, rpcAuthority().secondary] });
const address = (value) => ethers.getAddress(`0x${value.toString(16).padStart(40, "0")}`);
const authorityWallets = ["1", "2", "3"].map((char) => new ethers.Wallet(`0x${char.repeat(64)}`));
const roles = ["production-launch-authority", "independent-security-authority", "governance-authority"];
const fundingTypes = { FundingAuthorization: [
  { name: "role", type: "bytes32" }, { name: "boardSetDigest", type: "bytes32" },
  { name: "releaseBindingDigest", type: "bytes32" }, { name: "authorizationDigest", type: "bytes32" },
  { name: "expiresAt", type: "uint64" }, { name: "nonce", type: "uint256" },
] };

test("activation runner providers probe raw chain IDs before static construction", async () => {
  const transport = async (request) => ({
    statusCode: 200, statusMessage: "OK", headers: { "content-type": "application/json" },
    body: Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x14a34" })),
  });
  await assert.rejects(
    () => buildActivationRpcProviders(rpcRegistry(), rpcAuthority(), "https://rpc.example", "https://rpc.example.", 84532, { primary: transport, secondary: transport }),
    /origins|hostname|distinct HTTPS RPC origins and hosts|aliases are forbidden/,
  );
  const providers = await buildActivationRpcProviders(
    rpcRegistry(), rpcAuthority(), "https://primary.example", "https://secondary.example", 84532,
    { primary: transport, secondary: transport },
  );
  try {
    assert.equal(
      providers.primary._getConnection().clone().getUrlFunc,
      providers.primary._getConnection().getUrlFunc,
    );
    assert.equal(
      providers.secondary._getConnection().clone().getUrlFunc,
      providers.secondary._getConnection().getUrlFunc,
    );
    assert.equal(providers.endpoints.primary.url, "https://primary.example");
    assert.equal(providers.endpoints.secondary.url, "https://secondary.example");
    assert.equal(providers.authority.primary.observedRawChainId, "0x14a34");
  } finally {
    providers.primary.destroy();
    providers.secondary.destroy();
  }
});

test("activation RPC provider cleanup attempts both providers when one destroy fails", async () => {
  const destroyed = [];
  await destroyActivationRpcProviders({
    primary: {
      destroy() {
        destroyed.push("primary");
        throw new Error("primary cleanup failed");
      },
    },
    secondary: {
      destroy() {
        destroyed.push("secondary");
      },
    },
  });
  assert.deepEqual(destroyed, ["primary", "secondary"]);
});

function manifest() {
  return {
    schema: "p42-prizes/deployment-manifest/v2",
    releaseMode: "production",
    status: "governance-setup-complete",
    network: { name: "baseSepolia", chainId: 84532 },
    deploymentCommit: "a".repeat(40),
    deploymentConfigHash: `0x${"b".repeat(64)}`,
    roles: {
      owner: address(1), treasury: address(2), productionLaunchAuthority: authorityWallets[0].address,
      independentSecurityAuthority: authorityWallets[1].address, governanceAuthority: authorityWallets[2].address,
    },
    governance: {
      signers: [address(3), address(4), address(5)], threshold: "2",
      delaySeconds: "3600", operationGracePeriodSeconds: "604800",
    },
    contracts: {
      timelock: { address: address(1), runtimeCodeHash: `0x${"1".repeat(64)}` },
      registry: { address: address(6) },
      rolloverVault: { address: address(7) },
      submissionManagerFactory: { address: address(8) },
      challengeManagerFactory: { address: address(9) },
      objectiveVerifier: { address: address(10) },
      resolverQuorum: { address: address(11) },
    },
    releaseEvidence: {
      releaseBindingDigest: hash("1"), boardSetDigest: hash("0"), capsuleDigest: hash("2"),
      slateDigest: hash("3"), releaseIndexDigest: hash("4"),
    },
    problems: Array.from({ length: 10 }, (_, index) => ({
      problemId: index + 1,
      problemSlug: `problem-${index + 1}`,
      contracts: {
        pool: { address: address(100 + index * 4), runtimeCodeHash: `0x${"2".repeat(64)}` },
        ledger: { address: address(101 + index * 4) },
        submissions: { address: address(102 + index * 4), runtimeCodeHash: `0x${"3".repeat(64)}` },
        challenges: { address: address(103 + index * 4) },
      },
    })),
  };
}

function signatureBundle(inputManifest, auth = authorization(inputManifest)) {
  const expiresAt = String(Math.floor(Date.parse(auth.expires_at_utc) / 1000));
  const common = {
    boardSetDigest: `0x${inputManifest.releaseEvidence.boardSetDigest.slice(7)}`,
    releaseBindingDigest: `0x${inputManifest.releaseEvidence.releaseBindingDigest.slice(7)}`,
    authorizationDigest: `0x${auth.authorization_digest.slice(7)}`,
    expiresAt: BigInt(expiresAt), nonce: 0n,
  };
  return {
    schema: "p42-funding-activation-signatures/v2", chainId: inputManifest.network.chainId,
    boardSetDigest: inputManifest.releaseEvidence.boardSetDigest,
    releaseBindingDigest: inputManifest.releaseEvidence.releaseBindingDigest,
    authorizationDigest: auth.authorization_digest, expiresAt,
    authorities: {
      productionLaunchAuthority: authorityWallets[0].address,
      independentSecurityAuthority: authorityWallets[1].address,
      governanceAuthority: authorityWallets[2].address,
    },
    boards: inputManifest.problems.map((problem, boardIndex) => {
      const submissionManager = problem.contracts.submissions.address;
      const domain = { name: "P42SubmissionManager", version: "2", chainId: inputManifest.network.chainId, verifyingContract: submissionManager };
      return {
        boardIndex, problemId: problem.problemId, submissionManager, nonce: "0",
        signatures: roles.map((role, roleIndex) => ({
          role, signer: authorityWallets[roleIndex].address,
          signature: ethers.Signature.from(authorityWallets[roleIndex].signingKey.sign(
            ethers.TypedDataEncoder.hash(domain, fundingTypes, { ...common, role: ethers.id(role) }),
          )).serialized,
        })),
      };
    }),
  };
}

function authorization(inputManifest, manifestBytesDigest = hash("e")) {
  return {
    schema_version: "p42-production-launch-authorization/v1",
    status: "authorized",
    authorization_digest: hash("a"),
    expires_at_utc: "2030-01-01T00:00:00Z",
    release_binding: {
      network: "base-sepolia", chain_id: 84532,
      deployment_commit: inputManifest.deploymentCommit,
      git_commit: "f".repeat(40),
    },
    artifacts: {
      deployment_manifest: { sha256: manifestBytesDigest },
      activation_rpc_operator_registry: { sha256: hash("9") },
    },
  };
}

test("activation plan binds ten treasury authorizations before governance opens pools", () => {
  const deployment = manifest();
  const auth = authorization(deployment);
  const plan = buildFundingActivationPlan({
    manifest: deployment,
    manifestBytesDigest: hash("e"),
    validatedAuthorization: { value: auth, validatedBytesDigest: hash("d"), dependencySecurityReportDigest: hash("8") },
    rpcRegistry: rpcRegistry(),
    rpcAuthority: rpcAuthority(), activationSignatures: signatureBundle(deployment, auth), manifestValidator: () => ({}),
  });
  assert.equal(plan.boardCount, 10);
  assert.equal(plan.operations.length, 30);
  assert.deepEqual(plan.operations.map((row) => row.authority), [
    ...Array(10).fill("treasury"), ...Array(20).fill("governance"),
  ]);
  const authorizeLabels = plan.operations.slice(0, 10).map((row) => row.label);
  const armLabels = plan.operations.slice(10, 20).map((row) => row.label);
  for (let index = 0; index < 10; index += 1) {
    const authorize = plan.operations[index];
    const arm = plan.operations[index + 10];
    const open = plan.operations[index + 20];
    assert.deepEqual(arm.dependsOn, authorizeLabels);
    assert.deepEqual(open.dependsOn, armLabels);
    const decoded = new ethers.Interface([
      "function authorizeFunding(bytes32,uint64,uint256,bytes[3])",
    ]).decodeFunctionData("authorizeFunding", authorize.data);
    assert.equal(decoded[0], `0x${"a".repeat(64)}`);
    assert.equal(decoded[2], 0n);
    assert.equal(decoded[3].length, 3);
    assert.equal(authorize.verifiedSignatureCount, 3);
    assert.equal(arm.data.slice(-64), "a".repeat(64));
  }
});

test("activation run rejects caller plan replacement and noncanonical bytes", () => {
  const deployment = manifest();
  const auth = authorization(deployment);
  const plan = buildFundingActivationPlan({
    manifest: deployment, manifestBytesDigest: hash("e"),
    validatedAuthorization: { value: auth, validatedBytesDigest: hash("d"), dependencySecurityReportDigest: hash("8") },
    rpcRegistry: rpcRegistry(),
    rpcAuthority: rpcAuthority(), activationSignatures: signatureBundle(deployment, auth), manifestValidator: () => ({}),
  });
  assert.equal(assertCanonicalActivationPlanArtifact({ value: plan, bytes: serializeFundingActivationPlan(plan) }, plan), plan);
  const replacement = { ...plan, treasury: address(999) };
  assert.throws(
    () => assertCanonicalActivationPlanArtifact({ value: replacement, bytes: serializeFundingActivationPlan(replacement) }, plan),
    /exact freshly reconstructed canonical plan/,
  );
  assert.throws(
    () => assertCanonicalActivationPlanArtifact({ value: plan, bytes: Buffer.from(JSON.stringify(plan)) }, plan),
    /exact freshly reconstructed canonical plan/,
  );
});

test("activation rejects release substitution and incomplete topology", () => {
  const deployment = manifest();
  const auth = authorization(deployment);
  auth.release_binding.deployment_commit = "9".repeat(40);
  assert.throws(() => buildFundingActivationPlan({ manifest: deployment, manifestBytesDigest: hash("e"), validatedAuthorization: { value: auth, validatedBytesDigest: hash("d"), dependencySecurityReportDigest: hash("8") }, rpcRegistry: rpcRegistry(), rpcAuthority: rpcAuthority(), activationSignatures: signatureBundle(deployment, auth), manifestValidator: () => ({}) }), /deployment_commit/);
  deployment.problems.pop();
  assert.throws(() => buildFundingActivationPlan({ manifest: deployment, manifestBytesDigest: hash("e"), validatedAuthorization: { value: authorization(deployment), validatedBytesDigest: hash("d"), dependencySecurityReportDigest: hash("8") }, rpcRegistry: rpcRegistry(), rpcAuthority: rpcAuthority(), activationSignatures: { schema: "p42-funding-activation-signatures/v2" }, manifestValidator: () => ({}) }), /exactly ten/);
});

test("activation accepts a descendant evidence commit without granting it deployment authority", () => {
  const deployment = manifest();
  const auth = authorization(deployment);
  auth.release_binding.git_commit = "9".repeat(40);
  const plan = buildFundingActivationPlan({
    manifest: deployment,
    manifestBytesDigest: hash("e"),
    validatedAuthorization: { value: auth, validatedBytesDigest: hash("d"), dependencySecurityReportDigest: hash("8") },
    rpcRegistry: rpcRegistry(),
    rpcAuthority: rpcAuthority(),
    activationSignatures: signatureBundle(deployment, auth),
    manifestValidator: () => ({}),
  });
  assert.equal(plan.deploymentCommit, deployment.deploymentCommit);
});

test("activation rejects a legacy 43-contract authorization path", () => {
  const deployment = manifest();
  delete deployment.contracts.submissionManagerFactory;
  delete deployment.contracts.challengeManagerFactory;
  delete deployment.contracts.objectiveVerifier;
  delete deployment.contracts.resolverQuorum;
  let historicalValidatorCalled = false;
  assert.throws(() => buildFundingActivationPlan({
    manifest: deployment,
    manifestBytesDigest: hash("e"),
    validatedAuthorization: { value: authorization(deployment), validatedBytesDigest: hash("d"), dependencySecurityReportDigest: hash("8") },
    rpcRegistry: rpcRegistry(),
    rpcAuthority: rpcAuthority(),
    activationSignatures: signatureBundle(deployment),
    manifestValidator: () => { historicalValidatorCalled = true; },
  }), /exact seven ordered shared contracts/);
  assert.equal(historicalValidatorCalled, false);
});

test("activation fails closed on legacy, reordered, high-s, forged, and incomplete signature bundles", () => {
  const deployment = manifest();
  const auth = authorization(deployment);
  const build = (bundle) => buildFundingActivationPlan({
    manifest: deployment, manifestBytesDigest: hash("e"),
    validatedAuthorization: { value: auth, validatedBytesDigest: hash("d"), dependencySecurityReportDigest: hash("8") },
    rpcRegistry: rpcRegistry(),
    rpcAuthority: rpcAuthority(),
    activationSignatures: bundle, manifestValidator: () => ({}),
  });
  const legacy = signatureBundle(deployment, auth); legacy.schema = "p42-funding-activation-signatures/v1";
  assert.throws(() => build(legacy), /legacy or unknown/);
  const reordered = signatureBundle(deployment, auth);
  [reordered.boards[0].signatures[0], reordered.boards[0].signatures[1]] = [reordered.boards[0].signatures[1], reordered.boards[0].signatures[0]];
  assert.throws(() => build(reordered), /role order or signer/);
  const highS = signatureBundle(deployment, auth);
  const parsed = ethers.Signature.from(highS.boards[0].signatures[0].signature);
  const high = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n - BigInt(parsed.s);
  highS.boards[0].signatures[0].signature = ethers.concat([parsed.r, ethers.toBeHex(high, 32), ethers.toBeHex(parsed.v === 27 ? 28 : 27, 1)]);
  assert.throws(() => build(highS), /low-s\/v/);
  const forged = signatureBundle(deployment, auth);
  forged.boards[0].signatures[0].signature = forged.boards[1].signatures[0].signature;
  assert.throws(() => build(forged), /recovered signer/);
  const incomplete = signatureBundle(deployment, auth); incomplete.boards.pop();
  assert.throws(() => build(incomplete), /exactly ten/);
  const aliased = signatureBundle(deployment, auth);
  deployment.roles.productionLaunchAuthority = deployment.roles.treasury;
  aliased.authorities.productionLaunchAuthority = deployment.roles.treasury;
  assert.throws(() => build(aliased), /distinct from treasury and owner/);
});

test("activation signature bundle binds chain, managers, release digests, expiry, and nonce", () => {
  const deployment = manifest();
  const auth = authorization(deployment);
  const build = (bundle) => buildFundingActivationPlan({
    manifest: deployment, manifestBytesDigest: hash("e"),
    validatedAuthorization: { value: auth, validatedBytesDigest: hash("d"), dependencySecurityReportDigest: hash("8") },
    rpcRegistry: rpcRegistry(),
    rpcAuthority: rpcAuthority(),
    activationSignatures: bundle, manifestValidator: () => ({}),
  });
  for (const [mutate, message] of [
    [(bundle) => { bundle.chainId = 8453; }, /chain/],
    [(bundle) => { bundle.boardSetDigest = hash("9"); }, /boardSetDigest/],
    [(bundle) => { bundle.releaseBindingDigest = hash("9"); }, /releaseBindingDigest/],
    [(bundle) => { bundle.authorizationDigest = hash("9"); }, /authorizationDigest/],
    [(bundle) => { bundle.expiresAt = "1"; }, /expiry/],
    [(bundle) => { bundle.boards[0].submissionManager = address(999); }, /ordered manifest board/],
    [(bundle) => { bundle.boards[0].nonce = "1"; }, /recovered signer/],
  ]) {
    const bundle = signatureBundle(deployment, auth);
    mutate(bundle);
    assert.throws(() => build(bundle), message);
  }
});

test("validator invocation is argv-only, bounded, and rejects nonzero exit", () => {
  let observed;
  let calls = 0;
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-sp1-validator-")));
  const reportPath = join(root, "report.json");
  const reportBytes = Buffer.from(`${JSON.stringify({
    schema: "p42-objective-dependency-security-report/v1",
    result: "pass",
    summary: { highFindings: 0, findings: 0, trackedLockfiles: 7, sp1Lockfiles: 4 },
  }, null, 2)}\n`);
  writeFileSync(reportPath, reportBytes);
  process.env.P42_FUNDING_TREASURY_PRIVATE_KEY = `0x${"7".repeat(64)}`;
  const fake = (executable, args, options) => {
    observed = { executable, args, options };
    calls += 1;
    if (calls === 1) return { status: 0, stdout: reportBytes, stderr: Buffer.alloc(0) };
    return { status: 1, stdout: Buffer.alloc(0), stderr: Buffer.from("rejected") };
  };
  assert.throws(() => runProductionAuthorizationValidator({
    python: process.execPath,
    repoRoot: realpathSync(join(process.cwd(), "..")),
    authorizationPath: new URL("./package.json", import.meta.url).pathname,
    trustRegistryPath: new URL("./package.json", import.meta.url).pathname,
    artifactRoot: process.cwd(),
    sp1SecurityReportPath: reportPath,
    chainRpcUrl: "https://rpc.example",
    spawn: fake,
  }), /rejected/);
  assert.equal(observed.options.shell, false);
  assert.equal(observed.options.maxBuffer, 32 * 1024 * 1024);
  assert.equal(observed.options.timeout, 15 * 60 * 1000);
  assert.equal(observed.options.killSignal, "SIGKILL");
  assert.equal(observed.options.env.P42_FUNDING_TREASURY_PRIVATE_KEY, undefined);
  assert.deepEqual(
    Object.keys(observed.options.env).filter((name) => name !== "PYTHONPATH").sort(),
    ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR"].filter((name) => process.env[name] !== undefined).sort(),
  );
  delete process.env.P42_FUNDING_TREASURY_PRIVATE_KEY;
  assert.ok(observed.args.includes("production-launch-authorization-validate"));
});

test("launch authorization validation fails closed on blocked or changed SP1 report", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-sp1-validator-")));
  const reportPath = join(root, "report.json");
  const report = {
    schema: "p42-objective-dependency-security-report/v1",
    result: "blocked",
    summary: { highFindings: 4, findings: 12, trackedLockfiles: 7, sp1Lockfiles: 4 },
  };
  const bytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
  writeFileSync(reportPath, bytes);
  const args = {
    python: process.execPath, repoRoot: realpathSync(join(process.cwd(), "..")),
    authorizationPath: new URL("./package.json", import.meta.url).pathname,
    trustRegistryPath: new URL("./package.json", import.meta.url).pathname,
    artifactRoot: process.cwd(), sp1SecurityReportPath: reportPath,
    chainRpcUrl: "https://rpc.example",
  };
  assert.throws(() => runProductionAuthorizationValidator({
    ...args,
    spawn: () => ({ status: 1, stdout: bytes, stderr: Buffer.alloc(0) }),
  }), /blocks production launch authorization/);
  assert.throws(() => runProductionAuthorizationValidator({
    ...args,
    spawn: () => ({ status: 0, stdout: Buffer.from(bytes.toString().replace('"blocked"', '"pass"')), stderr: Buffer.alloc(0) }),
  }), /missing, changed, or not the exact fresh scanner output/);
});

test("activation plan output is immutable, private, and rejects aliases", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-")));
  chmodSync(root, 0o700);
  const path = join(root, "plan.json");
  const plan = { schema: "p42-funding-activation-plan/v1", planDigest: hash("1") };
  writePrivateActivationPlan(path, plan);
  writePrivateActivationPlan(path, plan);
  chmodSync(path, 0o644);
  assert.throws(() => writePrivateActivationPlan(path, plan), /private JSON/);

  const target = join(root, "target.json");
  writeFileSync(target, `${JSON.stringify(plan)}\n`, { mode: 0o600 });
  const alias = join(root, "alias.json");
  symlinkSync(target, alias);
  assert.throws(() => writePrivateActivationPlan(alias, plan), /private JSON|symbolic|ELOOP/);
});
