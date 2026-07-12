import assert from "node:assert/strict";
import { test } from "node:test";
import { ethers } from "ethers";
import { chmodSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildFundingActivationPlan, runProductionAuthorizationValidator, writePrivateActivationPlan } from "./funding-activation.mjs";

const hash = (char) => `sha256:${char.repeat(64)}`;
const address = (value) => ethers.getAddress(`0x${value.toString(16).padStart(40, "0")}`);

function manifest() {
  return {
    schema: "p42-prizes/deployment-manifest/v2",
    releaseMode: "production",
    status: "governance-setup-complete",
    network: { name: "baseSepolia", chainId: 84532 },
    deploymentCommit: "a".repeat(40),
    deploymentConfigHash: `0x${"b".repeat(64)}`,
    roles: { treasury: address(2) },
    governance: {
      signers: [address(3), address(4), address(5)], threshold: "2",
      delaySeconds: "3600", operationGracePeriodSeconds: "604800",
    },
    contracts: { timelock: { address: address(1), runtimeCodeHash: `0x${"1".repeat(64)}` } },
    releaseEvidence: {
      releaseBindingDigest: hash("1"), capsuleDigest: hash("2"), slateDigest: hash("3"), releaseIndexDigest: hash("4"),
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

function authorization(inputManifest, manifestBytesDigest = hash("e")) {
  return {
    schema_version: "p42-production-launch-authorization/v1",
    status: "authorized",
    authorization_digest: hash("a"),
    expires_at_utc: "2030-01-01T00:00:00Z",
    release_binding: {
      network: "base-sepolia", chain_id: 84532, git_commit: inputManifest.deploymentCommit,
    },
    artifacts: { deployment_manifest: { sha256: manifestBytesDigest } },
  };
}

test("activation plan binds ten treasury authorizations before governance opens pools", () => {
  const deployment = manifest();
  const auth = authorization(deployment);
  const plan = buildFundingActivationPlan({
    manifest: deployment,
    manifestBytesDigest: hash("e"),
    validatedAuthorization: { value: auth, validatedBytesDigest: hash("d") }, manifestValidator: () => ({}),
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
    assert.equal(authorize.data.slice(10, 74), "a".repeat(64));
    assert.equal(arm.data.slice(-64), "a".repeat(64));
  }
});

test("activation rejects release substitution and incomplete topology", () => {
  const deployment = manifest();
  const auth = authorization(deployment);
  auth.release_binding.git_commit = "9".repeat(40);
  assert.throws(() => buildFundingActivationPlan({ manifest: deployment, manifestBytesDigest: hash("e"), validatedAuthorization: { value: auth, validatedBytesDigest: hash("d") }, manifestValidator: () => ({}) }), /git_commit/);
  deployment.problems.pop();
  assert.throws(() => buildFundingActivationPlan({ manifest: deployment, manifestBytesDigest: hash("e"), validatedAuthorization: { value: authorization(deployment), validatedBytesDigest: hash("d") }, manifestValidator: () => ({}) }), /exactly ten/);
});

test("validator invocation is argv-only, bounded, and rejects nonzero exit", () => {
  let observed;
  process.env.P42_FUNDING_TREASURY_PRIVATE_KEY = `0x${"7".repeat(64)}`;
  const fake = (executable, args, options) => {
    observed = { executable, args, options };
    return { status: 1, stdout: Buffer.alloc(0), stderr: Buffer.from("rejected") };
  };
  assert.throws(() => runProductionAuthorizationValidator({
    python: process.execPath,
    repoRoot: process.cwd(),
    authorizationPath: new URL("./package.json", import.meta.url).pathname,
    trustRegistryPath: new URL("./package.json", import.meta.url).pathname,
    artifactRoot: process.cwd(),
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
