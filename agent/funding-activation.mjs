#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readSync, realpathSync, writeSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { assertCanonicalManifestTopology } from "./canonical-topology.mjs";

import { manifestProblemContracts } from "./indexer.mjs";
import { readStrictJsonFileSync, parseStrictJsonBytes } from "./strict-json.mjs";
import { validateSolverManifest } from "./solver-manifest.mjs";

const LIMITS = Object.freeze({ maxBytes: 32 * 1024 * 1024, maxDepth: 256, trailingNewline: "allow" });
const AUTH_SCHEMA = "p42-production-launch-authorization/v1";
export const ACTIVATION_PLAN_SCHEMA = "p42-funding-activation-plan/v1";

const submissionsInterface = new ethers.Interface([
  "function authorizeFunding(bytes32 authorizationDigest,uint64 expiresAt)",
  "function armFunding(bytes32 authorizationDigest)",
]);
const poolInterface = new ethers.Interface(["function setAcceptingFunds(bool accepting)"]);

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function exactPath(path, label) {
  if (typeof path !== "string" || path.trim() === "") throw new Error(`${label} path is required`);
  const absolute = resolve(path);
  if (realpathSync(absolute) !== absolute) throw new Error(`${label} path must be canonical and may not be a symlink`);
  return absolute;
}

function authorizationBytes32(digest) {
  if (!/^sha256:[0-9a-f]{64}$/.test(digest ?? "")) throw new Error("validated authorization digest is malformed");
  return `0x${digest.slice(7)}`;
}

function assertReleaseBinding(authorization, manifest, manifestBytesDigest) {
  const binding = authorization.release_binding;
  const authorizationNetwork = manifest.network.chainId === 8453 ? "base-mainnet"
    : manifest.network.chainId === 84532 ? "base-sepolia" : null;
  if (!binding || binding.network !== authorizationNetwork || binding.chain_id !== manifest.network.chainId) {
    throw new Error("validated authorization network does not match deployment manifest");
  }
  if (binding.git_commit !== manifest.deploymentCommit) {
    throw new Error("validated authorization git_commit does not match deployment manifest");
  }
  const manifestRef = authorization.artifacts?.deployment_manifest;
  if (manifestRef?.sha256 !== manifestBytesDigest) {
    throw new Error("validated authorization does not bind the exact deployment manifest bytes");
  }
}

export function runProductionAuthorizationValidator({
  python,
  repoRoot,
  authorizationPath,
  trustRegistryPath,
  artifactRoot,
  chainRpcUrl,
  nowUtc = null,
  spawn = spawnSync,
}) {
  const executable = exactPath(python, "python interpreter");
  const root = exactPath(repoRoot, "repository root");
  const authorization = exactPath(authorizationPath, "authorization");
  const registry = exactPath(trustRegistryPath, "trust registry");
  const artifacts = exactPath(artifactRoot, "artifact root");
  if (typeof chainRpcUrl !== "string" || !/^https:\/\//.test(chainRpcUrl)) {
    throw new Error("production authorization validation requires an explicit HTTPS chain RPC URL");
  }
  const args = [
    "-m", "p42_prizes.cli", "production-launch-authorization-validate",
    "--authorization", authorization,
    "--trust-registry", registry,
    "--artifact-root", artifacts,
    "--chain-rpc-url", chainRpcUrl,
  ];
  if (nowUtc !== null) args.push("--now-utc", nowUtc);
  const validatorEnv = Object.fromEntries(
    ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR"]
      .filter((name) => typeof process.env[name] === "string")
      .map((name) => [name, process.env[name]]),
  );
  validatorEnv.PYTHONPATH = resolve(root, "src");
  const result = spawn(executable, args, {
    cwd: root,
    env: validatorEnv,
    encoding: null,
    maxBuffer: LIMITS.maxBytes,
    timeout: 15 * 60 * 1000,
    killSignal: "SIGKILL",
    shell: false,
    windowsHide: true,
  });
  if (result.error) throw new Error(`production authorization validator failed or timed out: ${result.error.message}`);
  if (result.signal !== null && result.signal !== undefined) {
    throw new Error(`production authorization validator terminated by ${result.signal}`);
  }
  if (result.status !== 0) {
    const stderr = Buffer.from(result.stderr ?? Buffer.alloc(0)).subarray(0, 4096).toString("utf8").trim();
    throw new Error(`production authorization validator rejected the packet${stderr ? `: ${stderr}` : ""}`);
  }
  const bytes = Buffer.from(result.stdout ?? Buffer.alloc(0));
  const value = parseStrictJsonBytes(bytes, LIMITS);
  if (value?.schema_version !== AUTH_SCHEMA || value.status !== "authorized") {
    throw new Error("production authorization validator returned an unexpected artifact");
  }
  return Object.freeze({ value, validatedBytes: bytes, validatedBytesDigest: sha256(bytes) });
}

export function buildFundingActivationPlan({
  manifest,
  manifestBytesDigest,
  validatedAuthorization,
  manifestValidator = validateSolverManifest,
  validationContext = null,
}) {
  assertCanonicalManifestTopology(manifest);
  manifestValidator(manifest, manifest.problems?.[0]?.problemId ?? null, validationContext);
  if (manifest.releaseMode !== "production" || manifest.status !== "governance-setup-complete") {
    throw new Error("funding activation requires a completed production deployment manifest");
  }
  if (!Array.isArray(manifest.problems) || manifest.problems.length !== 10) {
    throw new Error("funding activation requires exactly ten deployment boards");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(manifestBytesDigest ?? "")) {
    throw new Error("funding activation requires the exact manifest bytes digest");
  }
  const authorization = validatedAuthorization?.value;
  if (!authorization || !/^sha256:[0-9a-f]{64}$/.test(validatedAuthorization.validatedBytesDigest ?? "")) {
    throw new Error("funding activation requires validator-produced authorization bytes");
  }
  assertReleaseBinding(authorization, manifest, manifestBytesDigest);
  const governanceNumbers = [
    Number(manifest.governance.threshold),
    Number(manifest.governance.delaySeconds),
    Number(manifest.governance.operationGracePeriodSeconds),
  ];
  if (governanceNumbers.some((value) => !Number.isSafeInteger(value) || value < 1)) {
    throw new Error("funding activation requires bounded positive governance timing and threshold values");
  }
  const digest = authorizationBytes32(authorization.authorization_digest);
  const expiresAt = Math.floor(Date.parse(authorization.expires_at_utc) / 1000);
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 1) throw new Error("validated authorization expiry is invalid");
  const operations = [];
  const boards = manifest.problems.map((problem, index) => ({
    index,
    problem,
    contracts: manifestProblemContracts(manifest, problem),
    prefix: `board.${problem.problemId}`,
  }));
  const addresses = boards.flatMap(({ contracts }) => [contracts.submissions.address, contracts.pool.address].map(ethers.getAddress));
  if (new Set(addresses.map((value) => value.toLowerCase())).size !== 20) {
    throw new Error("funding activation requires twenty unique manager and pool addresses");
  }
  for (const { contracts } of boards) {
    for (const entry of [contracts.submissions, contracts.pool]) {
      if (!/^0x[0-9a-fA-F]{64}$/.test(entry.runtimeCodeHash ?? "")) {
        throw new Error("funding activation requires every target runtime code hash");
      }
    }
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(manifest.contracts.timelock.runtimeCodeHash ?? "")) {
    throw new Error("funding activation requires the timelock runtime code hash");
  }
  const authorizationLabels = boards.map(({ prefix }) => `${prefix}.authorizeFunding`);
  const armLabels = boards.map(({ prefix }) => `${prefix}.armFunding`);
  const governanceIdentity = (label, target, data) => {
    const salt = ethers.keccak256(ethers.toUtf8Bytes(`${authorization.authorization_digest}:${label}`));
    const operationId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "bytes", "bytes32"], [target, 0n, data, salt],
    ));
    return { salt, operationId };
  };
  for (const { index, problem, contracts, prefix } of boards) {
    operations.push({
      sequence: operations.length + 1,
      authority: "treasury",
      label: `${prefix}.authorizeFunding`,
      boardIndex: index,
      problemId: problem.problemId,
      to: ethers.getAddress(contracts.submissions.address),
      expectedRuntimeCodeHash: contracts.submissions.runtimeCodeHash,
      value: "0",
      data: submissionsInterface.encodeFunctionData("authorizeFunding", [digest, expiresAt]),
      dependsOn: [],
    });
  }
  for (const { index, problem, contracts, prefix } of boards) {
    const label = `${prefix}.armFunding`;
    const to = ethers.getAddress(contracts.submissions.address);
    const data = submissionsInterface.encodeFunctionData("armFunding", [digest]);
    operations.push({
      sequence: operations.length + 1,
      authority: "governance",
      label,
      boardIndex: index,
      problemId: problem.problemId,
      to,
      expectedRuntimeCodeHash: contracts.submissions.runtimeCodeHash,
      value: "0",
      data,
      ...governanceIdentity(label, to, data),
      dependsOn: authorizationLabels,
    });
  }
  for (const { index, problem, contracts, prefix } of boards) {
    const label = `${prefix}.setAcceptingFunds`;
    const to = ethers.getAddress(contracts.pool.address);
    const data = poolInterface.encodeFunctionData("setAcceptingFunds", [true]);
    operations.push({
      sequence: operations.length + 1,
      authority: "governance",
      label,
      boardIndex: index,
      problemId: problem.problemId,
      to,
      expectedRuntimeCodeHash: contracts.pool.runtimeCodeHash,
      value: "0",
      data,
      ...governanceIdentity(label, to, data),
      dependsOn: armLabels,
    });
  }
  const body = {
    schema: ACTIVATION_PLAN_SCHEMA,
    chainId: manifest.network.chainId,
    network: manifest.network.chainId === 8453 ? "base-mainnet" : "base-sepolia",
    deploymentCommit: manifest.deploymentCommit,
    deploymentConfigHash: manifest.deploymentConfigHash,
    manifestBytesDigest,
    releaseBindingDigest: manifest.releaseEvidence.releaseBindingDigest,
    capsuleDigest: manifest.releaseEvidence.capsuleDigest,
    slateDigest: manifest.releaseEvidence.slateDigest,
    releaseIndexDigest: manifest.releaseEvidence.releaseIndexDigest,
    authorizationDigest: authorization.authorization_digest,
    authorizationExpiresAt: expiresAt,
    authorizationBytesDigest: validatedAuthorization.validatedBytesDigest,
    timelock: ethers.getAddress(manifest.contracts.timelock.address),
    timelockRuntimeCodeHash: manifest.contracts.timelock.runtimeCodeHash,
    treasury: ethers.getAddress(manifest.roles.treasury),
    governanceSigners: manifest.governance.signers.map(ethers.getAddress),
    governanceThreshold: governanceNumbers[0],
    governanceDelaySeconds: governanceNumbers[1],
    governanceOperationGraceSeconds: governanceNumbers[2],
    boardCount: 10,
    operations,
  };
  return Object.freeze({ ...body, planDigest: sha256(Buffer.from(canonical(body))) });
}

export function loadManifestExact(path) {
  const canonicalPath = exactPath(path, "deployment manifest");
  const before = lstatSync(canonicalPath);
  const fd = openSync(canonicalPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 2 || stat.size > LIMITS.maxBytes || stat.dev !== before.dev || stat.ino !== before.ino) {
      throw new Error("deployment manifest must be a stable bounded regular file");
    }
    const bytes = Buffer.alloc(stat.size);
    for (let offset = 0; offset < bytes.length;) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) throw new Error("deployment manifest truncated during activation read");
      offset += count;
    }
    const after = lstatSync(canonicalPath);
    if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size) {
      throw new Error("deployment manifest changed during activation read");
    }
    const value = parseStrictJsonBytes(bytes, LIMITS);
    return { value, bytesDigest: sha256(bytes) };
  } finally { closeSync(fd); }
}

function arg(name) {
  const index = process.argv.indexOf(`--${name}`);
  const value = index < 0 ? null : process.argv[index + 1];
  return value && !value.startsWith("--") ? value : null;
}

export function writePrivateActivationPlan(path, plan) {
  const absolute = resolve(path);
  const parent = realpathSync(dirname(absolute));
  const parentMetadata = lstatSync(parent);
  if (!parentMetadata.isDirectory() || parentMetadata.isSymbolicLink()
      || (typeof process.getuid === "function" && parentMetadata.uid !== process.getuid())
      || (parentMetadata.mode & 0o022) !== 0) {
    throw new Error("activation plan output parent is not a private owner-controlled directory");
  }
  if (resolve(parent, absolute.slice(dirname(absolute).length + 1)) !== absolute) {
    throw new Error("activation plan output path is not canonical");
  }
  const bytes = Buffer.from(`${JSON.stringify(plan, null, 2)}\n`);
  let fd;
  try {
    fd = openSync(absolute, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    for (let offset = 0; offset < bytes.length;) {
      const count = writeSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) throw new Error("activation plan write made no progress");
      offset += count;
    }
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    const directory = openSync(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (error?.code === "EEXIST") {
      const existing = readStrictJsonFileSync(absolute, {
        ...LIMITS, trailingNewline: "require", privateFile: true,
      });
      if (existing.planDigest === plan.planDigest && canonical(existing) === canonical(plan)) return;
      throw new Error("existing activation plan conflicts with validated plan");
    }
    throw error;
  }
}

export function fundingActivationPlanMain() {
  const required = ["manifest", "authorization", "trust-registry", "artifact-root", "chain-rpc-url", "python", "repo-root", "output"];
  const values = Object.fromEntries(required.map((name) => [name, arg(name)]));
  const missing = required.filter((name) => values[name] === null);
  if (missing.length > 0) throw new Error(`missing required activation arguments: ${missing.join(", ")}`);
  const manifest = loadManifestExact(values.manifest);
  const validatedAuthorization = runProductionAuthorizationValidator({
    python: values.python,
    repoRoot: values["repo-root"],
    authorizationPath: values.authorization,
    trustRegistryPath: values["trust-registry"],
    artifactRoot: values["artifact-root"],
    chainRpcUrl: values["chain-rpc-url"],
  });
  const plan = buildFundingActivationPlan({
    manifest: manifest.value,
    manifestBytesDigest: manifest.bytesDigest,
    validatedAuthorization,
  });
  writePrivateActivationPlan(values.output, plan);
  process.stdout.write(`${plan.planDigest}\n`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try { fundingActivationPlanMain(); } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
