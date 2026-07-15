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
export const ACTIVATION_SIGNATURES_SCHEMA = "p42-funding-activation-signatures/v2";
export const ACTIVATION_PLAN_SCHEMA = "p42-funding-activation-plan/v2";

export const FUNDING_ROLES = Object.freeze([
  Object.freeze({ name: "production-launch-authority", manifestField: "productionLaunchAuthority" }),
  Object.freeze({ name: "independent-security-authority", manifestField: "independentSecurityAuthority" }),
  Object.freeze({ name: "governance-authority", manifestField: "governanceAuthority" }),
]);
export const FUNDING_TYPES = Object.freeze({
  FundingAuthorization: Object.freeze([
    Object.freeze({ name: "role", type: "bytes32" }),
    Object.freeze({ name: "boardSetDigest", type: "bytes32" }),
    Object.freeze({ name: "releaseBindingDigest", type: "bytes32" }),
    Object.freeze({ name: "authorizationDigest", type: "bytes32" }),
    Object.freeze({ name: "expiresAt", type: "uint64" }),
    Object.freeze({ name: "nonce", type: "uint256" }),
  ]),
});
const SECP256K1_HALF_ORDER = BigInt("0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

const submissionsInterface = new ethers.Interface([
  "function authorizeFunding(bytes32 authorizationDigest,uint64 expiresAt,uint256 nonce,bytes[3] signatures)",
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

export function authorizationBytes32(digest) {
  if (!/^sha256:[0-9a-f]{64}$/.test(digest ?? "")) throw new Error("validated authorization digest is malformed");
  return `0x${digest.slice(7)}`;
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
  return value;
}

function boundedUint(value, bits, label) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed >= (1n << BigInt(bits))) throw new Error(`${label} exceeds uint${bits}`);
  return parsed;
}

function validateSignature(signature, expectedSigner, typedDataDigest, label) {
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new Error(`${label} must be one 65-byte signature`);
  }
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const v = Number.parseInt(signature.slice(130, 132), 16);
  if (s > SECP256K1_HALF_ORDER || (v !== 27 && v !== 28)) {
    throw new Error(`${label} is not canonical low-s/v`);
  }
  let recovered;
  try {
    recovered = ethers.recoverAddress(typedDataDigest, {
      r: `0x${signature.slice(2, 66)}`,
      s: `0x${signature.slice(66, 130)}`,
      v,
    });
  } catch {
    throw new Error(`${label} is not a valid EIP-712 signature`);
  }
  if (recovered !== expectedSigner) throw new Error(`${label} recovered signer does not match manifest authority`);
}

export function validateFundingActivationSignatures({ bundle, manifest, authorizationDigest, expiresAt, boards }) {
  exactObject(bundle, [
    "schema", "chainId", "boardSetDigest", "releaseBindingDigest", "authorizationDigest",
    "expiresAt", "authorities", "boards",
  ], "funding activation signature bundle");
  if (bundle.schema !== ACTIVATION_SIGNATURES_SCHEMA) {
    throw new Error("legacy or unknown funding activation signature bundle is forbidden");
  }
  if (bundle.chainId !== manifest.network.chainId) throw new Error("signature bundle chain does not match manifest");
  for (const [field, expected] of [
    ["boardSetDigest", manifest.releaseEvidence.boardSetDigest],
    ["releaseBindingDigest", manifest.releaseEvidence.releaseBindingDigest],
    ["authorizationDigest", authorizationDigest],
  ]) {
    if (bundle[field] !== expected || !/^sha256:[0-9a-f]{64}$/.test(bundle[field] ?? "")) {
      throw new Error(`signature bundle ${field} does not match activation binding`);
    }
  }
  if (boundedUint(bundle.expiresAt, 64, "signature bundle expiresAt") !== BigInt(expiresAt)) {
    throw new Error("signature bundle expiry does not match validated authorization");
  }
  exactObject(bundle.authorities, FUNDING_ROLES.map(({ manifestField }) => manifestField), "signature bundle authorities");
  const authorities = FUNDING_ROLES.map(({ manifestField }) => {
    const pinned = ethers.getAddress(manifest.roles?.[manifestField]);
    if (ethers.getAddress(bundle.authorities[manifestField]) !== pinned) {
      throw new Error(`signature bundle ${manifestField} does not match manifest authority`);
    }
    return pinned;
  });
  if (new Set(authorities.map((value) => value.toLowerCase())).size !== FUNDING_ROLES.length) {
    throw new Error("manifest funding authorities must be distinct");
  }
  const forbiddenAuthorities = [
    manifest.roles?.deployer,
    manifest.roles?.owner,
    manifest.roles?.treasury,
    manifest.roles?.resolver,
    manifest.roles?.guardian,
    manifest.roles?.objectiveVerifier,
    ...(manifest.governance?.signers ?? []),
  ]
    .filter((value) => value !== undefined && value !== null)
    .map((value) => ethers.getAddress(value).toLowerCase());
  if (authorities.some((value) => forbiddenAuthorities.includes(value.toLowerCase()))) {
    throw new Error("manifest funding authorities must be distinct from treasury and owner");
  }
  if (!Array.isArray(bundle.boards) || bundle.boards.length !== 10) {
    throw new Error("signature bundle requires exactly ten board entries");
  }
  const expectedManagers = new Set(boards.map(({ contracts }) => ethers.getAddress(contracts.submissions.address).toLowerCase()));
  const observedManagers = new Set();
  const validated = bundle.boards.map((entry, index) => {
    exactObject(entry, ["boardIndex", "problemId", "submissionManager", "nonce", "signatures"], `signature bundle board ${index}`);
    const board = boards[index];
    const manager = ethers.getAddress(entry.submissionManager);
    if (entry.boardIndex !== index || String(entry.problemId) !== String(board.problem.problemId)
        || manager !== ethers.getAddress(board.contracts.submissions.address)) {
      throw new Error(`signature bundle board ${index} does not match the ordered manifest board`);
    }
    const managerKey = manager.toLowerCase();
    if (!expectedManagers.has(managerKey) || observedManagers.has(managerKey)) {
      throw new Error(`signature bundle board ${index} has an extra or duplicate manager`);
    }
    observedManagers.add(managerKey);
    const nonce = boundedUint(entry.nonce, 256, `signature bundle board ${index} nonce`);
    if (!Array.isArray(entry.signatures) || entry.signatures.length !== FUNDING_ROLES.length) {
      throw new Error(`signature bundle board ${index} requires exactly three signatures`);
    }
    const domain = { name: "P42SubmissionManager", version: "2", chainId: bundle.chainId, verifyingContract: manager };
    const common = {
      boardSetDigest: authorizationBytes32(bundle.boardSetDigest),
      releaseBindingDigest: authorizationBytes32(bundle.releaseBindingDigest),
      authorizationDigest: authorizationBytes32(bundle.authorizationDigest),
      expiresAt: BigInt(bundle.expiresAt),
      nonce,
    };
    const signatures = entry.signatures.map((record, roleIndex) => {
      exactObject(record, ["role", "signer", "signature"], `signature bundle board ${index} signature ${roleIndex}`);
      const role = FUNDING_ROLES[roleIndex];
      const expectedSigner = authorities[roleIndex];
      if (record.role !== role.name || ethers.getAddress(record.signer) !== expectedSigner) {
        throw new Error(`signature bundle board ${index} signature role order or signer is invalid`);
      }
      const value = { ...common, role: ethers.id(role.name) };
      validateSignature(record.signature, expectedSigner, ethers.TypedDataEncoder.hash(domain, FUNDING_TYPES, value), `signature bundle board ${index} ${role.name}`);
      return record.signature;
    });
    return Object.freeze({ nonce, signatures: Object.freeze(signatures) });
  });
  if (observedManagers.size !== expectedManagers.size) throw new Error("signature bundle has missing manifest boards");
  return Object.freeze(validated);
}

export function assertReleaseBinding(authorization, manifest, manifestBytesDigest) {
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
  activationSignatures,
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
  const verifiedSignatures = validateFundingActivationSignatures({
    bundle: activationSignatures,
    manifest,
    authorizationDigest: authorization.authorization_digest,
    expiresAt,
    boards,
  });
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
    const signed = verifiedSignatures[index];
    operations.push({
      sequence: operations.length + 1,
      authority: "treasury",
      label: `${prefix}.authorizeFunding`,
      boardIndex: index,
      problemId: problem.problemId,
      to: ethers.getAddress(contracts.submissions.address),
      expectedRuntimeCodeHash: contracts.submissions.runtimeCodeHash,
      value: "0",
      authorizationNonce: signed.nonce.toString(),
      verifiedSignatureCount: signed.signatures.length,
      data: submissionsInterface.encodeFunctionData("authorizeFunding", [digest, expiresAt, signed.nonce, signed.signatures]),
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
    activationSignaturesDigest: sha256(Buffer.from(canonical(activationSignatures))),
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

export function loadFundingActivationSignatures(path) {
  return readStrictJsonFileSync(exactPath(path, "funding activation signatures"), {
    ...LIMITS, trailingNewline: "require",
  });
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
  const required = ["manifest", "authorization", "activation-signatures", "trust-registry", "artifact-root", "chain-rpc-url", "python", "repo-root", "output"];
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
    activationSignatures: loadFundingActivationSignatures(values["activation-signatures"]),
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
