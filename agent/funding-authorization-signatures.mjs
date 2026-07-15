#!/usr/bin/env node

import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

import { assertCanonicalManifestTopology } from "./canonical-topology.mjs";
import {
  ACTIVATION_SIGNATURES_SCHEMA,
  FUNDING_ROLES,
  FUNDING_TYPES,
  assertReleaseBinding,
  authorizationBytes32,
  loadManifestExact,
  runProductionAuthorizationValidator,
  validateFundingActivationSignatures,
} from "./funding-activation.mjs";
import { manifestProblemContracts } from "./indexer.mjs";
import { validateSolverManifest } from "./solver-manifest.mjs";
import { readStrictJsonFileSync, writeTrustedFileExclusiveSync } from "./strict-json.mjs";

export const AUTHORIZATION_REQUEST_SET_SCHEMA = "p42-funding-authorization-request-set/v2";
export const AUTHORIZATION_REQUEST_SCHEMA = "p42-funding-authorization-request/v2";
export const AUTHORIZATION_ROLE_SIGNATURE_SCHEMA = "p42-funding-authorization-role-signature/v2";
export const MANAGER_NONCE_EVIDENCE_SCHEMA = "p42-funding-manager-nonce-evidence/v2";
const REQUEST_TTL_SECONDS = 15 * 60;
const LIMITS = Object.freeze({
  maxBytes: 8 * 1024 * 1024,
  maxDepth: 128,
  trailingNewline: "require",
  privateFile: true,
});
const managerInterface = new ethers.Interface(["function fundingAuthorizationNonce() view returns (uint256)"]);

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function digest(value) {
  return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
  return value;
}

function canonicalUint(value, bits, label) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed >= (1n << BigInt(bits))) throw new Error(`${label} exceeds uint${bits}`);
  return parsed;
}

function boardsFor(manifest) {
  return manifest.problems.map((problem, index) => ({
    index,
    problem,
    contracts: manifestProblemContracts(manifest, problem),
  }));
}

function assertActivationSource({ manifest, manifestBytesDigest, validatedAuthorization, manifestValidator = validateSolverManifest }) {
  assertCanonicalManifestTopology(manifest);
  manifestValidator(manifest, manifest.problems?.[0]?.problemId ?? null);
  if (manifest.releaseMode !== "production" || manifest.status !== "governance-setup-complete"
      || !Array.isArray(manifest.problems) || manifest.problems.length !== 10) {
    throw new Error("funding authorization requests require a completed ten-board production manifest");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(manifestBytesDigest ?? "")) {
    throw new Error("funding authorization requests require the exact manifest bytes digest");
  }
  const authorization = validatedAuthorization?.value;
  if (!authorization || !/^sha256:[0-9a-f]{64}$/.test(validatedAuthorization.validatedBytesDigest ?? "")) {
    throw new Error("funding authorization requests require validator-produced authorization bytes");
  }
  assertReleaseBinding(authorization, manifest, manifestBytesDigest);
  const expiresAt = Math.floor(Date.parse(authorization.expires_at_utc) / 1000);
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 1) throw new Error("validated authorization expiry is invalid");
  return { authorization, expiresAt, boards: boardsFor(manifest) };
}

function assertAuthorities(manifest) {
  const authorities = Object.fromEntries(FUNDING_ROLES.map(({ manifestField }) => [
    manifestField, ethers.getAddress(manifest.roles?.[manifestField]),
  ]));
  const values = Object.values(authorities);
  if (new Set(values.map((value) => value.toLowerCase())).size !== values.length) {
    throw new Error("manifest funding authorities must be distinct");
  }
  const forbidden = [
    manifest.roles?.deployer,
    manifest.roles?.owner,
    manifest.roles?.treasury,
    manifest.roles?.resolver,
    manifest.roles?.guardian,
    manifest.roles?.objectiveVerifier,
    ...(manifest.governance?.signers ?? []),
  ].filter((value) => value !== undefined && value !== null)
    .map((value) => ethers.getAddress(value).toLowerCase());
  if (values.some((value) => forbidden.includes(value.toLowerCase()))) {
    throw new Error("manifest funding authorities must be distinct from treasury and owner");
  }
  return authorities;
}

function assertNonceEvidence(evidence, manifest, boards) {
  exactObject(evidence, [
    "schema", "chainId", "finalizedBlockNumber", "finalizedBlockHash", "finalizedBlockTimestamp", "boards",
  ], "manager nonce evidence");
  if (evidence.schema !== MANAGER_NONCE_EVIDENCE_SCHEMA || evidence.chainId !== manifest.network.chainId
      || !Number.isSafeInteger(evidence.finalizedBlockNumber) || evidence.finalizedBlockNumber < 0
      || !/^0x[0-9a-f]{64}$/.test(evidence.finalizedBlockHash ?? "")
      || !Number.isSafeInteger(evidence.finalizedBlockTimestamp) || evidence.finalizedBlockTimestamp < 1
      || !Array.isArray(evidence.boards) || evidence.boards.length !== 10) {
    throw new Error("manager nonce evidence identity is invalid");
  }
  evidence.boards.forEach((entry, index) => {
    exactObject(entry, ["boardIndex", "problemId", "submissionManager", "nonce"], `manager nonce evidence board ${index}`);
    const board = boards[index];
    if (entry.boardIndex !== index || String(entry.problemId) !== String(board.problem.problemId)
        || ethers.getAddress(entry.submissionManager) !== ethers.getAddress(board.contracts.submissions.address)) {
      throw new Error(`manager nonce evidence board ${index} does not match the ordered manifest board`);
    }
    canonicalUint(entry.nonce, 256, `manager nonce evidence board ${index} nonce`);
  });
  return evidence;
}

async function readManagerNonce(provider, manager, blockNumber) {
  const data = managerInterface.encodeFunctionData("fundingAuthorizationNonce", []);
  const result = await provider.send("eth_call", [{ to: manager, data }, ethers.toQuantity(blockNumber)]);
  return managerInterface.decodeFunctionResult("fundingAuthorizationNonce", result)[0];
}

export async function collectManagerNonceEvidence(manifest, primaryProvider, secondaryProvider) {
  if (!primaryProvider || !secondaryProvider || primaryProvider === secondaryProvider) {
    throw new Error("manager nonce evidence requires two independent RPC providers");
  }
  const boards = boardsFor(manifest);
  const [primaryNetwork, secondaryNetwork, primaryFinalized, secondaryFinalized] = await Promise.all([
    primaryProvider.getNetwork(), secondaryProvider.getNetwork(),
    primaryProvider.getBlock("finalized"), secondaryProvider.getBlock("finalized"),
  ]);
  if (Number(primaryNetwork.chainId) !== manifest.network.chainId || Number(secondaryNetwork.chainId) !== manifest.network.chainId) {
    throw new Error("manager nonce evidence RPC chain mismatch");
  }
  if (!primaryFinalized || !secondaryFinalized) throw new Error("manager nonce evidence finalized block is unavailable");
  const blockNumber = Math.min(primaryFinalized.number, secondaryFinalized.number);
  const [primaryBlock, secondaryBlock] = await Promise.all([
    primaryProvider.getBlock(blockNumber), secondaryProvider.getBlock(blockNumber),
  ]);
  if (!primaryBlock || !secondaryBlock || primaryBlock.hash.toLowerCase() !== secondaryBlock.hash.toLowerCase()
      || primaryBlock.timestamp !== secondaryBlock.timestamp) {
    throw new Error("manager nonce evidence RPCs disagree on the common finalized block");
  }
  const rows = await Promise.all(boards.map(async ({ index, problem, contracts }) => {
    const manager = ethers.getAddress(contracts.submissions.address);
    const [primaryNonce, secondaryNonce] = await Promise.all([
      readManagerNonce(primaryProvider, manager, blockNumber), readManagerNonce(secondaryProvider, manager, blockNumber),
    ]);
    if (primaryNonce !== secondaryNonce) throw new Error(`manager nonce evidence RPCs disagree for board ${problem.problemId}`);
    return { boardIndex: index, problemId: problem.problemId, submissionManager: manager, nonce: primaryNonce.toString() };
  }));
  return Object.freeze({
    schema: MANAGER_NONCE_EVIDENCE_SCHEMA,
    chainId: manifest.network.chainId,
    finalizedBlockNumber: blockNumber,
    finalizedBlockHash: primaryBlock.hash.toLowerCase(),
    finalizedBlockTimestamp: primaryBlock.timestamp,
    boards: rows,
  });
}

function requestBody({ common, board, nonce, role, signer, generation, requestExpiresAt }) {
  const domain = {
    name: "P42SubmissionManager",
    version: "2",
    chainId: common.chainId,
    verifyingContract: ethers.getAddress(board.contracts.submissions.address),
  };
  const message = {
    role: ethers.id(role),
    boardSetDigest: authorizationBytes32(common.boardSetDigest),
    releaseBindingDigest: authorizationBytes32(common.releaseBindingDigest),
    authorizationDigest: authorizationBytes32(common.authorizationDigest),
    expiresAt: common.authorizationExpiresAt,
    nonce: nonce.toString(),
  };
  return {
    schema: AUTHORIZATION_REQUEST_SCHEMA,
    generation,
    requestExpiresAt,
    boardIndex: board.index,
    problemId: board.problem.problemId,
    submissionManager: domain.verifyingContract,
    nonce: nonce.toString(),
    role,
    signer,
    domain,
    types: FUNDING_TYPES,
    primaryType: "FundingAuthorization",
    message,
    typedDataDigest: ethers.TypedDataEncoder.hash(domain, FUNDING_TYPES, message),
  };
}

export function buildFundingAuthorizationRequestSet({
  manifest,
  manifestBytesDigest,
  validatedAuthorization,
  nonceEvidence,
  generation,
  manifestValidator = validateSolverManifest,
}) {
  if (!Number.isSafeInteger(generation) || generation < 1) throw new Error("request generation must be a positive safe integer");
  const { authorization, expiresAt, boards } = assertActivationSource({
    manifest, manifestBytesDigest, validatedAuthorization, manifestValidator,
  });
  assertNonceEvidence(nonceEvidence, manifest, boards);
  if (generation !== nonceEvidence.finalizedBlockNumber) {
    throw new Error("request generation must equal its common finalized block number");
  }
  if (nonceEvidence.finalizedBlockTimestamp >= expiresAt) throw new Error("validated authorization is expired at the finalized request anchor");
  const requestExpiresAt = Math.min(expiresAt, nonceEvidence.finalizedBlockTimestamp + REQUEST_TTL_SECONDS);
  const authorities = assertAuthorities(manifest);
  const common = {
    chainId: manifest.network.chainId,
    boardSetDigest: manifest.releaseEvidence.boardSetDigest,
    releaseBindingDigest: manifest.releaseEvidence.releaseBindingDigest,
    authorizationDigest: authorization.authorization_digest,
    authorizationExpiresAt: String(expiresAt),
  };
  const requests = boards.flatMap((board, boardIndex) => FUNDING_ROLES.map(({ name, manifestField }) => {
    const body = requestBody({
      common,
      board,
      nonce: canonicalUint(nonceEvidence.boards[boardIndex].nonce, 256, `board ${boardIndex} nonce`),
      role: name,
      signer: authorities[manifestField],
      generation,
      requestExpiresAt,
    });
    return Object.freeze({ ...body, requestId: digest(body) });
  }));
  const body = {
    schema: AUTHORIZATION_REQUEST_SET_SCHEMA,
    generation,
    requestGeneratedAt: nonceEvidence.finalizedBlockTimestamp,
    requestExpiresAt,
    chainId: common.chainId,
    manifestBytesDigest,
    authorizationBytesDigest: validatedAuthorization.validatedBytesDigest,
    boardSetDigest: common.boardSetDigest,
    releaseBindingDigest: common.releaseBindingDigest,
    authorizationDigest: common.authorizationDigest,
    authorizationExpiresAt: common.authorizationExpiresAt,
    authorities,
    nonceEvidence,
    requests,
  };
  return Object.freeze({ ...body, requestSetDigest: digest(body) });
}

function validateRoleArtifact(artifact, request, requestSet) {
  exactObject(artifact, [
    "schema", "requestSetDigest", "requestId", "generation", "requestExpiresAt", "boardIndex",
    "submissionManager", "role", "signer", "signature",
  ], "funding authorization role artifact");
  if (artifact.schema !== AUTHORIZATION_ROLE_SIGNATURE_SCHEMA
      || artifact.requestSetDigest !== requestSet.requestSetDigest || artifact.requestId !== request.requestId
      || artifact.generation !== requestSet.generation || artifact.requestExpiresAt !== requestSet.requestExpiresAt
      || artifact.boardIndex !== request.boardIndex
      || ethers.getAddress(artifact.submissionManager) !== request.submissionManager
      || artifact.role !== request.role || ethers.getAddress(artifact.signer) !== request.signer
      || typeof artifact.signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(artifact.signature)) {
    throw new Error("funding authorization role artifact does not match its exact request identity");
  }
  let recovered;
  try { recovered = ethers.verifyTypedData(request.domain, request.types, request.message, artifact.signature); }
  catch { throw new Error("funding authorization role artifact signature is invalid"); }
  if (ethers.getAddress(recovered) !== request.signer) {
    throw new Error("funding authorization role artifact recovered signer does not match request authority");
  }
  return artifact.signature;
}

export function assembleFundingActivationSignatures({
  manifest,
  manifestBytesDigest,
  validatedAuthorization,
  requestSet,
  roleArtifacts,
  freshNonceEvidence,
  manifestValidator = validateSolverManifest,
}) {
  const expected = buildFundingAuthorizationRequestSet({
    manifest,
    manifestBytesDigest,
    validatedAuthorization,
    nonceEvidence: requestSet?.nonceEvidence,
    generation: requestSet?.generation,
    manifestValidator,
  });
  if (canonical(requestSet) !== canonical(expected)) throw new Error("funding authorization request set identity is invalid");
  const { boards } = assertActivationSource({ manifest, manifestBytesDigest, validatedAuthorization, manifestValidator });
  assertNonceEvidence(freshNonceEvidence, manifest, boards);
  if (freshNonceEvidence.finalizedBlockNumber < requestSet.nonceEvidence.finalizedBlockNumber) {
    throw new Error("fresh manager nonce evidence regresses before the request anchor");
  }
  if (freshNonceEvidence.finalizedBlockTimestamp > requestSet.requestExpiresAt) {
    throw new Error("funding authorization request set is expired");
  }
  for (let index = 0; index < 10; index += 1) {
    if (freshNonceEvidence.boards[index].nonce !== requestSet.nonceEvidence.boards[index].nonce) {
      throw new Error(`funding authorization request set has stale nonce for board ${index}`);
    }
  }
  if (!Array.isArray(roleArtifacts) || roleArtifacts.length !== 30) {
    throw new Error("funding activation assembly requires exactly 30 role artifacts");
  }
  const byRequest = new Map();
  for (const artifact of roleArtifacts) {
    if (typeof artifact?.requestId !== "string" || byRequest.has(artifact.requestId)) {
      throw new Error("funding activation role artifacts contain a missing or duplicate request identity");
    }
    byRequest.set(artifact.requestId, artifact);
  }
  const signatures = expected.requests.map((request) => {
    const artifact = byRequest.get(request.requestId);
    if (!artifact) throw new Error(`funding activation role artifact is missing for ${request.requestId}`);
    return validateRoleArtifact(artifact, request, expected);
  });
  if (byRequest.size !== expected.requests.length) throw new Error("funding activation role artifacts contain substituted requests");
  const bundle = {
    schema: ACTIVATION_SIGNATURES_SCHEMA,
    chainId: expected.chainId,
    boardSetDigest: expected.boardSetDigest,
    releaseBindingDigest: expected.releaseBindingDigest,
    authorizationDigest: expected.authorizationDigest,
    expiresAt: expected.authorizationExpiresAt,
    authorities: expected.authorities,
    boards: boards.map((board, boardIndex) => ({
      boardIndex,
      problemId: board.problem.problemId,
      submissionManager: ethers.getAddress(board.contracts.submissions.address),
      nonce: expected.nonceEvidence.boards[boardIndex].nonce,
      signatures: FUNDING_ROLES.map(({ name }, roleIndex) => ({
        role: name,
        signer: expected.requests[boardIndex * 3 + roleIndex].signer,
        signature: signatures[boardIndex * 3 + roleIndex],
      })),
    })),
  };
  validateFundingActivationSignatures({
    bundle,
    manifest,
    authorizationDigest: expected.authorizationDigest,
    expiresAt: BigInt(expected.authorizationExpiresAt),
    boards,
  });
  return Object.freeze(bundle);
}

export function writeImmutablePrivateJson(path, trustedRoot, value) {
  const absolute = resolve(path);
  const root = realpathSync(resolve(trustedRoot));
  const payload = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  if (writeTrustedFileExclusiveSync(absolute, root, payload)) return;
  const existing = readStrictJsonFileSync(absolute, { ...LIMITS, trustedRoot: root });
  if (canonical(existing) !== canonical(value)) throw new Error("existing immutable funding authorization artifact conflicts");
}

function arg(name) {
  const index = process.argv.indexOf(`--${name}`);
  const value = index < 0 ? null : process.argv[index + 1];
  return value && !value.startsWith("--") ? value : null;
}

function args(name) {
  const values = [];
  for (let index = 0; index < process.argv.length; index += 1) {
    if (process.argv[index] === `--${name}` && process.argv[index + 1] && !process.argv[index + 1].startsWith("--")) {
      values.push(process.argv[index + 1]);
    }
  }
  return values;
}

function required(name) {
  const value = arg(name);
  if (value === null) throw new Error(`--${name} is required`);
  return value;
}

function assertNoPrivateKeys() {
  if (process.argv.some((value) => /private[-_]?key/i.test(value))
      || Object.keys(process.env).some((name) => /P42_FUNDING.*PRIVATE_KEY/.test(name) && process.env[name])) {
    throw new Error("funding authorization tooling forbids plaintext private-key inputs");
  }
}

function rpcProviders(chainId) {
  const primaryUrl = process.env.P42_PRIMARY_BASE_RPC_URL;
  const secondaryUrl = process.env.P42_SECONDARY_BASE_RPC_URL;
  if (!primaryUrl || !secondaryUrl) throw new Error("P42_PRIMARY_BASE_RPC_URL and P42_SECONDARY_BASE_RPC_URL are required");
  const primary = new URL(primaryUrl); const secondary = new URL(secondaryUrl);
  if (primary.protocol !== "https:" || secondary.protocol !== "https:" || primary.hostname === secondary.hostname
      || primary.origin === secondary.origin) throw new Error("funding authorization requires distinct HTTPS RPC hosts");
  for (const url of [primary, secondary]) {
    if (url.username || url.password || url.search || url.hash || !["", "/"].includes(url.pathname)) {
      throw new Error("funding authorization RPC URLs must be credential-free root HTTPS endpoints");
    }
  }
  return [
    new ethers.JsonRpcProvider(primaryUrl, chainId, { staticNetwork: true }),
    new ethers.JsonRpcProvider(secondaryUrl, chainId, { staticNetwork: true }),
  ];
}

function commonInputs() {
  const manifest = loadManifestExact(required("manifest"));
  const [primary, secondary] = rpcProviders(manifest.value.network.chainId);
  const validatedAuthorization = runProductionAuthorizationValidator({
    python: required("python"),
    repoRoot: required("repo-root"),
    authorizationPath: required("authorization"),
    trustRegistryPath: required("trust-registry"),
    artifactRoot: required("artifact-root"),
    chainRpcUrl: process.env.P42_SECONDARY_BASE_RPC_URL,
  });
  return { manifest, validatedAuthorization, primary, secondary };
}

export async function fundingAuthorizationRequestMain() {
  assertNoPrivateKeys();
  const { manifest, validatedAuthorization, primary, secondary } = commonInputs();
  const nonceEvidence = await collectManagerNonceEvidence(manifest.value, primary, secondary);
  const requestSet = buildFundingAuthorizationRequestSet({
    manifest: manifest.value,
    manifestBytesDigest: manifest.bytesDigest,
    validatedAuthorization,
    nonceEvidence,
    generation: nonceEvidence.finalizedBlockNumber,
  });
  writeImmutablePrivateJson(required("output"), required("trusted-root"), requestSet);
  process.stdout.write(`${requestSet.requestSetDigest}\n`);
}

export async function fundingAuthorizationAssembleMain() {
  assertNoPrivateKeys();
  const { manifest, validatedAuthorization, primary, secondary } = commonInputs();
  const trustedRoot = required("trusted-root");
  const requestSet = readStrictJsonFileSync(resolve(required("request-set")), { ...LIMITS, trustedRoot: realpathSync(resolve(trustedRoot)) });
  const signaturePaths = args("signature");
  const roleArtifacts = signaturePaths.map((path) => readStrictJsonFileSync(resolve(path), {
    ...LIMITS,
    trustedRoot: realpathSync(resolve(trustedRoot)),
  }));
  const freshNonceEvidence = await collectManagerNonceEvidence(manifest.value, primary, secondary);
  const bundle = assembleFundingActivationSignatures({
    manifest: manifest.value,
    manifestBytesDigest: manifest.bytesDigest,
    validatedAuthorization,
    requestSet,
    roleArtifacts,
    freshNonceEvidence,
  });
  writeImmutablePrivateJson(required("output"), trustedRoot, bundle);
  process.stdout.write(`${digest(bundle)}\n`);
}

const invoked = process.argv[1] ? basename(process.argv[1]) : "";
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const main = invoked.includes("assemble") ? fundingAuthorizationAssembleMain : fundingAuthorizationRequestMain;
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
