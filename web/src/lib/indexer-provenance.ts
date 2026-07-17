import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { createHash, createPublicKey, verify } from "node:crypto";
import { dirname, relative, resolve, sep } from "node:path";
import { AbiCoder, Interface, Signature, TypedDataEncoder, getAddress, keccak256, recoverAddress, toUtf8Bytes } from "ethers";
import deploymentSchema from "@/schemas/deployment-manifest-v2.schema.json";
import checkpointV2Schema from "@/schemas/indexer-checkpoint-v2.schema.json";
import checkpointV3Schema from "@/schemas/indexer-checkpoint-v3.schema.json";
import checkpointV4Schema from "@/schemas/indexer-checkpoint-v4.schema.json";
import completionSchema from "@/schemas/funding-activation-completion.schema.json";
import rpcRegistrySchema from "@/schemas/activation-rpc-operator-registry.schema.json";
import type { ChainProvenance, Problem } from "@/lib/types";

const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;

if (typeof window !== "undefined") throw new Error("indexer provenance artifacts are server-only");

type JsonSchema = Record<string, unknown>;
type JsonObject = Record<string, unknown>;

export interface ActivatedIndexerSnapshot {
  manifest: Readonly<JsonObject>;
  checkpoint: Readonly<JsonObject>;
  provenance: ReadonlyMap<string, ChainProvenance>;
  highWaterIdentity: Readonly<ActivatedIndexerHighWaterIdentity>;
}

export interface ActivatedIndexerHighWaterIdentity {
  checkpointDigest: string;
  releaseBindingDigest: string;
  authorizationDigest: string;
  chainId: number;
  chainName: string;
  deploymentCommit: string;
  deploymentConfigHash: string;
}

interface ActivatedArtifactBundle {
  manifest: JsonObject;
  manifestBytes: Buffer;
  checkpoint: JsonObject;
  checkpointBytes: Buffer;
  authorization: JsonObject;
  authorizationBytes: Buffer;
  productionPolicy: JsonObject;
  trustRegistry: JsonObject;
  checkpointAttestation: JsonObject;
  activationSignatures: JsonObject;
  plan: JsonObject;
  completion: JsonObject;
  rpcRegistry: JsonObject;
  checkpointMaxAgeSeconds?: number;
  nowSeconds?: number;
}

export interface IndexerArtifactPaths {
  deploymentManifestPath: string;
  indexerCheckpointPath: string;
  indexerCheckpointAttestationPath?: string;
  launchAuthorizationPath?: string;
  fundingActivationPlanPath?: string;
  fundingActivationSignaturesPath?: string;
  fundingActivationCompletionPath?: string;
  activationRpcOperatorRegistryPath?: string;
  activationRpcOperatorRegistryTrustedRoot?: string;
  checkpointMaxAgeSeconds?: number;
}

export interface IndexerProvenanceEnvironment {
  [key: string]: string | undefined;
  P42_DEPLOYMENT_MANIFEST_PATH?: string;
  P42_INDEXER_CHECKPOINT_PATH?: string;
  P42_INDEXER_CHECKPOINT_ATTESTATION_PATH?: string;
  P42_LAUNCH_AUTHORIZATION_PATH?: string;
  P42_FUNDING_ACTIVATION_PLAN_PATH?: string;
  P42_FUNDING_ACTIVATION_SIGNATURES_PATH?: string;
  P42_FUNDING_ACTIVATION_COMPLETION_PATH?: string;
  P42_ACTIVATION_RPC_OPERATOR_REGISTRY_PATH?: string;
  P42_ACTIVATION_RPC_OPERATOR_REGISTRY_TRUSTED_ROOT?: string;
  P42_PORTAL_CHECKPOINT_MAX_AGE_SECONDS?: string;
}

export const PRODUCTION_PORTAL_TRUST_POLICY_PATH = "/etc/p42/portal-production-trust-policy.json";
export const PRODUCTION_PORTAL_TRUST_POLICY_ROOT = "/etc/p42/portal-production-trust-policy.sha256";

function object(value: unknown, label: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as JsonObject;
}

function schemaRef(root: JsonSchema, ref: string): JsonSchema {
  if (!ref.startsWith("#/$defs/")) throw new Error(`unsupported schema reference ${ref}`);
  return object(object(root.$defs, "$defs")[ref.slice(8)], ref) as JsonSchema;
}

function isRfc3339DateTime(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, , offsetHourText, offsetMinuteText] = match;
  const year = Number(yearText); const month = Number(monthText); const day = Number(dayText);
  const hour = Number(hourText); const minute = Number(minuteText); const second = Number(secondText);
  const offsetHour = offsetHourText === undefined ? 0 : Number(offsetHourText);
  const offsetMinute = offsetMinuteText === undefined ? 0 : Number(offsetMinuteText);
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  return month >= 1 && month <= 12 && day >= 1 && day <= daysInMonth &&
    hour <= 23 && minute <= 59 && second <= 59 && offsetHour <= 23 && offsetMinute <= 59;
}

function validateSchema(value: unknown, rawSchema: unknown, root: JsonSchema, path: string): void {
  const schema = object(rawSchema, `${path} schema`) as JsonSchema;
  if (typeof schema.$ref === "string") return validateSchema(value, schemaRef(root, schema.$ref), root, path);
  if (Array.isArray(schema.oneOf)) {
    const matches = schema.oneOf.filter((candidate) => {
      try { validateSchema(value, candidate, root, path); return true; } catch { return false; }
    });
    if (matches.length !== 1) throw new Error(`${path} does not match exactly one allowed shape`);
    return;
  }
  if (Array.isArray(schema.allOf)) for (const candidate of schema.allOf) validateSchema(value, candidate, root, path);
  if (schema.if) {
    let matches = true;
    try { validateSchema(value, schema.if, root, path); } catch { matches = false; }
    if (matches && schema.then) validateSchema(value, schema.then, root, path);
    if (!matches && schema.else) validateSchema(value, schema.else, root, path);
  }
  if ("const" in schema && value !== schema.const) throw new Error(`${path} has an invalid constant value`);
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) throw new Error(`${path} has an invalid value`);

  if (schema.type === "object" || schema.properties || schema.required) {
    const record = object(value, path);
    const properties = schema.properties ? object(schema.properties, `${path}.properties`) : {};
    for (const key of (schema.required as string[] | undefined) ?? []) if (!(key in record)) throw new Error(`${path}.${key} is required`);
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(record)) if (!(key in properties)) throw new Error(`${path}.${key} is not allowed`);
    }
    for (const [key, child] of Object.entries(properties)) if (key in record) validateSchema(record[key], child, root, `${path}.${key}`);
    const extraSchema = typeof schema.additionalProperties === "object" ? schema.additionalProperties : null;
    if (extraSchema) for (const [key, child] of Object.entries(record)) if (!(key in properties)) validateSchema(child, extraSchema, root, `${path}.${key}`);
    const count = Object.keys(record).length;
    if (typeof schema.minProperties === "number" && count < schema.minProperties) throw new Error(`${path} has too few properties`);
    return;
  }
  if (schema.type === "array") {
    if (!Array.isArray(value)) throw new Error(`${path} must be an array`);
    if (typeof schema.minItems === "number" && value.length < schema.minItems) throw new Error(`${path} has too few items`);
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) throw new Error(`${path} has too many items`);
    if (schema.uniqueItems && new Set(value.map((entry) => JSON.stringify(entry))).size !== value.length) throw new Error(`${path} must be unique`);
    if (schema.items) value.forEach((entry, index) => validateSchema(entry, schema.items, root, `${path}[${index}]`));
    return;
  }
  if (schema.type === "string") {
    if (typeof value !== "string") throw new Error(`${path} must be a string`);
    if (typeof schema.minLength === "number" && value.length < schema.minLength) throw new Error(`${path} is too short`);
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern).test(value)) throw new Error(`${path} has an invalid format`);
    if (schema.format === "date-time" && !isRfc3339DateTime(value)) throw new Error(`${path} must be an RFC 3339 date-time`);
    if (schema.format === "uri") { try { new URL(value); } catch { throw new Error(`${path} must be an absolute URI`); } }
    return;
  }
  if (schema.type === "integer") {
    if (!Number.isSafeInteger(value)) throw new Error(`${path} must be a safe integer`);
    if (typeof schema.minimum === "number" && (value as number) < schema.minimum) throw new Error(`${path} is below its minimum`);
    return;
  }
  if (schema.type === "boolean" && typeof value !== "boolean") throw new Error(`${path} must be boolean`);
  if (schema.type === "null" && value !== null) throw new Error(`${path} must be null`);
}

function readBoundedRegularJsonWithBytes(path: string): { value: unknown; bytes: Buffer } {
  if (!path || path.includes("\0")) throw new Error("artifact path is invalid");
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.size > MAX_ARTIFACT_BYTES) throw new Error("artifact must be a bounded regular file");
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (bytes.length > MAX_ARTIFACT_BYTES || bytes.length !== before.size ||
        before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new Error("artifact changed while reading");
    }
    return { value: JSON.parse(bytes.toString("utf8")) as unknown, bytes };
  } finally { closeSync(descriptor); }
}

function readBoundedRegularJson(path: string): unknown {
  return readBoundedRegularJsonWithBytes(path).value;
}

function readPrivateProtectedJsonWithBytes(pathValue: string, rootValue: string): { value: unknown; bytes: Buffer } {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("protected activation RPC registry requires O_NOFOLLOW support");
  }
  const path = resolve(pathValue); const root = resolve(rootValue);
  const rel = relative(root, path);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || rel.includes("\0")) {
    throw new Error("protected registry path escapes its trusted root");
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  let cursor = root;
  for (const part of rel.split(sep).slice(0, -1)) {
    const meta = lstatSync(cursor);
    if (!meta.isDirectory() || meta.isSymbolicLink() || (uid !== null && meta.uid !== uid) || (meta.mode & 0o022) !== 0) {
      throw new Error("protected registry trusted path ancestor is unsafe");
    }
    cursor = resolve(cursor, part);
  }
  const parent = lstatSync(dirname(path));
  const before = lstatSync(path);
  if (!parent.isDirectory() || parent.isSymbolicLink() || (uid !== null && parent.uid !== uid) || (parent.mode & 0o022) !== 0
      || !before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (uid !== null && before.uid !== uid)
      || (before.mode & 0o222) !== 0 || before.size > MAX_ARTIFACT_BYTES) {
    throw new Error("protected registry file ownership, mode, link, or parent is unsafe");
  }
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(descriptor);
    if (stat.dev !== before.dev || stat.ino !== before.ino || stat.nlink !== 1 || stat.mode !== before.mode
        || stat.uid !== before.uid || stat.size !== before.size) throw new Error("protected registry path identity changed");
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (bytes.length !== stat.size || stat.dev !== after.dev || stat.ino !== after.ino
        || stat.uid !== after.uid || stat.mode !== after.mode || stat.nlink !== after.nlink
        || stat.size !== after.size || stat.mtimeMs !== after.mtimeMs || stat.ctimeMs !== after.ctimeMs) {
      throw new Error("protected registry file changed while reading");
    }
    const text = bytes.toString("utf8");
    const value = JSON.parse(text) as unknown;
    if (text !== `${JSON.stringify(canonicalize(value))}\n`) {
      throw new Error("protected registry JSON bytes are not canonical");
    }
    return { value, bytes };
  } finally { closeSync(descriptor); }
}

function readProtectedFile(path: string, maxBytes: number): Buffer {
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("protected portal trust policy requires O_NOFOLLOW support");
  }
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.uid !== 0 || before.nlink !== 1
      || (before.mode & 0o222) !== 0 || before.size > maxBytes) {
      throw new Error("protected portal trust policy file is unsafe");
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (bytes.length !== before.size || before.dev !== after.dev || before.ino !== after.ino
      || before.uid !== after.uid || before.mode !== after.mode || before.nlink !== after.nlink
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new Error("protected portal trust policy changed while reading");
    }
    return bytes;
  } finally { closeSync(descriptor); }
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const record = value as JsonObject;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, canonicalize(record[key])]));
  }
  return value;
}

export function computePortalDeploymentConfigHash(manifest: JsonObject): string {
  const indexer = object(manifest.indexer, "manifest.indexer");
  const payload = {
    schema: manifest.schema, status: manifest.status, deploymentCommit: manifest.deploymentCommit,
    releaseMode: manifest.releaseMode, releaseEvidence: manifest.releaseEvidence,
    network: manifest.network, governance: manifest.governance, roles: manifest.roles,
    parameters: manifest.parameters, contracts: manifest.contracts,
    roleAcceptances: manifest.roleAcceptances,
    governanceSetup: manifest.governanceSetup, setupTransactions: manifest.setupTransactions,
    problems: manifest.problems,
    indexer: { startBlock: indexer.startBlock, finalityPolicy: indexer.finalityPolicy },
  };
  return keccak256(toUtf8Bytes(JSON.stringify(canonicalize(payload))));
}

function same(left: unknown, right: unknown): boolean {
  return typeof left === "string" && typeof right === "string"
    ? left.toLowerCase() === right.toLowerCase()
    : left === right;
}

function sha256Bytes(bytes: Buffer): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function sha256Canonical(value: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex")}`;
}

export function canonicalActivationRpcOrigin(value: unknown): string {
  if (typeof value !== "string") throw new Error("activation RPC origin is invalid");
  requireBinding(value.length > 0 && value === value.trim()
    && /^[\x21-\x7e]+$/.test(value) && !value.includes("%"));
  const match = /^https:\/\/([^/:?#]+)(?::([1-9][0-9]{0,4}))?$/.exec(value);
  requireBinding(match !== null);
  const hostname = match![1]; const portText = match![2];
  const labels = hostname.split(".");
  const labelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  requireBinding(hostname.length <= 253 && labels.length >= 2 && labels.every((label) => labelPattern.test(label))
    && !/^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$/.test(hostname));
  const port = portText === undefined ? 443 : Number(portText);
  requireBinding(Number.isSafeInteger(port) && port >= 1 && port <= 65535 && !(portText !== undefined && port === 443));
  const rendered = `https://${hostname}${port === 443 ? "" : `:${port}`}`;
  requireBinding(value === rendered);
  return rendered;
}

function validateActivationRpcRegistry(value: JsonObject, bytes: Buffer, expectedDigest: unknown): JsonObject {
  requireBinding(expectedDigest === sha256Bytes(bytes));
  validateSchema(value, rpcRegistrySchema, rpcRegistrySchema as JsonSchema, "activation RPC registry");
  const profiles = value.profiles as JsonObject[];
  const ids = new Set<string>(); const origins = new Set<string>();
  for (const raw of profiles) {
    const profile = object(raw, "activation RPC registry profile");
    const operatorId = String(profile.operatorId); const endpointOrigin = canonicalActivationRpcOrigin(profile.endpointOrigin);
    requireBinding(profile.endpointProfileDigest === sha256Canonical({ operatorId, endpointOrigin })
      && !ids.has(operatorId) && !origins.has(endpointOrigin));
    ids.add(operatorId); origins.add(endpointOrigin);
  }
  return value;
}

export function loadProtectedActivationRpcOperatorRegistry(
  path: string,
  trustedRoot: string,
  expectedDigest: string,
): JsonObject {
  const file = readPrivateProtectedJsonWithBytes(path, trustedRoot);
  return validateActivationRpcRegistry(object(file.value, "activation RPC registry"), file.bytes, expectedDigest);
}

function requireRpcAuthorityRegistryMembership(authority: JsonObject, registry: JsonObject, registryDigest: unknown): void {
  requireBinding(authority.registryDigest === registryDigest);
  const profiles = registry.profiles as JsonObject[];
  for (const role of ["primary", "secondary"]) {
    const asserted = object(authority[role], `activation RPC ${role} authority`);
    canonicalActivationRpcOrigin(asserted.endpointOrigin);
    requireBinding(profiles.some((profile) => JSON.stringify(canonicalize(profile)) === JSON.stringify(canonicalize(asserted))));
  }
}

const FUNDING_ROLES = [
  ["production-launch-authority", "productionLaunchAuthority"],
  ["independent-security-authority", "independentSecurityAuthority"],
  ["governance-authority", "governanceAuthority"],
] as const;
const FUNDING_TYPES = {
  FundingAuthorization: [
    { name: "role", type: "bytes32" }, { name: "boardSetDigest", type: "bytes32" },
    { name: "releaseBindingDigest", type: "bytes32" }, { name: "authorizationDigest", type: "bytes32" },
    { name: "expiresAt", type: "uint64" }, { name: "nonce", type: "uint256" },
  ],
};
const HALF_SECP256K1_ORDER = BigInt("0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
const submissionsInterface = new Interface([
  "function authorizeFunding(bytes32 authorizationDigest,uint64 expiresAt,uint256 nonce,bytes[3] signatures)",
  "function armFunding(bytes32 authorizationDigest)",
]);
const poolInterface = new Interface(["function setAcceptingFunds(bool accepting)"]);

function digestBytes32(value: unknown): string {
  requireBinding(typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value));
  return `0x${(value as string).slice(7)}`;
}

function canonicalUint(value: unknown): bigint {
  requireBinding(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value));
  return BigInt(value as string);
}

function reconstructCanonicalActivationPlan(
  manifest: JsonObject,
  manifestBytes: Buffer,
  authorization: JsonObject,
  authorizationBytes: Buffer,
  activationSignatures: JsonObject,
  rpcAuthority: JsonObject,
  rpcRegistry: JsonObject,
): JsonObject {
  requireBinding(exactKeys(activationSignatures, [
    "schema", "chainId", "boardSetDigest", "releaseBindingDigest", "authorizationDigest",
    "expiresAt", "authorities", "boards",
  ]) && activationSignatures.schema === "p42-funding-activation-signatures/v2");
  const network = object(manifest.network, "activation manifest network");
  const roles = object(manifest.roles, "activation manifest roles");
  const governance = object(manifest.governance, "activation manifest governance");
  const releaseEvidence = object(manifest.releaseEvidence, "activation manifest release evidence");
  const contracts = object(manifest.contracts, "activation manifest contracts");
  const timelock = object(contracts.timelock, "activation timelock");
  const authorizationBinding = object(authorization.release_binding, "activation authorization release binding");
  const authorizationArtifacts = object(authorization.artifacts, "activation authorization artifacts");
  const rpcRegistryRef = object(authorizationArtifacts.activation_rpc_operator_registry, "activation RPC registry reference");
  requireBinding(exactKeys(rpcAuthority, ["schema", "registryDigest", "primary", "secondary"])
    && rpcAuthority.schema === "p42-activation-rpc-authority/v1"
    && rpcAuthority.registryDigest === rpcRegistryRef.sha256);
  requireRpcAuthorityRegistryMembership(rpcAuthority, rpcRegistry, rpcRegistryRef.sha256);
  for (const role of ["primary", "secondary"]) {
    const profile = object(rpcAuthority[role], `activation RPC ${role} profile`);
    requireBinding(exactKeys(profile, ["operatorId", "endpointOrigin", "endpointProfileDigest"])
      && /^[a-z0-9][a-z0-9._-]{2,63}$/.test(String(profile.operatorId))
      && canonicalActivationRpcOrigin(profile.endpointOrigin) === profile.endpointOrigin
      && /^sha256:[0-9a-f]{64}$/.test(String(profile.endpointProfileDigest)));
  }
  requireBinding(object(rpcAuthority.primary, "primary RPC").operatorId !== object(rpcAuthority.secondary, "secondary RPC").operatorId);
  const problems = manifest.problems as JsonObject[];
  const signatureBoards = activationSignatures.boards as JsonObject[];
  requireBinding(Array.isArray(problems) && problems.length === 10
    && Array.isArray(signatureBoards) && signatureBoards.length === 10
    && activationSignatures.chainId === network.chainId
    && activationSignatures.boardSetDigest === releaseEvidence.boardSetDigest
    && activationSignatures.releaseBindingDigest === releaseEvidence.releaseBindingDigest
    && activationSignatures.authorizationDigest === authorization.authorization_digest);
  requireBinding(authorizationBinding.chain_id === network.chainId
    && authorizationBinding.network === (network.chainId === 8453 ? "base-mainnet" : "base-sepolia")
    && authorizationBinding.git_commit === manifest.deploymentCommit);
  const expiresAt = Date.parse(String(authorization.expires_at_utc)) / 1000;
  requireBinding(Number.isSafeInteger(expiresAt) && canonicalUint(activationSignatures.expiresAt) === BigInt(expiresAt));
  const authorities = object(activationSignatures.authorities, "activation signature authorities");
  requireBinding(exactKeys(authorities, FUNDING_ROLES.map(([, field]) => field)));
  const authorityAddresses = FUNDING_ROLES.map(([, field]) => {
    const expected = getAddress(String(roles[field]));
    requireBinding(getAddress(String(authorities[field])) === expected);
    return expected;
  });
  requireBinding(new Set(authorityAddresses.map((value) => value.toLowerCase())).size === 3);
  const forbiddenAuthorities = ["deployer", "owner", "treasury", "resolver", "guardian", "objectiveVerifier"]
    .flatMap((field) => typeof roles[field] === "string" ? [getAddress(String(roles[field])).toLowerCase()] : [])
    .concat((governance.signers as string[]).map((value) => getAddress(value).toLowerCase()));
  requireBinding(authorityAddresses.every((value) => !forbiddenAuthorities.includes(value.toLowerCase())));
  const digest = digestBytes32(authorization.authorization_digest);
  const boardRows = problems.map((problem, boardIndex) => {
    const problemContracts = object(problem.contracts, `activation problem ${boardIndex} contracts`);
    const submissions = object(problemContracts.submissions, `activation problem ${boardIndex} submissions`);
    const pool = object(problemContracts.pool, `activation problem ${boardIndex} pool`);
    const bundleBoard = object(signatureBoards[boardIndex], `activation signature board ${boardIndex}`);
    requireBinding(exactKeys(bundleBoard, ["boardIndex", "problemId", "submissionManager", "nonce", "signatures"])
      && bundleBoard.boardIndex === boardIndex && String(bundleBoard.problemId) === String(problem.problemId)
      && getAddress(String(bundleBoard.submissionManager)) === getAddress(String(submissions.address)));
    const nonce = canonicalUint(bundleBoard.nonce);
    const signatures = bundleBoard.signatures as JsonObject[];
    requireBinding(Array.isArray(signatures) && signatures.length === 3);
    const verifiedSignatures = signatures.map((rawRecord, roleIndex) => {
      const record = object(rawRecord, `activation signature board ${boardIndex} role ${roleIndex}`);
      const [role, field] = FUNDING_ROLES[roleIndex];
      requireBinding(exactKeys(record, ["role", "signer", "signature"])
        && record.role === role && getAddress(String(record.signer)) === authorityAddresses[roleIndex]);
      const rawSignature = String(record.signature);
      requireBinding(/^0x[0-9a-fA-F]{130}$/.test(rawSignature));
      const rawS = BigInt(`0x${rawSignature.slice(66, 130)}`);
      const rawV = Number.parseInt(rawSignature.slice(130, 132), 16);
      requireBinding(rawS <= HALF_SECP256K1_ORDER && [27, 28].includes(rawV));
      const signature = Signature.from(rawSignature);
      requireBinding(signature.serialized.toLowerCase() === rawSignature.toLowerCase());
      const typedDigest = TypedDataEncoder.hash(
        { name: "P42SubmissionManager", version: "2", chainId: Number(network.chainId), verifyingContract: getAddress(String(submissions.address)) },
        FUNDING_TYPES,
        {
          role: keccak256(toUtf8Bytes(role)), boardSetDigest: digestBytes32(activationSignatures.boardSetDigest),
          releaseBindingDigest: digestBytes32(activationSignatures.releaseBindingDigest), authorizationDigest: digest,
          expiresAt: BigInt(expiresAt), nonce,
        },
      );
      requireBinding(recoverAddress(typedDigest, signature) === getAddress(String(roles[field])));
      return rawSignature;
    });
    return { problem, submissions, pool, nonce, signatures: verifiedSignatures };
  });
  const addresses = boardRows.flatMap(({ submissions, pool }) => [submissions.address, pool.address].map((value) => getAddress(String(value)).toLowerCase()));
  requireBinding(new Set(addresses).size === 20);
  const authorizationLabels = boardRows.map(({ problem }) => `board.${problem.problemId}.authorizeFunding`);
  const armLabels = boardRows.map(({ problem }) => `board.${problem.problemId}.armFunding`);
  const operations: JsonObject[] = [];
  for (const [boardIndex, { problem, submissions, nonce, signatures }] of boardRows.entries()) {
    operations.push({
      sequence: operations.length + 1, authority: "treasury", label: authorizationLabels[boardIndex], boardIndex,
      problemId: problem.problemId, to: getAddress(String(submissions.address)), expectedRuntimeCodeHash: submissions.runtimeCodeHash,
      value: "0", authorizationNonce: nonce.toString(), verifiedSignatureCount: 3,
      data: submissionsInterface.encodeFunctionData("authorizeFunding", [digest, expiresAt, nonce, signatures]), dependsOn: [],
    });
  }
  const addGovernanceOperation = (boardIndex: number, phase: "arm" | "open") => {
    const { problem, submissions, pool } = boardRows[boardIndex];
    const label = phase === "arm" ? armLabels[boardIndex] : `board.${problem.problemId}.setAcceptingFunds`;
    const target = phase === "arm" ? submissions : pool;
    const data = phase === "arm" ? submissionsInterface.encodeFunctionData("armFunding", [digest]) : poolInterface.encodeFunctionData("setAcceptingFunds", [true]);
    const salt = keccak256(toUtf8Bytes(`${authorization.authorization_digest}:${label}`));
    const operationId = keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [String(target.address), 0n, data, salt]));
    operations.push({
      sequence: operations.length + 1, authority: "governance", label, boardIndex, problemId: problem.problemId,
      to: getAddress(String(target.address)), expectedRuntimeCodeHash: target.runtimeCodeHash, value: "0", data,
      salt, operationId, dependsOn: phase === "arm" ? authorizationLabels : armLabels,
    });
  };
  for (let index = 0; index < 10; index += 1) addGovernanceOperation(index, "arm");
  for (let index = 0; index < 10; index += 1) addGovernanceOperation(index, "open");
  const body = {
    schema: "p42-funding-activation-plan/v2", chainId: network.chainId,
    network: network.chainId === 8453 ? "base-mainnet" : "base-sepolia",
    deploymentCommit: manifest.deploymentCommit, deploymentConfigHash: manifest.deploymentConfigHash,
    manifestBytesDigest: sha256Bytes(manifestBytes), releaseBindingDigest: releaseEvidence.releaseBindingDigest,
    capsuleDigest: releaseEvidence.capsuleDigest, slateDigest: releaseEvidence.slateDigest,
    releaseIndexDigest: releaseEvidence.releaseIndexDigest, authorizationDigest: authorization.authorization_digest,
    authorizationExpiresAt: expiresAt, authorizationBytesDigest: sha256Bytes(authorizationBytes),
    rpcAuthority,
    activationSignaturesDigest: sha256Canonical(activationSignatures), timelock: getAddress(String(timelock.address)),
    timelockRuntimeCodeHash: timelock.runtimeCodeHash, treasury: getAddress(String(roles.treasury)),
    governanceSigners: (governance.signers as string[]).map(getAddress), governanceThreshold: Number(governance.threshold),
    governanceDelaySeconds: Number(governance.delaySeconds),
    governanceOperationGraceSeconds: Number(governance.operationGracePeriodSeconds), boardCount: 10, operations,
  };
  return { ...body, planDigest: sha256Canonical(body) };
}

function exactKeys(value: JsonObject, keys: readonly string[]): boolean {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function verifyProductionPolicyBindings(
  policy: JsonObject,
  manifestBytes: Buffer,
  authorization: JsonObject,
  authorizationBytes: Buffer,
  trustRegistry: JsonObject,
): string {
  requireBinding(exactKeys(policy, ["schema_version", "environment", "deployment_manifest", "launch_authorization", "trust_registry"]));
  requireBinding(policy.schema_version === "p42-portal-production-trust-policy/v1" && policy.environment === "production");
  const manifestPin = object(policy.deployment_manifest, "production policy deployment manifest");
  const authorizationPin = object(policy.launch_authorization, "production policy launch authorization");
  const registryPin = object(policy.trust_registry, "production policy trust registry");
  requireBinding(exactKeys(manifestPin, ["sha256"])
    && exactKeys(authorizationPin, ["sha256", "authorization_digest"])
    && exactKeys(registryPin, ["path", "sha256"]));
  requireBinding(manifestPin.sha256 === sha256Bytes(manifestBytes));
  requireBinding(authorizationPin.sha256 === sha256Bytes(authorizationBytes)
    && authorizationPin.authorization_digest === authorization.authorization_digest);
  requireBinding(typeof registryPin.path === "string" && registryPin.path.startsWith("/etc/p42/")
    && registryPin.sha256 === sha256Canonical(trustRegistry));
  return registryPin.sha256 as string;
}

function readProductionTrustPolicy(): { policy: JsonObject; trustRegistry: JsonObject } {
  const policyBytes = readProtectedFile(PRODUCTION_PORTAL_TRUST_POLICY_PATH, MAX_ARTIFACT_BYTES);
  const rootBytes = readProtectedFile(PRODUCTION_PORTAL_TRUST_POLICY_ROOT, 256);
  if (!rootBytes.every((byte) => byte <= 0x7f)) throw new Error("protected portal trust policy root must be ASCII");
  const expectedPolicyDigest = rootBytes.toString("ascii").trim();
  if (!/^sha256:[0-9a-f]{64}$/.test(expectedPolicyDigest) || expectedPolicyDigest !== sha256Bytes(policyBytes)) {
    throw new Error("portal production trust policy does not match its protected root");
  }
  const policy = object(JSON.parse(policyBytes.toString("utf8")) as unknown, "production portal trust policy");
  const registryPin = object(policy.trust_registry, "production policy trust registry");
  const trustRegistry = object(readBoundedRegularJson(String(registryPin.path)), "trust registry");
  return { policy, trustRegistry };
}

const AUTHORIZER_ROLES = new Set([
  "production-launch-authority", "independent-security-authority", "governance-authority",
]);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function verifyLaunchAuthorization(authorization: JsonObject, trustRegistry: JsonObject, pinnedRegistryDigest: string): void {
  requireBinding(pinnedRegistryDigest === sha256Canonical(trustRegistry));
  requireBinding(trustRegistry.schema_version === "p42-attestation-trust-registry/v1" && trustRegistry.environment === "production");
  const { authorization_digest: claimedDigest, authorization_signatures: signaturesValue, ...unsigned } = authorization;
  const digest = sha256Canonical(unsigned);
  requireBinding(claimedDigest === digest);
  const issuedAt = String(authorization.issued_at_utc);
  requireBinding(Number.isFinite(Date.parse(issuedAt)));
  const authorizers = authorization.authorizers as JsonObject[];
  const signatures = signaturesValue as JsonObject[];
  const registrations = trustRegistry.registrations as JsonObject[];
  requireBinding(Array.isArray(authorizers) && authorizers.length === 3 && Array.isArray(signatures) && signatures.length === 3);
  requireBinding(Array.isArray(registrations));
  const seenRoles = new Set<string>();
  const seenKeys = new Set<string>();
  for (const authorizerValue of authorizers) {
    const authorizer = object(authorizerValue, "authorization authorizer");
    const role = String(authorizer.role);
    const publicKey = String(authorizer.public_key);
    requireBinding(AUTHORIZER_ROLES.has(role) && !seenRoles.has(role) && /^ed25519:[0-9a-f]{64}$/.test(publicKey) && !seenKeys.has(publicKey));
    seenRoles.add(role); seenKeys.add(publicKey);
    const signature = signatures.find((entry) => entry.signer_role === role);
    requireBinding(Boolean(signature) && signature!.algorithm === "ed25519" && signature!.public_key === publicKey
      && signature!.signed_hash === digest && signature!.signed_at_utc === issuedAt
      && /^ed25519:[0-9a-f]{128}$/.test(String(signature!.signature)));
    const trusted = registrations.some((entry) => {
      if (entry.attestation_class !== authorization.schema_version || entry.signer_role !== role || entry.public_key !== publicKey) return false;
      const identity = object(entry.identity, "trusted signer identity");
      const validFrom = Date.parse(String(entry.valid_from_utc));
      const validUntil = entry.valid_until_utc == null ? Number.POSITIVE_INFINITY : Date.parse(String(entry.valid_until_utc));
      return identity.name === authorizer.name && identity.organization === authorizer.organization
        && identity.professional_email === authorizer.professional_email
        && Number.isFinite(validFrom) && validFrom <= Date.parse(issuedAt) && Date.parse(issuedAt) <= validUntil;
    });
    requireBinding(trusted);
    const rawKey = Buffer.from(publicKey.slice(8), "hex");
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawKey]), format: "der", type: "spki" });
    const message = Buffer.from(`P42-ATTESTATION-V2\n${authorization.schema_version}\n${role}\n${digest}\n${issuedAt}`, "ascii");
    requireBinding(verify(null, message, key, Buffer.from(String(signature!.signature).slice(8), "hex")));
  }
  requireBinding(seenRoles.size === AUTHORIZER_ROLES.size);
}

function verifyCheckpointAttestation(attestation: JsonObject, checkpointBytes: Buffer, trustRegistry: JsonObject, nowSeconds: number): void {
  requireBinding(JSON.stringify(Object.keys(attestation).sort()) === JSON.stringify([
    "checkpointDigest", "publicKey", "schema", "signature", "signedAtUtc", "signerRole",
  ]));
  requireBinding(attestation.schema === "p42-indexer-checkpoint-attestation/v1"
    && attestation.signerRole === "indexer-checkpoint-authority"
    && attestation.checkpointDigest === sha256Bytes(checkpointBytes));
  const publicKey = String(attestation.publicKey);
  const signedAt = String(attestation.signedAtUtc);
  const signedAtSeconds = Date.parse(signedAt) / 1000;
  const checkpoint = object(JSON.parse(checkpointBytes.toString("utf8")), "attested checkpoint");
  const checkpointTimestamp = Number(object(checkpoint.range, "attested checkpoint range").toBlockTimestamp);
  requireBinding(/^ed25519:[0-9a-f]{64}$/.test(publicKey) && Number.isFinite(signedAtSeconds)
    && signedAtSeconds >= checkpointTimestamp && signedAtSeconds <= nowSeconds + 30);
  const trusted = (trustRegistry.registrations as JsonObject[]).some((entry) => {
    if (entry.attestation_class !== attestation.schema || entry.signer_role !== attestation.signerRole || entry.public_key !== publicKey) return false;
    const from = Date.parse(String(entry.valid_from_utc)) / 1000;
    const until = entry.valid_until_utc == null ? Number.POSITIVE_INFINITY : Date.parse(String(entry.valid_until_utc)) / 1000;
    return Number.isFinite(from) && from <= signedAtSeconds && signedAtSeconds <= until;
  });
  requireBinding(trusted && /^ed25519:[0-9a-f]{128}$/.test(String(attestation.signature)));
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey.slice(8), "hex")]), format: "der", type: "spki" });
  const message = Buffer.from(`P42-ATTESTATION-V2\n${attestation.schema}\n${attestation.signerRole}\n${attestation.checkpointDigest}\n${signedAt}`, "ascii");
  requireBinding(verify(null, message, key, Buffer.from(String(attestation.signature).slice(8), "hex")));
}

function requireBinding(condition: boolean): void {
  if (!condition) throw new Error("deployment manifest and checkpoint bindings do not match");
}

function validateBindings(manifest: JsonObject, checkpoint: JsonObject, problem: Problem): { board: JsonObject; manifestProblem: JsonObject } {
  const binding = object(checkpoint.manifestBinding, "checkpoint.manifestBinding");
  const indexer = object(manifest.indexer, "manifest.indexer");
  const network = object(manifest.network, "manifest.network");
  requireBinding(same(binding.deploymentCommit, manifest.deploymentCommit));
  requireBinding(same(manifest.deploymentConfigHash, computePortalDeploymentConfigHash(manifest)));
  requireBinding(same(binding.deploymentConfigHash, manifest.deploymentConfigHash));
  requireBinding(binding.chainId === network.chainId && binding.startBlock === indexer.startBlock);
  requireBinding(JSON.stringify(checkpoint.finalityPolicy) === JSON.stringify(indexer.finalityPolicy));
  const range = object(checkpoint.range, "checkpoint.range");
  requireBinding(range.fromBlock === indexer.startBlock && range.toBlock === indexer.indexedThroughBlock);

  const problems = manifest.problems as JsonObject[];
  const boards = checkpoint.boards as JsonObject[];
  requireBinding(problems.length === boards.length && problems.length === Object.keys(object(binding.boards, "binding.boards")).length);
  const seenIds = new Set<string>();
  const seenSlugs = new Set<string>();
  for (let index = 0; index < problems.length; index += 1) {
    const manifestProblem = object(problems[index], `manifest.problems[${index}]`);
    const board = object(boards[index], `checkpoint.boards[${index}]`);
    const id = String(manifestProblem.problemId);
    requireBinding(board.problemId === id && board.problemSlug === manifestProblem.problemSlug);
    requireBinding(!seenIds.has(id) && !seenSlugs.has(String(board.problemSlug)));
    seenIds.add(id); seenSlugs.add(String(board.problemSlug));
    const expected = object(object(binding.boards, "binding.boards")[id], `binding.boards.${id}`);
    const contracts = object(manifestProblem.contracts, `manifest.problems[${index}].contracts`);
    for (const key of ["pool", "ledger", "submissions", "challenges"]) {
      const deployed = object(contracts[key], `manifest contract ${key}`);
      const bound = object(expected[key], `checkpoint contract ${key}`);
      requireBinding(same(bound.address, deployed.address) && same(bound.deployedCodeHash, deployed.deployedCodeHash) && same(bound.abiHash, deployed.abiHash));
    }
    requireBinding(manifestProblem.pool === object(contracts.pool, "pool").address);
    requireBinding(manifestProblem.ledger === object(contracts.ledger, "ledger").address);
    requireBinding(manifestProblem.submissionManager === object(contracts.submissions, "submissions").address);
    requireBinding(manifestProblem.challengeManager === object(contracts.challenges, "challenges").address);
  }
  for (const key of ["timelock", "registry"]) {
    const deployed = object(object(manifest.contracts, "manifest.contracts")[key], `manifest.contracts.${key}`);
    const bound = object(object(binding.contracts, "binding.contracts")[key], `binding.contracts.${key}`);
    requireBinding(same(bound.address, deployed.address) && same(bound.deployedCodeHash, deployed.deployedCodeHash) && same(bound.abiHash, deployed.abiHash));
  }
  const matchIndex = problems.findIndex((entry) => entry.problemSlug === problem.slug);
  requireBinding(matchIndex >= 0 && String(problems[matchIndex].problemId) === String(matchIndex + 1));
  return { board: boards[matchIndex], manifestProblem: problems[matchIndex] };
}

export function configuredIndexerArtifactPaths(env: IndexerProvenanceEnvironment = process.env): IndexerArtifactPaths | null {
  const deploymentManifestPath = env.P42_DEPLOYMENT_MANIFEST_PATH?.trim();
  const indexerCheckpointPath = env.P42_INDEXER_CHECKPOINT_PATH?.trim();
  if (!deploymentManifestPath || !indexerCheckpointPath) return null;
  const launchAuthorizationPath = env.P42_LAUNCH_AUTHORIZATION_PATH?.trim();
  const indexerCheckpointAttestationPath = env.P42_INDEXER_CHECKPOINT_ATTESTATION_PATH?.trim();
  const fundingActivationPlanPath = env.P42_FUNDING_ACTIVATION_PLAN_PATH?.trim();
  const fundingActivationSignaturesPath = env.P42_FUNDING_ACTIVATION_SIGNATURES_PATH?.trim();
  const fundingActivationCompletionPath = env.P42_FUNDING_ACTIVATION_COMPLETION_PATH?.trim();
  const activationRpcOperatorRegistryPath = env.P42_ACTIVATION_RPC_OPERATOR_REGISTRY_PATH?.trim();
  const activationRpcOperatorRegistryTrustedRoot = env.P42_ACTIVATION_RPC_OPERATOR_REGISTRY_TRUSTED_ROOT?.trim();
  const maxAgeText = env.P42_PORTAL_CHECKPOINT_MAX_AGE_SECONDS?.trim();
  const checkpointMaxAgeSeconds = maxAgeText ? Number(maxAgeText) : null;
  const funding = [launchAuthorizationPath, fundingActivationPlanPath, fundingActivationSignaturesPath,
    fundingActivationCompletionPath, indexerCheckpointAttestationPath, activationRpcOperatorRegistryPath,
    activationRpcOperatorRegistryTrustedRoot];
  if (funding.some(Boolean) && (!funding.every(Boolean) || !Number.isSafeInteger(checkpointMaxAgeSeconds) || checkpointMaxAgeSeconds! < 1 || checkpointMaxAgeSeconds! > 300)) return { deploymentManifestPath, indexerCheckpointPath };
  return funding.every(Boolean) ? {
    deploymentManifestPath, indexerCheckpointPath,
    indexerCheckpointAttestationPath,
    launchAuthorizationPath, fundingActivationPlanPath, fundingActivationSignaturesPath, fundingActivationCompletionPath,
    activationRpcOperatorRegistryPath, activationRpcOperatorRegistryTrustedRoot,
    checkpointMaxAgeSeconds: checkpointMaxAgeSeconds!,
  } : { deploymentManifestPath, indexerCheckpointPath };
}

function localOnly(problem: Problem): ChainProvenance {
  return {
    settlementState: "local-only", chain: "Base Sepolia", chainId: 84532,
    donationWalletAddress: null, poolAddress: null, poolRuntimeCodeHash: null,
    deploymentTransactionHash: null, registryAddress: null, problemRegistryId: null,
    verifierImageHash: problem.verifierImage.startsWith("sha256:") ? problem.verifierImage : null,
    admissionMatrixHash: null, deploymentCommit: null, indexedThroughBlock: null,
    indexedFrontierAtoms: null, checkpointBlock: null, reconciliationOk: false,
    fundingAuthorizationDigest: null, activationCompletionDigest: null, activationFinalizedBlock: null,
    source: "static-portal-data",
    note: "Phase 0 portal state only: complete, matching deployment and indexer artifacts are unavailable.",
  };
}

function provenanceFromArtifacts(problem: Problem, manifest: JsonObject, checkpoint: JsonObject): ChainProvenance {
    const aggregate = object(checkpoint.reconstruction, "checkpoint.reconstruction");
    requireBinding(aggregate.ok === true && aggregate.complete === true);
    const { board, manifestProblem } = validateBindings(manifest, checkpoint, problem);
    const reconstruction = object(board.reconstruction, "board.reconstruction");
    requireBinding(reconstruction.ok === true && reconstruction.complete === true && reconstruction.lifecycleSnapshotComplete === true);
    requireBinding((reconstruction.checks as JsonObject[]).every((check) => check.ok === true));
    requireBinding((aggregate.checks as JsonObject[]).every((check) => check.ok === true));
    const registry = object(object(manifest.contracts, "manifest.contracts").registry, "manifest.contracts.registry");
    const pool = object(object(manifestProblem.contracts, "problem.contracts").pool, "problem.contracts.pool");
    requireBinding(ADDRESS.test(String(registry.address)) && HASH.test(String(pool.runtimeCodeHash)));
    const frontierAtomsValue = object(board.onchain, "board.onchain").bestScoreAtoms;
    requireBinding(typeof frontierAtomsValue === "string" && /^-?[0-9]+$/.test(frontierAtomsValue));
    const frontierAtoms = frontierAtomsValue as string;
    const checkpointBlock = object(checkpoint.range, "checkpoint.range").toBlock as number;
    return {
      settlementState: "manifest-pending",
      chain: "Base Sepolia", chainId: 84532,
      donationWalletAddress: null, poolAddress: null,
      poolRuntimeCodeHash: pool.runtimeCodeHash as string,
      deploymentTransactionHash: null,
      registryAddress: registry.address as string,
      problemRegistryId: String(manifestProblem.problemId),
      verifierImageHash: manifestProblem.verifierImageHash as string,
      admissionMatrixHash: manifestProblem.admissionMatrixHash as string,
      deploymentCommit: manifest.deploymentCommit as string,
      indexedThroughBlock: checkpointBlock,
      indexedFrontierAtoms: frontierAtoms,
      checkpointBlock,
      fundingAuthorizationDigest: null,
      activationCompletionDigest: null,
      activationFinalizedBlock: null,
      reconciliationOk: true,
      source: "indexer-artifacts-v2",
      note: "Verified deployment and complete indexer reconstruction evidence. Funding publication remains disabled.",
    };
}

export function activatedProvenanceFromArtifacts(
  problem: Problem,
  manifest: JsonObject,
  manifestBytes: Buffer,
  checkpoint: JsonObject,
  checkpointBytes: Buffer,
  authorization: JsonObject,
  authorizationBytes: Buffer,
  productionPolicy: JsonObject,
  trustRegistry: JsonObject,
  checkpointAttestation: JsonObject,
  activationSignatures: JsonObject,
  plan: JsonObject,
  completion: JsonObject,
  rpcRegistry: JsonObject,
  checkpointMaxAgeSeconds = 300,
  nowSeconds = Math.floor(Date.now() / 1000),
): ChainProvenance {
  requireBinding(JSON.stringify(canonicalize(JSON.parse(checkpointBytes.toString("utf8"))))
    === JSON.stringify(canonicalize(checkpoint)));
  const pending = provenanceFromArtifacts(problem, manifest, checkpoint);
  requireBinding(manifest.releaseMode === "production" && manifest.status === "governance-setup-complete");
  requireBinding(authorization.schema_version === "p42-production-launch-authorization/v1" && authorization.status === "authorized");
  const trustRegistryDigest = verifyProductionPolicyBindings(
    productionPolicy, manifestBytes, authorization, authorizationBytes, trustRegistry,
  );
  verifyLaunchAuthorization(authorization, trustRegistry, trustRegistryDigest);
  verifyCheckpointAttestation(checkpointAttestation, checkpointBytes, trustRegistry, nowSeconds);
  requireBinding(/^sha256:[0-9a-f]{64}$/.test(String(authorization.authorization_digest)));
  requireBinding(plan.schema === "p42-funding-activation-plan/v2" && completion.schema === "p42-funding-activation-completion/v2");
  const canonicalPlan = reconstructCanonicalActivationPlan(
    manifest, manifestBytes, authorization, authorizationBytes, activationSignatures,
    object(plan.rpcAuthority, "activation plan RPC authority"),
    rpcRegistry,
  );
  requireBinding(JSON.stringify(canonicalize(plan)) === JSON.stringify(canonicalize(canonicalPlan)));
  const { planDigest, ...planBody } = plan;
  const { completionDigest, ...completionBody } = completion;
  requireBinding(planDigest === sha256Canonical(planBody) && completionDigest === sha256Canonical(completionBody));
  requireBinding(plan.manifestBytesDigest === sha256Bytes(manifestBytes) && completion.manifestBytesDigest === plan.manifestBytesDigest);
  const authorizationArtifacts = object(authorization.artifacts, "authorization.artifacts");
  const manifestRef = object(authorizationArtifacts.deployment_manifest, "authorization deployment manifest reference");
  requireBinding(manifestRef.sha256 === plan.manifestBytesDigest);
  requireBinding(plan.authorizationDigest === authorization.authorization_digest && completion.authorizationDigest === authorization.authorization_digest);
  requireBinding(JSON.stringify(canonicalize(completion.rpcAuthority)) === JSON.stringify(canonicalize(checkpoint.activationEvidence && object(checkpoint.activationEvidence, "activation evidence").rpcAuthority))
    && object(completion.rpcAuthority, "completion RPC authority").registryDigest === object(plan.rpcAuthority, "plan RPC authority").registryDigest);
  const observedAuthority = object(completion.rpcAuthority, "completion RPC authority");
  for (const role of ["primary", "secondary"]) {
    const observed = object(observedAuthority[role], `completion RPC ${role}`);
    const planned = object(object(plan.rpcAuthority, "plan RPC authority")[role], `plan RPC ${role}`);
    requireBinding(observed.operatorId === planned.operatorId
      && observed.endpointOrigin === planned.endpointOrigin
      && observed.endpointProfileDigest === planned.endpointProfileDigest
      && observed.observedRawChainId === `0x${Number(plan.chainId).toString(16)}`);
  }
  requireBinding(plan.authorizationBytesDigest === sha256Bytes(authorizationBytes)
    && completion.authorizationBytesDigest === plan.authorizationBytesDigest);
  const authorizationExpiry = Date.parse(String(authorization.expires_at_utc)) / 1000;
  requireBinding(Number.isSafeInteger(authorizationExpiry) && nowSeconds <= authorizationExpiry
    && authorizationExpiry === plan.authorizationExpiresAt && authorizationExpiry === completion.authorizationExpiresAt);
  requireBinding(Number.isSafeInteger(completion.finalizedBlockTimestamp)
    && Number(completion.finalizedBlockTimestamp) <= authorizationExpiry);
  requireBinding(completion.planDigest === plan.planDigest && completion.chainId === plan.chainId && completion.chainId === object(manifest.network, "manifest.network").chainId);
  const releaseBinding = object(authorization.release_binding, "authorization.release_binding");
  requireBinding(releaseBinding.chain_id === completion.chainId && releaseBinding.network === completion.network);
  requireBinding(completion.deploymentCommit === manifest.deploymentCommit && completion.deploymentConfigHash === manifest.deploymentConfigHash);
  requireBinding(completion.releaseBindingDigest === object(manifest.releaseEvidence, "manifest.releaseEvidence").releaseBindingDigest);
  const range = object(checkpoint.range, "checkpoint.range");
  const activationEvidence = object(checkpoint.activationEvidence, "checkpoint.activationEvidence");
  const completionAnchor = object(activationEvidence.completionAnchor, "checkpoint completion anchor");
  requireBinding(checkpoint.schema === "p42-prizes/indexer-checkpoint/v4"
    && activationEvidence.schema === "p42-funding-activation-checkpoint/v1"
    && activationEvidence.planDigest === plan.planDigest
    && completionAnchor.completionDigest === completion.completionDigest
    && completion.finalizedBlockNumber === completionAnchor.blockNumber
    && same(completion.finalizedBlockHash, completionAnchor.blockHash)
    && completion.finalizedBlockTimestamp === completionAnchor.blockTimestamp
    && Number(completionAnchor.blockNumber) <= Number(range.toBlock)
    && Number(completionAnchor.blockTimestamp) <= Number(range.toBlockTimestamp)
    && activationEvidence.finalizedBlockNumber === range.toBlock
    && same(activationEvidence.finalizedBlockHash, range.toBlockHash));
  requireBinding(Number.isSafeInteger(range.toBlockTimestamp)
    && Number(range.toBlockTimestamp) <= nowSeconds + 30
    && nowSeconds - Number(range.toBlockTimestamp) <= checkpointMaxAgeSeconds);

  const manifestProblems = manifest.problems as JsonObject[];
  const checkpointBoards = checkpoint.boards as JsonObject[];
  const completionBoards = completion.boards as JsonObject[];
  const planOperations = Array.isArray(plan.operations)
    ? plan.operations.map((operation, index) => object(operation, `activation plan operation ${index}`))
    : [];
  const checkpointOperations = Array.isArray(activationEvidence.operations)
    ? activationEvidence.operations.map((operation, index) => object(operation, `checkpoint activation operation ${index}`))
    : [];
  requireBinding(manifestProblems.length === 10 && checkpointBoards.length === 10
    && completionBoards.length === 10 && planOperations.length === 30 && checkpointOperations.length === 20);
  const governanceOperations = planOperations.slice(10);
  const evidenceIds = new Set<string>();
  const evidenceLabels = new Set<string>();
  for (let index = 0; index < governanceOperations.length; index += 1) {
    const planned = governanceOperations[index];
    const attested = checkpointOperations[index];
    requireBinding(attested.sequence === planned.sequence
      && attested.label === planned.label
      && String(attested.problemId) === String(planned.problemId)
      && same(attested.operationId, planned.operationId)
      && attested.state === 2
      && !evidenceIds.has(String(attested.operationId).toLowerCase())
      && !evidenceLabels.has(String(attested.label)));
    evidenceIds.add(String(attested.operationId).toLowerCase());
    evidenceLabels.add(String(attested.label));
  }
  const digestHex = `0x${String(authorization.authorization_digest).slice(7)}`;
  const seen = new Set<string>();
  for (let row = 0; row < 10; row += 1) {
    const manifestProblem = object(manifestProblems[row], `manifest problem ${row}`);
    const board = object(checkpointBoards[row], `checkpoint board ${row}`);
    const activated = object(completionBoards[row], `activation completion board ${row}`);
    const id = String(manifestProblem.problemId);
    requireBinding(!seen.has(id) && board.problemId === id && activated.problemId === id && board.problemSlug === manifestProblem.problemSlug);
    seen.add(id);
    const contracts = object(manifestProblem.contracts, `manifest problem ${row} contracts`);
    const pool = object(contracts.pool, `manifest pool ${row}`);
    const submissions = object(contracts.submissions, `manifest submissions ${row}`);
    const onchain = object(board.onchain, `checkpoint board ${row} onchain`);
    const armMatches = planOperations.filter((operation) => operation.label === `board.${id}.armFunding`
      && String(operation.problemId) === id && same(operation.to, submissions.address));
    const openMatches = planOperations.filter((operation) => operation.label === `board.${id}.setAcceptingFunds`
      && String(operation.problemId) === id && same(operation.to, pool.address));
    requireBinding(armMatches.length === 1 && openMatches.length === 1);
    const armEvidence = object(activated.armOperation, `activation completion board ${row} arm operation`);
    const openEvidence = object(activated.openOperation, `activation completion board ${row} open operation`);
    requireBinding(armEvidence.state === 2 && openEvidence.state === 2
      && same(armEvidence.operationId, armMatches[0].operationId)
      && same(openEvidence.operationId, openMatches[0].operationId)
      && checkpointOperations.some((operation) => same(operation.operationId, armEvidence.operationId) && operation.state === 2)
      && checkpointOperations.some((operation) => same(operation.operationId, openEvidence.operationId) && operation.state === 2));
    requireBinding(same(activated.pool, pool.address) && same(activated.submissionManager, submissions.address));
    requireBinding(same(activated.poolRuntimeCodeHash, pool.runtimeCodeHash));
    requireBinding(activated.fundingArmed === true && activated.acceptingFunds === true);
    requireBinding(onchain.fundingArmed === true && onchain.poolAcceptingFunds === true);
    requireBinding(same(activated.authorizedFundingDigest, digestHex) && same(activated.fundingAuthorizationDigest, digestHex));
    requireBinding(same(onchain.authorizedFundingDigest, digestHex) && same(onchain.fundingAuthorizationDigest, digestHex));
    requireBinding(String(onchain.fundingAuthorizationExpiresAt) === String(authorizationExpiry)
      && activated.fundingAuthorizationExpiresAt === authorizationExpiry);
  }
  const index = manifestProblems.findIndex((entry) => entry.problemSlug === problem.slug);
  requireBinding(index >= 0 && String(manifestProblems[index].problemId) === String(index + 1));
  const manifestProblem = object(manifestProblems[index], "manifest problem");
  const pool = object(object(manifestProblem.contracts, "manifest problem contracts").pool, "manifest pool");
  const network = object(manifest.network, "manifest.network");
  const mainnet = network.chainId === 8453 && network.name === "baseMainnet";
  const testnet = network.chainId === 84532 && network.name === "baseSepolia";
  requireBinding(mainnet || testnet);
  return {
    ...pending,
    settlementState: mainnet ? "mainnet-indexed" : "testnet-indexed",
    chain: mainnet ? "Base" : "Base Sepolia",
    chainId: network.chainId as number,
    donationWalletAddress: pool.address as string,
    poolAddress: pool.address as string,
    deploymentTransactionHash: pool.txHash as string,
    fundingAuthorizationDigest: authorization.authorization_digest as string,
    activationCompletionDigest: completion.completionDigest as string,
    activationFinalizedBlock: completion.finalizedBlockNumber as number,
    note: "Funding target is bound to a validated launch authorization and finalized activation checkpoint.",
  };
}

function readValidatedArtifacts(paths: IndexerArtifactPaths): { manifest: JsonObject; manifestBytes: Buffer; checkpoint: JsonObject; checkpointBytes: Buffer } {
  const manifestFile = readBoundedRegularJsonWithBytes(paths.deploymentManifestPath);
  const manifest = object(manifestFile.value, "manifest");
  const checkpointFile = readBoundedRegularJsonWithBytes(paths.indexerCheckpointPath);
  const checkpoint = object(checkpointFile.value, "checkpoint");
  validateSchema(manifest, deploymentSchema, deploymentSchema as JsonSchema, "manifest");
  const checkpointSchema = checkpoint.schema === "p42-prizes/indexer-checkpoint/v2"
    ? checkpointV2Schema
    : checkpoint.schema === "p42-prizes/indexer-checkpoint/v3"
      ? checkpointV3Schema
      : checkpoint.schema === "p42-prizes/indexer-checkpoint/v4"
        ? checkpointV4Schema
      : null;
  if (!checkpointSchema) throw new Error("unsupported indexer checkpoint schema");
  validateSchema(checkpoint, checkpointSchema, checkpointSchema as JsonSchema, "checkpoint");
  return { manifest, manifestBytes: manifestFile.bytes, checkpoint, checkpointBytes: checkpointFile.bytes };
}

/**
 * Apply the production activation/attestation gate to the cohort as one unit.
 * A caller receives every board from the same parsed artifact generation or an
 * exception; per-board success is intentionally not representable.
 */
export function activatedIndexerSnapshotFromArtifacts(
  problems: readonly Problem[],
  artifacts: ActivatedArtifactBundle,
): ActivatedIndexerSnapshot {
  requireBinding(problems.length === 10);
  requireBinding(artifacts.checkpoint.schema === "p42-prizes/indexer-checkpoint/v4");
  const entries = problems.map((problem) => {
    const provenance = activatedProvenanceFromArtifacts(
      problem,
      artifacts.manifest,
      artifacts.manifestBytes,
      artifacts.checkpoint,
      artifacts.checkpointBytes,
      artifacts.authorization,
      artifacts.authorizationBytes,
      artifacts.productionPolicy,
      artifacts.trustRegistry,
      artifacts.checkpointAttestation,
      artifacts.activationSignatures,
      artifacts.plan,
      artifacts.completion,
      artifacts.rpcRegistry,
      artifacts.checkpointMaxAgeSeconds,
      artifacts.nowSeconds,
    );
    requireBinding(
      provenance.reconciliationOk
      && (provenance.settlementState === "testnet-indexed" || provenance.settlementState === "mainnet-indexed"),
    );
    return [problem.slug, provenance] as const;
  });
  const network = object(artifacts.manifest.network, "activated manifest network");
  const releaseEvidence = object(artifacts.manifest.releaseEvidence, "activated manifest release evidence");
  return {
    manifest: artifacts.manifest,
    checkpoint: artifacts.checkpoint,
    provenance: new Map(entries),
    highWaterIdentity: {
      checkpointDigest: sha256Bytes(artifacts.checkpointBytes),
      releaseBindingDigest: String(releaseEvidence.releaseBindingDigest),
      authorizationDigest: String(artifacts.authorization.authorization_digest),
      chainId: Number(network.chainId),
      chainName: String(network.name),
      deploymentCommit: String(artifacts.manifest.deploymentCommit),
      deploymentConfigHash: String(artifacts.manifest.deploymentConfigHash),
    },
  };
}

/** Load only an exact-ten, activated, freshly attested artifact generation. */
export function loadActivatedIndexerSnapshot(
  problems: readonly Problem[],
  paths = configuredIndexerArtifactPaths(),
): ActivatedIndexerSnapshot | null {
  if (!paths?.launchAuthorizationPath
    || !paths.fundingActivationPlanPath
    || !paths.fundingActivationSignaturesPath
    || !paths.fundingActivationCompletionPath
    || !paths.indexerCheckpointAttestationPath
    || !paths.activationRpcOperatorRegistryPath
    || !paths.activationRpcOperatorRegistryTrustedRoot) return null;
  try {
    const { manifest, manifestBytes, checkpoint, checkpointBytes } = readValidatedArtifacts(paths);
    const authorizationFile = readBoundedRegularJsonWithBytes(paths.launchAuthorizationPath);
    const productionTrust = readProductionTrustPolicy();
    const completion = object(readBoundedRegularJson(paths.fundingActivationCompletionPath), "activation completion");
    validateSchema(completion, completionSchema, completionSchema as JsonSchema, "activation completion");
    const authorization = object(authorizationFile.value, "authorization");
    const registryDigest = object(object(authorization.artifacts, "authorization artifacts").activation_rpc_operator_registry, "authorization RPC registry").sha256;
    const rpcRegistry = loadProtectedActivationRpcOperatorRegistry(
      paths.activationRpcOperatorRegistryPath, paths.activationRpcOperatorRegistryTrustedRoot, String(registryDigest),
    );
    return activatedIndexerSnapshotFromArtifacts(problems, {
      manifest,
      manifestBytes,
      checkpoint,
      checkpointBytes,
      authorization,
      authorizationBytes: authorizationFile.bytes,
      productionPolicy: productionTrust.policy,
      trustRegistry: productionTrust.trustRegistry,
      checkpointAttestation: object(readBoundedRegularJson(paths.indexerCheckpointAttestationPath), "checkpoint attestation"),
      activationSignatures: object(readBoundedRegularJson(paths.fundingActivationSignaturesPath), "activation signatures"),
      plan: object(readBoundedRegularJson(paths.fundingActivationPlanPath), "activation plan"),
      completion,
      rpcRegistry,
      checkpointMaxAgeSeconds: paths.checkpointMaxAgeSeconds,
    });
  } catch {
    return null;
  }
}

export function loadIndexerProvenance(problem: Problem, paths = configuredIndexerArtifactPaths()): ChainProvenance {
  if (!paths) return localOnly(problem);
  try {
    const { manifest, manifestBytes, checkpoint, checkpointBytes } = readValidatedArtifacts(paths);
    if (paths.launchAuthorizationPath && paths.fundingActivationPlanPath && paths.fundingActivationSignaturesPath && paths.fundingActivationCompletionPath && paths.indexerCheckpointAttestationPath && paths.activationRpcOperatorRegistryPath && paths.activationRpcOperatorRegistryTrustedRoot) {
      const authorizationFile = readBoundedRegularJsonWithBytes(paths.launchAuthorizationPath);
      const authorization = object(authorizationFile.value, "authorization");
      const productionTrust = readProductionTrustPolicy();
      const checkpointAttestation = object(readBoundedRegularJson(paths.indexerCheckpointAttestationPath), "checkpoint attestation");
      const activationSignatures = object(readBoundedRegularJson(paths.fundingActivationSignaturesPath), "activation signatures");
      const plan = object(readBoundedRegularJson(paths.fundingActivationPlanPath), "activation plan");
      const completion = object(readBoundedRegularJson(paths.fundingActivationCompletionPath), "activation completion");
      validateSchema(completion, completionSchema, completionSchema as JsonSchema, "activation completion");
      const registryDigest = object(object(authorization.artifacts, "authorization artifacts").activation_rpc_operator_registry, "authorization RPC registry").sha256;
      const rpcRegistry = loadProtectedActivationRpcOperatorRegistry(
        paths.activationRpcOperatorRegistryPath, paths.activationRpcOperatorRegistryTrustedRoot, String(registryDigest),
      );
      return activatedProvenanceFromArtifacts(problem, manifest, manifestBytes, checkpoint, checkpointBytes, authorization, authorizationFile.bytes, productionTrust.policy, productionTrust.trustRegistry, checkpointAttestation, activationSignatures, plan, completion, rpcRegistry, paths.checkpointMaxAgeSeconds);
    }
    return provenanceFromArtifacts(problem, manifest, checkpoint);
  } catch { return localOnly(problem); }
}

/** Read one artifact generation and derive every board from that immutable parse. */
export function loadIndexerProvenanceSnapshot(
  problems: readonly Problem[],
  paths = configuredIndexerArtifactPaths(),
): ReadonlyMap<string, ChainProvenance> {
  if (!paths) return new Map(problems.map((problem) => [problem.slug, localOnly(problem)]));
  try {
    const { manifest, manifestBytes, checkpoint, checkpointBytes } = readValidatedArtifacts(paths);
    const hasFunding = paths.launchAuthorizationPath && paths.fundingActivationPlanPath && paths.fundingActivationSignaturesPath && paths.fundingActivationCompletionPath && paths.indexerCheckpointAttestationPath && paths.activationRpcOperatorRegistryPath && paths.activationRpcOperatorRegistryTrustedRoot;
    const authorizationFile = hasFunding ? readBoundedRegularJsonWithBytes(paths.launchAuthorizationPath!) : null;
    const authorization = authorizationFile ? object(authorizationFile.value, "authorization") : null;
    const productionTrust = hasFunding ? readProductionTrustPolicy() : null;
    const checkpointAttestation = hasFunding ? object(readBoundedRegularJson(paths.indexerCheckpointAttestationPath!), "checkpoint attestation") : null;
    const activationSignatures = hasFunding ? object(readBoundedRegularJson(paths.fundingActivationSignaturesPath!), "activation signatures") : null;
    const plan = hasFunding ? object(readBoundedRegularJson(paths.fundingActivationPlanPath!), "activation plan") : null;
    const completion = hasFunding ? object(readBoundedRegularJson(paths.fundingActivationCompletionPath!), "activation completion") : null;
    const registryDigest = authorization ? object(object(authorization.artifacts, "authorization artifacts").activation_rpc_operator_registry, "authorization RPC registry").sha256 : null;
    const rpcRegistry = hasFunding ? loadProtectedActivationRpcOperatorRegistry(
      paths.activationRpcOperatorRegistryPath!, paths.activationRpcOperatorRegistryTrustedRoot!, String(registryDigest),
    ) : null;
    if (completion) validateSchema(completion, completionSchema, completionSchema as JsonSchema, "activation completion");
    const entries = problems.map((problem) => [problem.slug, hasFunding
      ? activatedProvenanceFromArtifacts(problem, manifest, manifestBytes, checkpoint, checkpointBytes, authorization!, authorizationFile!.bytes, productionTrust!.policy, productionTrust!.trustRegistry, checkpointAttestation!, activationSignatures!, plan!, completion!, rpcRegistry!, paths.checkpointMaxAgeSeconds)
      : provenanceFromArtifacts(problem, manifest, checkpoint)] as const);
    return new Map(entries);
  } catch {
    return new Map(problems.map((problem) => [problem.slug, localOnly(problem)]));
  }
}
