import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { createHash, createPublicKey, verify } from "node:crypto";
import { keccak256, toUtf8Bytes } from "ethers";
import deploymentSchema from "@/schemas/deployment-manifest-v2.schema.json";
import checkpointSchema from "@/schemas/indexer-checkpoint-v2.schema.json";
import completionSchema from "@/schemas/funding-activation-completion.schema.json";
import type { ChainProvenance, Problem } from "@/lib/types";

const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;

if (typeof window !== "undefined") throw new Error("indexer provenance artifacts are server-only");

type JsonSchema = Record<string, unknown>;
type JsonObject = Record<string, unknown>;

export interface IndexerArtifactPaths {
  deploymentManifestPath: string;
  indexerCheckpointPath: string;
  indexerCheckpointAttestationPath?: string;
  launchAuthorizationPath?: string;
  fundingActivationPlanPath?: string;
  fundingActivationCompletionPath?: string;
  trustRegistryPath?: string;
  trustRegistryDigest?: string;
  checkpointMaxAgeSeconds?: number;
}

export interface IndexerProvenanceEnvironment {
  [key: string]: string | undefined;
  P42_DEPLOYMENT_MANIFEST_PATH?: string;
  P42_INDEXER_CHECKPOINT_PATH?: string;
  P42_INDEXER_CHECKPOINT_ATTESTATION_PATH?: string;
  P42_LAUNCH_AUTHORIZATION_PATH?: string;
  P42_FUNDING_ACTIVATION_PLAN_PATH?: string;
  P42_FUNDING_ACTIVATION_COMPLETION_PATH?: string;
  P42_ATTESTATION_TRUST_REGISTRY_PATH?: string;
  P42_ATTESTATION_TRUST_REGISTRY_SHA256?: string;
  P42_PORTAL_CHECKPOINT_MAX_AGE_SECONDS?: string;
}

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
    network: manifest.network, governance: manifest.governance, roles: manifest.roles,
    parameters: manifest.parameters, contracts: manifest.contracts,
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
  const matchIndex = problems.findIndex((entry) => entry.problemSlug === problem.slug && String(entry.problemId) === String(problem.id));
  requireBinding(matchIndex >= 0);
  return { board: boards[matchIndex], manifestProblem: problems[matchIndex] };
}

export function configuredIndexerArtifactPaths(env: IndexerProvenanceEnvironment = process.env): IndexerArtifactPaths | null {
  const deploymentManifestPath = env.P42_DEPLOYMENT_MANIFEST_PATH?.trim();
  const indexerCheckpointPath = env.P42_INDEXER_CHECKPOINT_PATH?.trim();
  if (!deploymentManifestPath || !indexerCheckpointPath) return null;
  const launchAuthorizationPath = env.P42_LAUNCH_AUTHORIZATION_PATH?.trim();
  const indexerCheckpointAttestationPath = env.P42_INDEXER_CHECKPOINT_ATTESTATION_PATH?.trim();
  const fundingActivationPlanPath = env.P42_FUNDING_ACTIVATION_PLAN_PATH?.trim();
  const fundingActivationCompletionPath = env.P42_FUNDING_ACTIVATION_COMPLETION_PATH?.trim();
  const trustRegistryPath = env.P42_ATTESTATION_TRUST_REGISTRY_PATH?.trim();
  const trustRegistryDigest = env.P42_ATTESTATION_TRUST_REGISTRY_SHA256?.trim();
  const maxAgeText = env.P42_PORTAL_CHECKPOINT_MAX_AGE_SECONDS?.trim();
  const checkpointMaxAgeSeconds = maxAgeText ? Number(maxAgeText) : null;
  const funding = [launchAuthorizationPath, fundingActivationPlanPath, fundingActivationCompletionPath, indexerCheckpointAttestationPath, trustRegistryPath, trustRegistryDigest];
  if (funding.some(Boolean) && (!funding.every(Boolean) || !Number.isSafeInteger(checkpointMaxAgeSeconds) || checkpointMaxAgeSeconds! < 1 || checkpointMaxAgeSeconds! > 300)) return { deploymentManifestPath, indexerCheckpointPath };
  return funding.every(Boolean) ? {
    deploymentManifestPath, indexerCheckpointPath,
    indexerCheckpointAttestationPath,
    launchAuthorizationPath, fundingActivationPlanPath, fundingActivationCompletionPath,
    trustRegistryPath, trustRegistryDigest, checkpointMaxAgeSeconds: checkpointMaxAgeSeconds!,
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
  trustRegistry: JsonObject,
  trustRegistryDigest: string,
  checkpointAttestation: JsonObject,
  plan: JsonObject,
  completion: JsonObject,
  checkpointMaxAgeSeconds = 300,
  nowSeconds = Math.floor(Date.now() / 1000),
): ChainProvenance {
  const pending = provenanceFromArtifacts(problem, manifest, checkpoint);
  requireBinding(manifest.releaseMode === "production" && manifest.status === "governance-setup-complete");
  requireBinding(authorization.schema_version === "p42-production-launch-authorization/v1" && authorization.status === "authorized");
  verifyLaunchAuthorization(authorization, trustRegistry, trustRegistryDigest);
  verifyCheckpointAttestation(checkpointAttestation, checkpointBytes, trustRegistry, nowSeconds);
  requireBinding(/^sha256:[0-9a-f]{64}$/.test(String(authorization.authorization_digest)));
  requireBinding(plan.schema === "p42-funding-activation-plan/v1" && completion.schema === "p42-funding-activation-completion/v1");
  const { planDigest, ...planBody } = plan;
  const { completionDigest, ...completionBody } = completion;
  requireBinding(planDigest === sha256Canonical(planBody) && completionDigest === sha256Canonical(completionBody));
  requireBinding(plan.manifestBytesDigest === sha256Bytes(manifestBytes) && completion.manifestBytesDigest === plan.manifestBytesDigest);
  const authorizationArtifacts = object(authorization.artifacts, "authorization.artifacts");
  const manifestRef = object(authorizationArtifacts.deployment_manifest, "authorization deployment manifest reference");
  requireBinding(manifestRef.sha256 === plan.manifestBytesDigest);
  requireBinding(plan.authorizationDigest === authorization.authorization_digest && completion.authorizationDigest === authorization.authorization_digest);
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
  requireBinding(Number(completion.finalizedBlockNumber) <= Number(range.toBlock));
  requireBinding(Number.isSafeInteger(range.toBlockTimestamp)
    && Number(range.toBlockTimestamp) <= nowSeconds + 30
    && nowSeconds - Number(range.toBlockTimestamp) <= checkpointMaxAgeSeconds);

  const manifestProblems = manifest.problems as JsonObject[];
  const checkpointBoards = checkpoint.boards as JsonObject[];
  const completionBoards = completion.boards as JsonObject[];
  requireBinding(manifestProblems.length === 10 && checkpointBoards.length === 10 && completionBoards.length === 10);
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
    requireBinding(same(activated.pool, pool.address) && same(activated.submissionManager, submissions.address));
    requireBinding(same(activated.poolRuntimeCodeHash, pool.runtimeCodeHash));
    requireBinding(activated.fundingArmed === true && activated.acceptingFunds === true);
    requireBinding(onchain.fundingArmed === true && onchain.poolAcceptingFunds === true);
    requireBinding(same(activated.authorizedFundingDigest, digestHex) && same(activated.fundingAuthorizationDigest, digestHex));
    requireBinding(same(onchain.authorizedFundingDigest, digestHex) && same(onchain.fundingAuthorizationDigest, digestHex));
    requireBinding(String(onchain.fundingAuthorizationExpiresAt) === String(authorizationExpiry)
      && activated.fundingAuthorizationExpiresAt === authorizationExpiry);
  }
  const index = manifestProblems.findIndex((entry) => String(entry.problemId) === String(problem.id) && entry.problemSlug === problem.slug);
  requireBinding(index >= 0);
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
  validateSchema(checkpoint, checkpointSchema, checkpointSchema as JsonSchema, "checkpoint");
  return { manifest, manifestBytes: manifestFile.bytes, checkpoint, checkpointBytes: checkpointFile.bytes };
}

export function loadIndexerProvenance(problem: Problem, paths = configuredIndexerArtifactPaths()): ChainProvenance {
  if (!paths) return localOnly(problem);
  try {
    const { manifest, manifestBytes, checkpoint, checkpointBytes } = readValidatedArtifacts(paths);
    if (paths.launchAuthorizationPath && paths.fundingActivationPlanPath && paths.fundingActivationCompletionPath && paths.indexerCheckpointAttestationPath && paths.trustRegistryPath && paths.trustRegistryDigest) {
      const authorizationFile = readBoundedRegularJsonWithBytes(paths.launchAuthorizationPath);
      const authorization = object(authorizationFile.value, "authorization");
      const trustRegistry = object(readBoundedRegularJson(paths.trustRegistryPath), "trust registry");
      const checkpointAttestation = object(readBoundedRegularJson(paths.indexerCheckpointAttestationPath), "checkpoint attestation");
      const plan = object(readBoundedRegularJson(paths.fundingActivationPlanPath), "activation plan");
      const completion = object(readBoundedRegularJson(paths.fundingActivationCompletionPath), "activation completion");
      validateSchema(completion, completionSchema, completionSchema as JsonSchema, "activation completion");
      return activatedProvenanceFromArtifacts(problem, manifest, manifestBytes, checkpoint, checkpointBytes, authorization, authorizationFile.bytes, trustRegistry, paths.trustRegistryDigest, checkpointAttestation, plan, completion, paths.checkpointMaxAgeSeconds);
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
    const hasFunding = paths.launchAuthorizationPath && paths.fundingActivationPlanPath && paths.fundingActivationCompletionPath && paths.indexerCheckpointAttestationPath && paths.trustRegistryPath && paths.trustRegistryDigest;
    const authorizationFile = hasFunding ? readBoundedRegularJsonWithBytes(paths.launchAuthorizationPath!) : null;
    const authorization = authorizationFile ? object(authorizationFile.value, "authorization") : null;
    const trustRegistry = hasFunding ? object(readBoundedRegularJson(paths.trustRegistryPath!), "trust registry") : null;
    const checkpointAttestation = hasFunding ? object(readBoundedRegularJson(paths.indexerCheckpointAttestationPath!), "checkpoint attestation") : null;
    const plan = hasFunding ? object(readBoundedRegularJson(paths.fundingActivationPlanPath!), "activation plan") : null;
    const completion = hasFunding ? object(readBoundedRegularJson(paths.fundingActivationCompletionPath!), "activation completion") : null;
    if (completion) validateSchema(completion, completionSchema, completionSchema as JsonSchema, "activation completion");
    const entries = problems.map((problem) => [problem.slug, hasFunding
      ? activatedProvenanceFromArtifacts(problem, manifest, manifestBytes, checkpoint, checkpointBytes, authorization!, authorizationFile!.bytes, trustRegistry!, paths.trustRegistryDigest!, checkpointAttestation!, plan!, completion!, paths.checkpointMaxAgeSeconds)
      : provenanceFromArtifacts(problem, manifest, checkpoint)] as const);
    return new Map(entries);
  } catch {
    return new Map(problems.map((problem) => [problem.slug, localOnly(problem)]));
  }
}
