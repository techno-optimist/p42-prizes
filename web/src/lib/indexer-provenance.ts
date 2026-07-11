import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { keccak256, toUtf8Bytes } from "ethers";
import deploymentSchema from "@/schemas/deployment-manifest-v2.schema.json";
import checkpointSchema from "@/schemas/indexer-checkpoint-v2.schema.json";
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
}

export interface IndexerProvenanceEnvironment {
  [key: string]: string | undefined;
  P42_DEPLOYMENT_MANIFEST_PATH?: string;
  P42_INDEXER_CHECKPOINT_PATH?: string;
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

function readBoundedRegularJson(path: string): unknown {
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
    return JSON.parse(bytes.toString("utf8")) as unknown;
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
  return deploymentManifestPath && indexerCheckpointPath ? { deploymentManifestPath, indexerCheckpointPath } : null;
}

function localOnly(problem: Problem): ChainProvenance {
  return {
    settlementState: "local-only", chain: "Base Sepolia", chainId: 84532,
    donationWalletAddress: null, poolAddress: null, poolRuntimeCodeHash: null,
    deploymentTransactionHash: null, registryAddress: null, problemRegistryId: null,
    verifierImageHash: problem.verifierImage.startsWith("sha256:") ? problem.verifierImage : null,
    admissionMatrixHash: null, deploymentCommit: null, indexedThroughBlock: null,
    indexedFrontierAtoms: null, checkpointBlock: null, reconciliationOk: false,
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
      reconciliationOk: true,
      source: "indexer-artifacts-v2",
      note: "Verified deployment and complete indexer reconstruction evidence. Funding publication remains disabled.",
    };
}

function readValidatedArtifacts(paths: IndexerArtifactPaths): { manifest: JsonObject; checkpoint: JsonObject } {
  const manifest = object(readBoundedRegularJson(paths.deploymentManifestPath), "manifest");
  const checkpoint = object(readBoundedRegularJson(paths.indexerCheckpointPath), "checkpoint");
  validateSchema(manifest, deploymentSchema, deploymentSchema as JsonSchema, "manifest");
  validateSchema(checkpoint, checkpointSchema, checkpointSchema as JsonSchema, "checkpoint");
  return { manifest, checkpoint };
}

export function loadIndexerProvenance(problem: Problem, paths = configuredIndexerArtifactPaths()): ChainProvenance {
  if (!paths) return localOnly(problem);
  try {
    const { manifest, checkpoint } = readValidatedArtifacts(paths);
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
    const { manifest, checkpoint } = readValidatedArtifacts(paths);
    const entries = problems.map((problem) => [problem.slug, provenanceFromArtifacts(problem, manifest, checkpoint)] as const);
    return new Map(entries);
  } catch {
    return new Map(problems.map((problem) => [problem.slug, localOnly(problem)]));
  }
}
