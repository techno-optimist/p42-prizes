import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { link, lstat, open, unlink } from "node:fs/promises";
import { basename, delimiter, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { keccak256 } from "ethers";

import {
  ADMISSION_MATRIX_HASH_ALGORITHM,
  admissionMatrixHashForDigest,
  assertAdmissionMatrixAnchor,
  boardCeremonyConfig,
  readCeremonyConfig,
  validateDeploymentTimestamps,
} from "./deployment-ceremony-helper.js";
import { readContractsArtifactJsonSyncWithBytes, readContractsConfigJsonSync, readContractsConfigJsonSyncWithBytes } from "./strict-json-helper.js";

export const MULTIBOARD_CEREMONY_SCHEMA = "p42-prizes/multi-board-ceremony/v1";
export const PRODUCTION_RELEASE_SLATE_SCHEMA = "p42-prizes/production-release-slate/v2";
export const PRODUCTION_RELEASE_INDEX_SCHEMA = "p42-prizes/production-release-index/v1";
export const RELEASE_MODES = Object.freeze({ PRODUCTION: "production", FIXTURE: "fixture" });
const PRODUCTION_BOARD_SET_PATH = fileURLToPath(new URL("../../protocol/production-board-set-v1.json", import.meta.url));
const productionBoardSet = readContractsConfigJsonSync(PRODUCTION_BOARD_SET_PATH);
if (
  Object.keys(productionBoardSet ?? {}).sort().join(",") !== "boards,evidence,schema,status"
  || productionBoardSet?.schema !== "p42-prizes/production-board-set/v1"
  || productionBoardSet?.status !== "frozen-source-cohort"
  || !Array.isArray(productionBoardSet?.boards)
  || productionBoardSet.boards.length !== 10
  || new Set(productionBoardSet.boards).size !== 10
  || productionBoardSet.boards.some((slug) => typeof slug !== "string" || !/^[a-z0-9][a-z0-9-]*$/.test(slug))
) throw new Error("canonical production board set is invalid");
const evidenceRef = productionBoardSet.evidence;
if (Object.keys(evidenceRef ?? {}).sort().join(",") !== "path,schema_path,schema_sha256,sha256" || evidenceRef.path !== "docs/provenance/production-board-evidence-v1.json" || evidenceRef.schema_path !== "schemas/production-board-evidence.schema.json") throw new Error("canonical production board evidence reference is invalid");
const evidencePath = fileURLToPath(new URL(`../../${evidenceRef.path}`, import.meta.url));
const evidenceSchemaPath = fileURLToPath(new URL(`../../${evidenceRef.schema_path}`, import.meta.url));
const { bytes: productionEvidenceBytes, value: productionEvidence } = readContractsConfigJsonSyncWithBytes(evidencePath);
const { bytes: productionEvidenceSchemaBytes, value: productionEvidenceSchema } = readContractsConfigJsonSyncWithBytes(evidenceSchemaPath);
if (`sha256:${createHash("sha256").update(productionEvidenceBytes).digest("hex")}` !== evidenceRef.sha256 || `sha256:${createHash("sha256").update(productionEvidenceSchemaBytes).digest("hex")}` !== evidenceRef.schema_sha256) throw new Error("canonical production board evidence digest mismatch");
const productionEvidenceValidator = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(productionEvidenceValidator);
const validateProductionEvidenceSchema = productionEvidenceValidator.compile(productionEvidenceSchema);
export function validateProductionBoardEvidence(evidence) {
  if (!validateProductionEvidenceSchema(evidence)) throw new Error("canonical production board evidence fails schema validation");
  return evidence;
}
validateProductionBoardEvidence(productionEvidence);
if (productionEvidence?.schema !== "p42-prizes/production-board-evidence/v1" || canonical(productionEvidence?.boards?.map((board) => board?.slug)) !== canonical([productionBoardSet.boards[0], productionBoardSet.boards[6]])) throw new Error("canonical production board evidence identity mismatch");
export const PRODUCTION_LAUNCH_SLUGS = Object.freeze([...productionBoardSet.boards]);

const RELEASE_IDENTITY_KEYS = ["problemId", "problemSlug", "verifierVersion", "specHash", "verifierSourceDigest", "verifierImageDigest", "admissionMatrixDigest", "objectiveGuestElfPath", "objectiveGuestElfDigest", "objectiveGuestElfSha256", "objectiveProgramVKey"];
const RELEASE_BOARD_KEYS = ["problemId", "problemSlug", "problemPath", "problemPackageDigest", "verifierVersion", "specHash", "verifierSourceDigest", "verifierImageDigest", "admissionMatrixPath", "admissionMatrixDigest", "objectiveGuestElfPath", "objectiveGuestElfDigest", "objectiveGuestElfSha256", "objectiveProgramVKey"];
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const PLACEHOLDER_DIGEST_RE = /^sha256:([0-9a-f])\1{63}$/;
const IMAGE_REPOSITORY_RE = /^(?=.{1,255}$)(?:localhost|[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?)\/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;
const IMAGE_RELEASE_KEYS = ["schema_version", "published_at_utc", "source_commit", "source_archive_digest", "registry_base", "platforms", "boards", "manifest_mutation", "publication_journal_hash", "dossier_hash"];
const IMAGE_BOARD_KEYS = ["slug", "problem_id", "version", "source_hash", "repository", "index_digest", "immutable_reference", "platform_manifests"];
const IMAGE_PLATFORM_KEYS = ["platform", "manifest_digest", "manifest_size", "config_digest", "config_size", "layer_count", "labels", "runtime"];
const IMAGE_LABEL_KEYS = ["org.opencontainers.image.revision", "io.projectforty2.verifier.source-sha256", "io.projectforty2.verifier.source-algorithm", "io.projectforty2.verifier.problem-id", "io.projectforty2.verifier.version"];

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function sha256Canonical(value) {
  return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
}

export function releaseBoardIdentity(problem, index) {
  return {
    problemId: String(problem.problemId ?? index + 1),
    problemSlug: problem.problemSlug,
    verifierVersion: problem.verifierVersion,
    specHash: problem.specHash,
    verifierSourceDigest: problem.verifierSourceDigest,
    verifierImageDigest: problem.verifierImageDigest,
    admissionMatrixDigest: problem.admissionMatrixDigest,
    objectiveGuestElfPath: problem.objectiveGuestElfPath,
    objectiveGuestElfDigest: problem.objectiveGuestElfDigest,
    objectiveGuestElfSha256: problem.objectiveGuestElfSha256,
    objectiveProgramVKey: problem.objectiveProgramVKey,
  };
}

export function validateProductionReleaseSlate(slate, problems) {
  const root = exactObject(slate, ["schema", "mode", "status", "generatedAt", "sourceCommit", "imageRegistry", "objectiveVerifier", "boards", "slateDigest"], "production release slate");
  if (root.schema !== PRODUCTION_RELEASE_SLATE_SCHEMA || root.mode !== RELEASE_MODES.PRODUCTION || root.status !== "ready") throw new Error("production release slate must have production/ready identity");
  if (!/^[0-9a-f]{40}$/.test(root.sourceCommit) || !Number.isFinite(Date.parse(root.generatedAt))) throw new Error("production release slate provenance is invalid");
  exactObject(root.imageRegistry, ["path", "digest"], "production release slate.imageRegistry");
  if (!DIGEST_RE.test(root.imageRegistry.digest) || PLACEHOLDER_DIGEST_RE.test(root.imageRegistry.digest)) throw new Error("production image registry digest is placeholder or invalid");
  exactObject(root.objectiveVerifier, ["artifactPath", "artifactDigest", "runtimeCodehash", "proofsActive"], "production release slate.objectiveVerifier");
  if (!DIGEST_RE.test(root.objectiveVerifier.artifactDigest) || PLACEHOLDER_DIGEST_RE.test(root.objectiveVerifier.artifactDigest)
      || !/^0x[0-9a-f]{64}$/.test(root.objectiveVerifier.runtimeCodehash)
      || /^0x([0-9a-f])\1{63}$/.test(root.objectiveVerifier.runtimeCodehash)
      || root.objectiveVerifier.proofsActive !== false) throw new Error("production objective verifier artifact is placeholder, active, or invalid");
  if (!Array.isArray(root.boards) || root.boards.length !== 10) throw new Error("production release slate must contain exactly 10 boards");
  root.boards.forEach((board, index) => {
    exactObject(board, RELEASE_BOARD_KEYS, `production release slate.boards[${index}]`);
    if (board.problemId !== String(index + 1)) throw new Error(`production release slate board ${index + 1} must have ordered problemId ${index + 1}`);
    if (board.problemPath !== `problems/${board.problemSlug}`) throw new Error(`production board ${index + 1} problemPath must be canonical`);
    for (const field of ["problemPackageDigest", "verifierSourceDigest", "verifierImageDigest", "admissionMatrixDigest", "objectiveGuestElfDigest"]) {
      if (!DIGEST_RE.test(board[field]) || PLACEHOLDER_DIGEST_RE.test(board[field]) || /local-dev|placeholder/i.test(board[field])) throw new Error(`production board ${index + 1} ${field} is placeholder or invalid`);
    }
    if (board.objectiveGuestElfSha256 !== `0x${board.objectiveGuestElfDigest.slice("sha256:".length)}`) throw new Error(`production board ${index + 1} guest ELF SHA-256 bytes32 mismatch`);
    for (const field of ["objectiveGuestElfSha256", "objectiveProgramVKey"]) {
      if (!/^0x[0-9a-f]{64}$/.test(board[field]) || /^0x([0-9a-f])\1{63}$/.test(board[field])) throw new Error(`production board ${index + 1} ${field} is placeholder or invalid`);
    }
  });
  for (const field of ["problemPackageDigest", "verifierSourceDigest", "verifierImageDigest", "admissionMatrixDigest", "objectiveGuestElfDigest"]) {
    if (new Set(root.boards.map((board) => board[field])).size !== 10) throw new Error(`production ${field} values must be distinct`);
  }
  const { slateDigest, ...body } = root;
  if (sha256Canonical(body) !== slateDigest) throw new Error("production release slate digest mismatch");
  if (problems !== undefined) {
    if (!Array.isArray(problems) || problems.length !== 10) throw new Error("production release requires exactly 10 complete boards");
    problems.forEach((problem, index) => {
      const expected = Object.fromEntries(RELEASE_IDENTITY_KEYS.map((key) => [key, root.boards[index][key]]));
      if (canonical(releaseBoardIdentity(problem, index)) !== canonical(expected)) {
        throw new Error(`production board identity ${index + 1} does not match the closed release slate`);
      }
    });
  }
  return root;
}

export function validateVerifierImageReleaseDossier(dossier, { sourceCommit, problems, now = Date.now() } = {}) {
  const root = exactObject(dossier, IMAGE_RELEASE_KEYS, "verifier image release dossier");
  if (root.schema_version !== "p42-verifier-image-release/v1") throw new Error("verifier image release dossier schema is invalid");
  const publishedAt = Date.parse(root.published_at_utc);
  const canonicalPublishedAt = Number.isFinite(publishedAt) ? new Date(publishedAt).toISOString().replace(".000Z", "Z") : null;
  if (!Number.isFinite(now) || !Number.isFinite(publishedAt) || canonicalPublishedAt !== root.published_at_utc || publishedAt > now) throw new Error("verifier image release timestamp is invalid or future-dated");
  if (!/^[0-9a-f]{40}$/.test(root.source_commit) || (sourceCommit !== undefined && root.source_commit !== sourceCommit)) throw new Error("verifier image release source commit mismatch");
  for (const field of ["source_archive_digest", "publication_journal_hash", "dossier_hash"]) if (!DIGEST_RE.test(root[field]) || PLACEHOLDER_DIGEST_RE.test(root[field])) throw new Error(`verifier image release ${field} is invalid`);
  if (!IMAGE_REPOSITORY_RE.test(root.registry_base) || canonical(root.platforms) !== canonical(["linux/amd64", "linux/arm64"]) || root.manifest_mutation !== "none") throw new Error("verifier image release registry/platform policy mismatch");
  if (!Array.isArray(root.boards) || root.boards.length !== 10) throw new Error("verifier image release must contain exactly 10 boards");
  root.boards.forEach((entry, index) => {
    const board = exactObject(entry, IMAGE_BOARD_KEYS, `verifier image release board ${index + 1}`);
    const problem = problems?.[index];
    if (board.slug !== PRODUCTION_LAUNCH_SLUGS[index] || board.repository !== `${root.registry_base}/${board.slug}` || !IMAGE_REPOSITORY_RE.test(board.repository)) throw new Error(`verifier image release board ${index + 1} canonical identity mismatch`);
    if (problem && (board.slug !== problem.problemSlug || board.problem_id !== problem.problemSlug || board.version !== problem.verifierVersion || board.source_hash !== problem.verifierSourceDigest || board.index_digest !== problem.verifierImageDigest)) throw new Error(`verifier image release board ${index + 1} identity mismatch`);
    if (board.slug !== board.problem_id || !DIGEST_RE.test(board.source_hash) || !DIGEST_RE.test(board.index_digest) || PLACEHOLDER_DIGEST_RE.test(board.source_hash) || PLACEHOLDER_DIGEST_RE.test(board.index_digest) || board.immutable_reference !== `${board.repository}@${board.index_digest}`) throw new Error(`verifier image release board ${index + 1} provenance mismatch`);
    if (!Array.isArray(board.platform_manifests) || board.platform_manifests.length !== 2) throw new Error(`verifier image release board ${index + 1} platform matrix is incomplete`);
    board.platform_manifests.forEach((entryPlatform, platformIndex) => {
      const platform = exactObject(entryPlatform, IMAGE_PLATFORM_KEYS, `verifier image release board ${index + 1} platform ${platformIndex + 1}`);
      const expectedPlatform = root.platforms[platformIndex];
      if (platform.platform !== expectedPlatform || !DIGEST_RE.test(platform.manifest_digest) || !DIGEST_RE.test(platform.config_digest) || !Number.isSafeInteger(platform.manifest_size) || platform.manifest_size < 1 || !Number.isSafeInteger(platform.config_size) || platform.config_size < 1 || !Number.isSafeInteger(platform.layer_count) || platform.layer_count < 1) throw new Error(`verifier image release board ${index + 1} platform evidence is invalid`);
      const labels = exactObject(platform.labels, IMAGE_LABEL_KEYS, `verifier image release board ${index + 1} labels`);
      if (labels["org.opencontainers.image.revision"] !== root.source_commit || labels["io.projectforty2.verifier.source-sha256"] !== board.source_hash || labels["io.projectforty2.verifier.source-algorithm"] !== "p42-source-tree-sha256/v2" || labels["io.projectforty2.verifier.problem-id"] !== board.problem_id || labels["io.projectforty2.verifier.version"] !== board.version) throw new Error(`verifier image release board ${index + 1} labels mismatch`);
      const runtime = exactObject(platform.runtime, ["user", "workdir", "entrypoint", "cmd"], `verifier image release board ${index + 1} runtime`);
      if (!new Set(["inherited-root-overridden-by-runner", "65534", "65534:65534"]).has(runtime.user) || runtime.workdir !== `/repo/problems/${board.slug}` || runtime.entrypoint !== null || canonical(runtime.cmd) !== "[]") throw new Error(`verifier image release board ${index + 1} runtime mismatch`);
    });
  });
  const { dossier_hash: claimed, ...body } = root;
  if (sha256Canonical(body) !== claimed) throw new Error("verifier image release dossier hash mismatch");
  return root;
}

export function createProductionReleaseSlate({
  generatedAt,
  sourceCommit,
  imageRegistryPath,
  imageRegistryBytes,
  imageDossier,
  objectiveVerifierArtifactPath,
  objectiveVerifierArtifactBytes,
  objectiveVerifierArtifact,
  problems,
  now = Date.now(),
} = {}) {
  if (!/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/.test(imageRegistryPath ?? "")) throw new Error("production image dossier path must be repository-relative");
  if (!(Buffer.isBuffer(imageRegistryBytes) || imageRegistryBytes instanceof Uint8Array)) throw new Error("production image dossier exact bytes are required");
  const dossier = validateVerifierImageReleaseDossier(imageDossier, { sourceCommit, problems, now });
  if (!/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/.test(objectiveVerifierArtifactPath ?? "")) throw new Error("objective verifier artifact path must be repository-relative");
  if (!(Buffer.isBuffer(objectiveVerifierArtifactBytes) || objectiveVerifierArtifactBytes instanceof Uint8Array)) throw new Error("objective verifier artifact exact bytes are required");
  const objectiveVerifierDeployedBytecode = objectiveVerifierArtifact?.deployedBytecode;
  if (typeof objectiveVerifierDeployedBytecode !== "string" || !/^0x(?:[0-9a-fA-F]{2})+$/.test(objectiveVerifierDeployedBytecode)) throw new Error("objective verifier artifact must contain nonempty deployedBytecode");
  const objectiveVerifierRuntimeCodehash = keccak256(objectiveVerifierDeployedBytecode);
  const generatedAtMs = Date.parse(generatedAt);
  const canonicalGeneratedAt = Number.isFinite(generatedAtMs) ? new Date(generatedAtMs).toISOString().replace(".000Z", "Z") : null;
  if (!Number.isFinite(generatedAtMs) || canonicalGeneratedAt !== generatedAt || generatedAtMs < Date.parse(dossier.published_at_utc) || generatedAtMs > now) throw new Error("production slate generatedAt is invalid, future-dated, or predates image publication");
  const body = {
    schema: PRODUCTION_RELEASE_SLATE_SCHEMA,
    mode: RELEASE_MODES.PRODUCTION,
    status: "ready",
    generatedAt,
    sourceCommit,
    imageRegistry: {
      path: imageRegistryPath,
      digest: `sha256:${createHash("sha256").update(imageRegistryBytes).digest("hex")}`,
    },
    objectiveVerifier: {
      artifactPath: objectiveVerifierArtifactPath,
      artifactDigest: `sha256:${createHash("sha256").update(objectiveVerifierArtifactBytes).digest("hex")}`,
      runtimeCodehash: objectiveVerifierRuntimeCodehash,
      proofsActive: false,
    },
    boards: problems.map((problem, index) => ({
      problemId: String(index + 1),
      problemSlug: problem.problemSlug,
      problemPath: `problems/${problem.problemSlug}`,
      problemPackageDigest: problem.verifierSourceDigest,
      verifierVersion: problem.verifierVersion,
      specHash: problem.specHash,
      verifierSourceDigest: problem.verifierSourceDigest,
      verifierImageDigest: problem.verifierImageDigest,
      admissionMatrixPath: problem.admissionMatrixPath,
      admissionMatrixDigest: problem.admissionMatrixDigest,
      objectiveGuestElfPath: problem.objectiveGuestElfPath,
      objectiveGuestElfDigest: problem.objectiveGuestElfDigest,
      objectiveGuestElfSha256: problem.objectiveGuestElfSha256,
      objectiveProgramVKey: problem.objectiveProgramVKey,
    })),
  };
  const slate = { ...body, slateDigest: sha256Canonical(body) };
  return validateProductionReleaseSlate(slate, problems);
}

export async function publishProductionReleaseSlate(slate, directory, {
  trustedRoot,
  storage = { open, link, lstat, unlink },
  beforeDirectoryFsync,
} = {}) {
  validateProductionReleaseSlate(slate);
  const root = resolve(trustedRoot ?? "");
  const publicationDirectory = resolve(directory);
  const rel = relative(root, publicationDirectory);
  if (!trustedRoot || (rel && (rel === ".." || rel.startsWith(`..${sep}`)))) throw new Error("slate publication directory must be within an explicit trusted root");
  const held = [];
  for (const path of [root, ...(rel ? rel.split(sep).map((_, index, parts) => join(root, ...parts.slice(0, index + 1))) : [])]) {
    const handle = await storage.open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (!metadata.isDirectory() || (typeof process.getuid === "function" && metadata.uid !== process.getuid()) || (metadata.mode & 0o022) !== 0) throw new Error("slate publication trusted parent is unsafe");
    held.push({ path, handle, metadata });
  }
  const target = join(publicationDirectory, `${slate.slateDigest.slice("sha256:".length)}.slate.json`);
  const temporary = join(publicationDirectory, `.${basename(target)}.${process.pid}.${Date.now()}.tmp`);
  const bytes = Buffer.from(`${canonical(slate)}\n`);
  const assertParentsHeld = async () => {
    for (const entry of held) {
      const current = await storage.lstat(entry.path);
      if (!current.isDirectory() || current.dev !== entry.metadata.dev || current.ino !== entry.metadata.ino) throw new Error("slate publication trusted parent was replaced");
    }
  };
  let temporaryHandle;
  let targetHandle;
  try {
    temporaryHandle = await storage.open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o444);
    await temporaryHandle.writeFile(bytes); await temporaryHandle.sync(); await temporaryHandle.close(); temporaryHandle = undefined;
    await assertParentsHeld();
    try { await storage.link(temporary, target); } catch (error) { if (error.code !== "EEXIST") throw error; }
    await storage.unlink(temporary);
    const before = await storage.lstat(target);
    targetHandle = await storage.open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = await targetHandle.stat();
    if (!before.isFile() || !opened.isFile() || before.dev !== opened.dev || before.ino !== opened.ino || opened.nlink !== 1 || opened.size !== bytes.length || (opened.mode & 0o777) !== 0o444 || (typeof process.getuid === "function" && opened.uid !== process.getuid())) throw new Error("published slate target metadata is unsafe");
    const stored = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < stored.length) {
      const { bytesRead } = await targetHandle.read(stored, offset, stored.length - offset, offset);
      if (bytesRead === 0) throw new Error("published slate target was truncated");
      offset += bytesRead;
    }
    if (!stored.equals(bytes)) throw new Error("content-addressed slate path contains different bytes");
    await assertParentsHeld();
    if (beforeDirectoryFsync) await beforeDirectoryFsync({ target, bytes });
    await held.at(-1).handle.sync();
    const finalMetadata = await storage.lstat(target);
    if (finalMetadata.dev !== opened.dev || finalMetadata.ino !== opened.ino || finalMetadata.size !== opened.size || finalMetadata.nlink !== 1 || (finalMetadata.mode & 0o777) !== 0o444) throw new Error("published slate target changed before durable return");
    const finalStored = Buffer.alloc(opened.size);
    let finalOffset = 0;
    while (finalOffset < finalStored.length) {
      const { bytesRead } = await targetHandle.read(finalStored, finalOffset, finalStored.length - finalOffset, finalOffset);
      if (bytesRead === 0) throw new Error("published slate target was truncated during final descriptor read");
      finalOffset += bytesRead;
    }
    if (!finalStored.equals(bytes)) throw new Error("published slate target bytes changed before durable return");
  } finally {
    if (temporaryHandle) await temporaryHandle.close();
    if (targetHandle) await targetHandle.close();
    try { await storage.unlink(temporary); } catch {}
    for (const entry of held.reverse()) await entry.handle.close();
  }
  return { digest: slate.slateDigest, uri: `sha256://${slate.slateDigest.slice(7)}`, path: target };
}

export function createProductionReleaseIndex({ sourceCommit, generatedAt, capsule, slate } = {}) {
  const generatedAtMs = Date.parse(generatedAt);
  const canonicalGeneratedAt = Number.isFinite(generatedAtMs) ? new Date(generatedAtMs).toISOString().replace(".000Z", "Z") : null;
  if (!/^[0-9a-f]{40}$/.test(sourceCommit ?? "") || canonicalGeneratedAt !== generatedAt) throw new Error("release index provenance is invalid or noncanonical");
  for (const [label, publication] of [["capsule", capsule], ["slate", slate]]) {
    if (!publication || !DIGEST_RE.test(publication.digest ?? "") || publication.uri !== `sha256://${publication.digest.slice(7)}`) throw new Error(`release index ${label} publication is invalid`);
  }
  const body = {
    schema: PRODUCTION_RELEASE_INDEX_SCHEMA,
    sourceCommit,
    generatedAt,
    capsule: { digest: capsule.digest, uri: capsule.uri },
    slate: { digest: slate.digest, uri: slate.uri },
  };
  return { ...body, indexDigest: sha256Canonical(body) };
}

export function validateProductionReleaseIndex(index) {
  exactObject(index, ["schema", "sourceCommit", "generatedAt", "capsule", "slate", "indexDigest"], "production release index");
  if (index.schema !== PRODUCTION_RELEASE_INDEX_SCHEMA) throw new Error("production release index schema is invalid");
  const expected = createProductionReleaseIndex(index);
  if (expected.indexDigest !== index.indexDigest) throw new Error("production release index digest mismatch");
  return index;
}

export async function publishProductionReleaseIndex(index, directory, {
  trustedRoot,
  storage = { open, link, lstat, unlink },
} = {}) {
  validateProductionReleaseIndex(index);
  const root = resolve(trustedRoot ?? "");
  const publicationDirectory = resolve(directory);
  const rel = relative(root, publicationDirectory);
  if (!trustedRoot || (rel && (rel === ".." || rel.startsWith(`..${sep}`)))) throw new Error("release index publication directory must be within an explicit trusted root");
  const held = [];
  for (const path of [root, ...(rel ? rel.split(sep).map((_, i, parts) => join(root, ...parts.slice(0, i + 1))) : [])]) {
    const handle = await storage.open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (!metadata.isDirectory() || (typeof process.getuid === "function" && metadata.uid !== process.getuid()) || (metadata.mode & 0o022) !== 0) throw new Error("release index publication trusted parent is unsafe");
    held.push({ path, handle, metadata });
  }
  const target = join(publicationDirectory, `${index.indexDigest.slice(7)}.release.json`);
  const temporary = join(publicationDirectory, `.${basename(target)}.${process.pid}.${Date.now()}.tmp`);
  const bytes = Buffer.from(`${canonical(index)}\n`);
  let temporaryHandle; let targetHandle;
  try {
    temporaryHandle = await storage.open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o444);
    await temporaryHandle.writeFile(bytes); await temporaryHandle.sync(); await temporaryHandle.close(); temporaryHandle = undefined;
    try { await storage.link(temporary, target); } catch (error) { if (error.code !== "EEXIST") throw error; }
    await storage.unlink(temporary);
    const before = await storage.lstat(target);
    targetHandle = await storage.open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = await targetHandle.stat();
    if (!before.isFile() || !opened.isFile() || before.dev !== opened.dev || before.ino !== opened.ino || opened.nlink !== 1 || opened.size !== bytes.length || (opened.mode & 0o777) !== 0o444 || (typeof process.getuid === "function" && opened.uid !== process.getuid())) throw new Error("published release index target metadata is unsafe");
    const stored = Buffer.alloc(opened.size); let offset = 0;
    while (offset < stored.length) { const { bytesRead } = await targetHandle.read(stored, offset, stored.length - offset, offset); if (bytesRead === 0) throw new Error("published release index target was truncated"); offset += bytesRead; }
    if (!stored.equals(bytes)) throw new Error("content-addressed release index path contains different bytes");
    for (const entry of held) { const current = await storage.lstat(entry.path); if (!current.isDirectory() || current.dev !== entry.metadata.dev || current.ino !== entry.metadata.ino) throw new Error("release index publication trusted parent was replaced"); }
    await held.at(-1).handle.sync();
    const finalMetadata = await storage.lstat(target);
    if (finalMetadata.dev !== opened.dev || finalMetadata.ino !== opened.ino || finalMetadata.size !== opened.size || finalMetadata.nlink !== 1 || (finalMetadata.mode & 0o777) !== 0o444) throw new Error("published release index target changed before durable return");
    const finalStored = Buffer.alloc(opened.size); offset = 0;
    while (offset < finalStored.length) { const { bytesRead } = await targetHandle.read(finalStored, offset, finalStored.length - offset, offset); if (bytesRead === 0) throw new Error("published release index target was truncated during final descriptor read"); offset += bytesRead; }
    if (!finalStored.equals(bytes)) throw new Error("published release index target bytes changed before durable return");
  } finally {
    if (temporaryHandle) await temporaryHandle.close();
    if (targetHandle) await targetHandle.close();
    try { await storage.unlink(temporary); } catch {}
    for (const entry of held.reverse()) await entry.handle.close();
  }
  return { digest: index.indexDigest, uri: `sha256://${index.indexDigest.slice(7)}`, path: target };
}

function resolveWithin(root, relativePath, label) {
  const path = resolve(root, relativePath);
  if (path !== root && !path.startsWith(`${root}${sep}`)) throw new Error(`${label} escapes trusted root`);
  return path;
}

function readBoundArtifact(path, label, maxBytes = 64 * 1024 * 1024) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(fd);
    if (!metadata.isFile() || metadata.nlink !== 1 || metadata.size < 1 || metadata.size > maxBytes) throw new Error(`${label} is not a bounded nonempty single-link regular file`);
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}

export function validateProductionSlatePreflight(ethers, slate, config, {
  repoRoot,
  evidenceRoot = repoRoot,
  pythonExecutable = process.env.P42_ADMISSION_PYTHON ?? process.env.P42_RUNTIME_PYTHON ?? "python3",
  runAdmitReady = runAdmitReadyCommand,
  readMatrixSnapshot = readContractsConfigJsonSyncWithBytes,
  readDossier = readContractsArtifactJsonSyncWithBytes,
} = {}) {
  validateProductionReleaseSlate(slate, config.problems);
  const root = resolve(repoRoot ?? "");
  if (!repoRoot) throw new Error("production slate preflight requires an explicit repository root");
  const evidence = resolve(evidenceRoot ?? "");
  if (!evidenceRoot) throw new Error("production slate preflight requires an explicit evidence root");
  const registryPath = resolveWithin(evidence, slate.imageRegistry.path, "image registry path");
  const { bytes: registryBytes, value: registryValue } = readDossier(registryPath, { trustedRoot: evidence });
  if (`sha256:${createHash("sha256").update(registryBytes).digest("hex")}` !== slate.imageRegistry.digest) throw new Error("immutable image registry digest mismatch");
  const registry = validateVerifierImageReleaseDossier(registryValue, {
    sourceCommit: slate.sourceCommit,
    problems: config.problems,
  });
  const objectiveVerifierPath = resolveWithin(evidence, slate.objectiveVerifier.artifactPath, "objective verifier artifact path");
  const { bytes: objectiveVerifierBytes, value: objectiveVerifierArtifact } = readDossier(objectiveVerifierPath, { trustedRoot: evidence });
  if (`sha256:${createHash("sha256").update(objectiveVerifierBytes).digest("hex")}` !== slate.objectiveVerifier.artifactDigest) throw new Error("objective verifier artifact digest mismatch");
  if (typeof objectiveVerifierArtifact?.deployedBytecode !== "string" || !/^0x(?:[0-9a-fA-F]{2})+$/.test(objectiveVerifierArtifact.deployedBytecode)
      || keccak256(objectiveVerifierArtifact.deployedBytecode) !== slate.objectiveVerifier.runtimeCodehash) throw new Error("objective verifier runtime codehash is not derived from its artifact");
  const images = new Map(registry.boards.map((entry) => [entry.slug, entry.index_digest]));
  return slate.boards.map((board, index) => {
    const problemPath = resolveWithin(root, board.problemPath, `board ${index + 1} problemPath`);
    const matrixPath = resolveWithin(evidence, board.admissionMatrixPath, `board ${index + 1} admissionMatrixPath`);
    const { bytes: matrixBytes, value: matrix } = readMatrixSnapshot(matrixPath, { trustedRoot: evidence });
    const objectiveGuestElfPath = resolveWithin(evidence, board.objectiveGuestElfPath, `board ${index + 1} objectiveGuestElfPath`);
    const objectiveProgramBytes = readBoundArtifact(objectiveGuestElfPath, `board ${index + 1} objective program`);
    const guestElfDigest = `sha256:${createHash("sha256").update(objectiveProgramBytes).digest("hex")}`;
    if (guestElfDigest !== board.objectiveGuestElfDigest) throw new Error(`production board ${index + 1} guest ELF digest mismatch`);
    if (`0x${guestElfDigest.slice("sha256:".length)}` !== board.objectiveGuestElfSha256) throw new Error(`production board ${index + 1} guest ELF SHA-256 bytes32 mismatch`);
    runAdmitReady({ repoRoot: root, problemPath, matrixPath, matrixBytes, pythonExecutable });
    if (matrix.matrix_hash !== board.admissionMatrixDigest || matrix.problem_id !== board.problemSlug || matrix.verifier_version !== board.verifierVersion || matrix.verifier_image !== board.verifierImageDigest) throw new Error(`production board ${index + 1} admission matrix identity mismatch`);
    if (matrix.source?.tree_hash !== board.verifierSourceDigest || board.problemPackageDigest !== board.verifierSourceDigest) throw new Error(`production board ${index + 1} package/source provenance mismatch`);
    if (images.get(board.problemSlug) !== board.verifierImageDigest) throw new Error(`production board ${index + 1} immutable image registry mismatch`);
    return { problemId: board.problemId, problemSlug: board.problemSlug, matrixDigest: board.admissionMatrixDigest };
  });
}

export function bindReleaseMode(config, { releaseMode, slate } = {}) {
  if (!Object.values(RELEASE_MODES).includes(releaseMode)) throw new Error("release mode must be explicitly production or fixture");
  if (releaseMode === RELEASE_MODES.PRODUCTION) validateProductionReleaseSlate(slate, config.problems);
  return { ...config, releaseMode, releaseSlateDigest: releaseMode === RELEASE_MODES.PRODUCTION ? slate.slateDigest : null };
}

const ROOT_KEYS = ["schema", "governance", "roles", "parameters", "problems"];
const GOVERNANCE_KEYS = ["signers", "threshold", "delaySeconds", "guardian"];
const ROLE_KEYS = [
  "treasury",
  "resolver",
  "productionLaunchAuthority",
  "independentSecurityAuthority",
  "governanceAuthority",
];
const INTERNAL_OBJECTIVE_VERIFIER_PLACEHOLDER = "0x000000000000000000000000000000000000ffff";
const INTERNAL_OBJECTIVE_VERIFIER_CODEHASH_PLACEHOLDER = `0x${"ab".repeat(32)}`;
const INTERNAL_FUNDING_BOARD_SET_PLACEHOLDER = `0x${"bc".repeat(32)}`;
const INTERNAL_FUNDING_RELEASE_BINDING_PLACEHOLDER = `0x${"cd".repeat(32)}`;
const PARAMETER_ENV = Object.freeze({
  alphaBps: "P42_ALPHA_BPS",
  betaBps: "P42_BETA_BPS",
  challengeWindowSeconds: "P42_CHALLENGE_WINDOW_SECONDS",
  feeBps: "P42_FEE_BPS",
  minCounterBondWei: "P42_MIN_COUNTER_BOND_WEI",
  minPostingBondWei: "P42_MIN_POSTING_BOND_WEI",
  rerunCostMultiplierBps: "P42_RERUN_COST_MULTIPLIER_BPS",
  rerunCostWei: "P42_RERUN_COST_WEI",
  resolverDecisionBondWei: "P42_RESOLVER_DECISION_BOND_WEI",
  resolverFraudWindowSeconds: "P42_RESOLVER_FRAUD_WINDOW_SECONDS",
});
const BOARD_ENV = Object.freeze({
  fundingCapWei: "P42_FUNDING_CAP_WEI",
  maxSolutionBytes: "P42_MAX_SOLUTION_BYTES",
  earliestCloseTimestamp: "P42_EARLIEST_CLOSE_TIMESTAMP",
  closeByTimestamp: "P42_CLOSE_BY_TIMESTAMP",
  specHash: "P42_PROBLEM_SPEC_HASH",
  problemSlug: "P42_PROBLEM_SLUG",
  verifierVersion: "P42_VERIFIER_VERSION",
  verifierSourceDigest: "P42_VERIFIER_SOURCE_DIGEST",
  verifierSourceHash: "P42_VERIFIER_SOURCE_HASH",
  verifierImageDigest: "P42_VERIFIER_IMAGE_DIGEST",
  verifierImageHash: "P42_VERIFIER_IMAGE_HASH",
  metadataURI: "P42_METADATA_URI",
  seedScoreAtoms: "P42_SEED_SCORE_ATOMS",
  minImprovementAtoms: "P42_MIN_IMPROVEMENT_ATOMS",
  objectiveGuestElfPath: "P42_OBJECTIVE_GUEST_ELF_PATH",
  objectiveGuestElfDigest: "P42_OBJECTIVE_GUEST_ELF_DIGEST",
  objectiveProgramVKey: "P42_OBJECTIVE_PROGRAM_VKEY",
});
const BOARD_KEYS = [
  ...Object.keys(BOARD_ENV),
  "objectiveGuestElfSha256",
  "onchainDa",
  "certifiedObjective",
  "admissionMatrixDigest",
  "admissionMatrixURI",
  "admissionMatrixPath",
];
const CERTIFIED_OBJECTIVE_KEYS = ["seedBest", "direction", "minImprovement"];
const DURABLE_ADMISSION_URI_RE = /^(?:ipfs|ar):\/\/\S+$/;

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const expected = new Set(keys);
  const missing = keys.filter((key) => !Object.hasOwn(value, key));
  const extra = Object.keys(value).filter((key) => !expected.has(key));
  if (missing.length || extra.length) {
    throw new Error(`${label} keys mismatch (missing: ${missing.join(",") || "none"}; extra: ${extra.join(",") || "none"})`);
  }
  return value;
}

function requiredString(value, label) {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${label} must be a non-empty string`);
  if (value.trim() !== value) throw new Error(`${label} must not have surrounding whitespace`);
  return value;
}

function admissionMatrixInput(ethers, problem) {
  const digest = requiredString(problem.admissionMatrixDigest, "problem.admissionMatrixDigest");
  const uri = requiredString(problem.admissionMatrixURI, "problem.admissionMatrixURI");
  const path = requiredString(problem.admissionMatrixPath, "problem.admissionMatrixPath");
  if (!DURABLE_ADMISSION_URI_RE.test(uri)) {
    throw new Error("problem.admissionMatrixURI must use an ipfs:// or ar:// durable URI");
  }
  return {
    admissionMatrixDigest: digest,
    admissionMatrixHashAlgorithm: ADMISSION_MATRIX_HASH_ALGORITHM,
    admissionMatrixHash: admissionMatrixHashForDigest(ethers, digest, "problem.admissionMatrixDigest"),
    admissionMatrixURI: uri,
    admissionMatrixPath: path,
  };
}

function problemEnv(ethers, input, problem) {
  const governance = exactObject(input.governance, GOVERNANCE_KEYS, "governance");
  const roles = exactObject(input.roles, ROLE_KEYS, "roles");
  const parameters = exactObject(input.parameters, Object.keys(PARAMETER_ENV), "parameters");
  const board = exactObject(problem, BOARD_KEYS, "problem");
  const admission = admissionMatrixInput(ethers, board);
  if (board.objectiveGuestElfSha256 !== `0x${board.objectiveGuestElfDigest.slice("sha256:".length)}`) {
    throw new Error("problem.objectiveGuestElfSha256 must be the bytes32 payload of objectiveGuestElfDigest");
  }
  if (!Array.isArray(governance.signers) || governance.signers.length < 3) {
    throw new Error("governance.signers must be an array of at least three addresses");
  }
  const env = {
    P42_GOVERNANCE_SIGNERS: governance.signers.map((value, index) => requiredString(value, `governance.signers[${index}]`)).join(","),
    P42_GOVERNANCE_THRESHOLD: requiredString(governance.threshold, "governance.threshold"),
    P42_GOVERNANCE_DELAY_SECONDS: requiredString(governance.delaySeconds, "governance.delaySeconds"),
    P42_GUARDIAN_ADDRESS: requiredString(governance.guardian, "governance.guardian"),
    P42_TREASURY_ADDRESS: requiredString(roles.treasury, "roles.treasury"),
    P42_RESOLVER_ADDRESS: requiredString(roles.resolver, "roles.resolver"),
    P42_PRODUCTION_LAUNCH_AUTHORITY_ADDRESS: requiredString(
      roles.productionLaunchAuthority,
      "roles.productionLaunchAuthority",
    ),
    P42_INDEPENDENT_SECURITY_AUTHORITY_ADDRESS: requiredString(
      roles.independentSecurityAuthority,
      "roles.independentSecurityAuthority",
    ),
    P42_FUNDING_GOVERNANCE_AUTHORITY_ADDRESS: requiredString(
      roles.governanceAuthority,
      "roles.governanceAuthority",
    ),
    // The generic single-board parser still models an external verifier role.
    // Multi-board production ignores these internal placeholders and deploys
    // the capsule-attested gateway as a canonical shared root.
    P42_OBJECTIVE_VERIFIER_ADDRESS: INTERNAL_OBJECTIVE_VERIFIER_PLACEHOLDER,
    P42_OBJECTIVE_VERIFIER_CODEHASH: INTERNAL_OBJECTIVE_VERIFIER_CODEHASH_PLACEHOLDER,
    // The exact values are derived from the frozen ten-board slate and release
    // reservation before deterministic address planning.
    P42_FUNDING_BOARD_SET_DIGEST: INTERNAL_FUNDING_BOARD_SET_PLACEHOLDER,
    P42_FUNDING_RELEASE_BINDING_DIGEST: INTERNAL_FUNDING_RELEASE_BINDING_PLACEHOLDER,
    P42_ADMISSION_MATRIX_HASH: admission.admissionMatrixHash,
    P42_ONCHAIN_DA: board.onchainDa === true ? "true" : board.onchainDa === false ? "false" : (() => {
      throw new Error("problem.onchainDa must be a boolean");
    })(),
  };
  for (const [field, envName] of Object.entries(PARAMETER_ENV)) {
    env[envName] = requiredString(parameters[field], `parameters.${field}`);
  }
  for (const [field, envName] of Object.entries(BOARD_ENV)) {
    env[envName] = requiredString(board[field], `problem.${field}`);
  }
  const certified = exactObject(board.certifiedObjective, CERTIFIED_OBJECTIVE_KEYS, "problem.certifiedObjective");
  env.P42_PROBLEM_SEED_BEST = requiredString(certified.seedBest, "problem.certifiedObjective.seedBest");
  env.P42_PROBLEM_DIRECTION = requiredString(certified.direction, "problem.certifiedObjective.direction");
  env.P42_PROBLEM_MIN_IMPROVEMENT = requiredString(
    certified.minImprovement,
    "problem.certifiedObjective.minImprovement",
  );
  return { env, admission };
}

function equalField(label, first, next) {
  if (String(first) !== String(next)) {
    throw new Error(`${label} differs between multi-board configurations`);
  }
}

export function readMultiBoardCeremonyConfig(ethers, value, { deployerAddress } = {}) {
  const input = exactObject(value, ROOT_KEYS, "multi-board ceremony");
  if (input.schema !== MULTIBOARD_CEREMONY_SCHEMA) {
    throw new Error(`multi-board ceremony.schema must equal ${MULTIBOARD_CEREMONY_SCHEMA}`);
  }
  if (!Array.isArray(input.problems) || input.problems.length < 1 || input.problems.length > 10) {
    throw new Error("multi-board ceremony.problems must contain 1..10 boards");
  }
  const parsed = input.problems.map((problem) => {
    const { env, admission } = problemEnv(ethers, input, problem);
    return {
      admission,
      config: readCeremonyConfig(ethers, env, { deployerAddress }),
    };
  });
  const first = parsed[0].config;
  const slugs = new Set();
  for (const [index, entry] of parsed.entries()) {
    const board = entry.config;
    if (slugs.has(board.problem.problemSlug)) {
      throw new Error(`multi-board ceremony.problems[${index}].problemSlug is duplicated`);
    }
    slugs.add(board.problem.problemSlug);
    for (const key of Object.keys(PARAMETER_ENV)) {
      equalField(`parameters.${key}`, first.parameters[key], board.parameters[key]);
    }
  }
  return {
    schema: MULTIBOARD_CEREMONY_SCHEMA,
    governance: first.governance,
    roles: {
      treasury: first.roles.treasury,
      resolver: first.roles.resolver,
      productionLaunchAuthority: first.roles.productionLaunchAuthority,
      independentSecurityAuthority: first.roles.independentSecurityAuthority,
      governanceAuthority: first.roles.governanceAuthority,
    },
    parameters: Object.fromEntries(Object.keys(PARAMETER_ENV).map((key) => [key, first.parameters[key]])),
    problems: parsed.map(({ config: board, admission }, index) => ({
      ...board.problem,
      ...admission,
      problemId: String(index + 1),
      fundingCapWei: board.parameters.fundingCapWei,
      onchainDa: board.parameters.onchainDa,
      maxSolutionBytes: board.parameters.maxSolutionBytes,
      earliestCloseTimestamp: board.parameters.earliestCloseTimestamp,
      closeByTimestamp: board.parameters.closeByTimestamp,
    })),
    finalityPolicy: first.finalityPolicy,
  };
}

export function boardSetDigest(problems) {
  if (!Array.isArray(problems) || problems.length < 1 || problems.length > 10) {
    throw new Error("board-set digest requires 1..10 boards");
  }
  return sha256Canonical(problems.map((problem, index) => releaseBoardIdentity(problem, index)));
}

export function productionBoardSetDigest(problems) {
  if (!Array.isArray(problems) || problems.length !== 10) {
    throw new Error("production board-set digest requires exactly 10 boards");
  }
  return boardSetDigest(problems);
}

function runAdmitReadyCommand({ repoRoot, problemPath, matrixPath, matrixBytes, pythonExecutable }) {
  const sourcePath = resolve(repoRoot, "src");
  const inheritedPythonPath = process.env.PYTHONPATH;
  execFileSync(
    pythonExecutable,
    ["-m", "p42_prizes.cli", "admit-ready", "--problem", problemPath, ...(matrixBytes ? ["--matrix-stdin"] : ["--matrix", matrixPath])],
    {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: "pipe",
      input: matrixBytes,
      env: {
        ...process.env,
        PYTHONPATH: inheritedPythonPath ? `${sourcePath}${delimiter}${inheritedPythonPath}` : sourcePath,
      },
    },
  );
}

function loadAdmissionMatrix(path) {
  try {
    const matrix = readContractsConfigJsonSync(path);
    if (!matrix || typeof matrix !== "object" || Array.isArray(matrix)) {
      throw new Error("matrix must be a JSON object");
    }
    return matrix;
  } catch (error) {
    throw new Error(`could not read admission matrix ${path}: ${error.message}`);
  }
}

export function validateMultiBoardAdmissionPreflight(
  ethers,
  config,
  {
    repoRoot = resolve(process.cwd(), ".."),
    pythonExecutable = process.env.P42_ADMISSION_PYTHON ?? process.env.P42_RUNTIME_PYTHON ?? "python3",
    runAdmitReady = runAdmitReadyCommand,
    readMatrix = loadAdmissionMatrix,
  } = {},
) {
  if (!config || !Array.isArray(config.problems) || config.problems.length === 0) {
    throw new Error("multi-board admission preflight requires parsed problem configurations");
  }
  const root = resolve(repoRoot);
  return config.problems.map((problem) => {
    const matrixPath = resolve(root, problem.admissionMatrixPath);
    const problemPath = resolve(root, "problems", problem.problemSlug);
    try {
      runAdmitReady({ repoRoot: root, problemPath, matrixPath, pythonExecutable });
    } catch (error) {
      const detail = String(error.stderr ?? error.stdout ?? error.message).trim();
      throw new Error(`admission preflight failed for ${problem.problemSlug}: ${detail || error.message}`);
    }
    const matrix = readMatrix(matrixPath);
    const anchor = assertAdmissionMatrixAnchor(
      ethers,
      problem,
      {
        digestLabel: `problem ${problem.problemSlug} admissionMatrixDigest`,
        hashLabel: `problem ${problem.problemSlug} admissionMatrixHash`,
        algorithmLabel: `problem ${problem.problemSlug} admissionMatrixHashAlgorithm`,
      },
    );
    if (matrix.matrix_hash !== anchor.admissionMatrixDigest) {
      throw new Error(
        `admission preflight failed for ${problem.problemSlug}: matrix_hash does not match admissionMatrixDigest`,
      );
    }
    return {
      problemId: String(problem.problemId),
      problemSlug: problem.problemSlug,
      admissionMatrixDigest: anchor.admissionMatrixDigest,
      admissionMatrixHash: anchor.admissionMatrixHash,
      admissionMatrixURI: problem.admissionMatrixURI,
    };
  });
}

export function validateMultiBoardDeploymentTimestamps(config, latestBlockTimestamp) {
  for (const [index, problem] of config.problems.entries()) {
    try {
      validateDeploymentTimestamps(boardCeremonyConfig(config, problem), latestBlockTimestamp);
    } catch (error) {
      throw new Error(`multi-board problem ${index + 1} (${problem.problemSlug}): ${error.message}`);
    }
  }
}
