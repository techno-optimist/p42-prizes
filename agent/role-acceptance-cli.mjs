#!/usr/bin/env node

import { basename, resolve } from "node:path";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  ROLE_ACCEPTANCE_SIGNATURE_SCHEMA,
  assembleRoleAcceptancePacket,
  buildRoleAcceptanceRequestSet,
  canonicalRoleAcceptanceJson,
  roleAcceptanceBytesDigest,
  roleAcceptanceCanonicalDigest,
} from "./role-acceptance.mjs";
import { preserveRoleAcceptanceInputs, readPreservedRoleAcceptanceArtifact } from "./role-acceptance-artifacts.mjs";
import { parseStrictJsonBytes, readStrictJsonFileSyncWithBytes, writeTrustedFileExclusiveSync } from "./strict-json.mjs";

const PRIVATE_JSON = Object.freeze({ maxBytes: 8 * 1024 * 1024, maxDepth: 128, trailingNewline: "require", privateFile: true });
const PUBLIC_JSON = Object.freeze({ maxBytes: 32 * 1024 * 1024, maxDepth: 128, trailingNewline: "allow" });

function arg(name) {
  const index = process.argv.indexOf(`--${name}`);
  const value = index < 0 ? null : process.argv[index + 1];
  return value && !value.startsWith("--") ? value : null;
}

function args(name) {
  const values = [];
  for (let index = 0; index < process.argv.length; index += 1) if (process.argv[index] === `--${name}` && process.argv[index + 1] && !process.argv[index + 1].startsWith("--")) values.push(process.argv[index + 1]);
  return values;
}

function required(name) {
  const value = arg(name);
  if (value === null) throw new Error(`--${name} is required`);
  return value;
}

function digestArg(name) {
  const value = required(name);
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) throw new Error(`--${name} must be a sha256 digest`);
  return value;
}

function assertNoSecretsOrRpc() {
  if (process.argv.some((value) => /private[-_]?key|mnemonic|seed[-_]?phrase/i.test(value))) throw new Error("role acceptance tooling forbids private-key inputs");
  const forbidden = Object.entries(process.env).filter(([name, value]) => value && (/PRIVATE_KEY|MNEMONIC|SEED_PHRASE/.test(name) || (/ROLE_ACCEPTANCE/.test(name) && /RPC/.test(name))));
  if (forbidden.length) throw new Error("role acceptance tooling refuses key and role-acceptance RPC environment inputs");
}

function readPublicExact(path) {
  const result = readStrictJsonFileSyncWithBytes(resolve(path), PUBLIC_JSON);
  return { ...result, bytesDigest: roleAcceptanceBytesDigest(result.bytes) };
}

function readPrivate(path, trustedRoot) {
  return readStrictJsonFileSyncWithBytes(resolve(path), { ...PRIVATE_JSON, trustedRoot }).value;
}

function readPreservedExact(path, expectedDigest, label) {
  const artifact = readPreservedRoleAcceptanceArtifact(resolve(path), expectedDigest, label);
  return { ...artifact, value: parseStrictJsonBytes(artifact.bytes, PUBLIC_JSON) };
}

export function writeExclusivePrivateJson(path, trustedRoot, value) {
  const payload = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  if (!writeTrustedFileExclusiveSync(resolve(path), trustedRoot, payload)) throw new Error("role acceptance output already exists; refusing to replace private artifact");
  return roleAcceptanceBytesDigest(payload);
}

function exactCapsule(capsuleFile) {
  const capsule = capsuleFile.value;
  const { capsuleDigest, ...body } = capsule;
  if (!/^sha256:[0-9a-f]{64}$/.test(capsuleDigest ?? "") || roleAcceptanceCanonicalDigest(body) !== capsuleDigest) throw new Error("release capsule canonical digest mismatch");
  return { capsule, capsuleDigest, capsuleBytesDigest: capsuleFile.bytesDigest };
}

export function prepareRoleAcceptance({ manifestFile, capsuleFile, expectedExplorerDossierDigest, expiresAt }) {
  const capsule = exactCapsule(capsuleFile);
  return buildRoleAcceptanceRequestSet({
    manifest: manifestFile.value,
    pendingManifestBytesDigest: manifestFile.bytesDigest,
    capsuleBytesDigest: capsule.capsuleBytesDigest,
    capsuleDigest: capsule.capsuleDigest,
    expectedExplorerDossierDigest,
    expiresAt,
  });
}

export function assembleRoleAcceptance({ manifestFile, capsuleFile, expectedExplorerDossierDigest, requestSet, signatureArtifacts }) {
  const capsule = exactCapsule(capsuleFile);
  return assembleRoleAcceptancePacket({
    manifest: manifestFile.value,
    pendingManifestBytesDigest: manifestFile.bytesDigest,
    capsuleBytesDigest: capsule.capsuleBytesDigest,
    capsuleDigest: capsule.capsuleDigest,
    expectedExplorerDossierDigest,
    requestSet,
    signatureArtifacts,
  });
}

export function roleAcceptancePrepareMain() {
  assertNoSecretsOrRpc();
  const trustedRoot = realpathSync(resolve(required("trusted-root")));
  const expiresAt = Number(required("expires-at"));
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 1) throw new Error("--expires-at must be a positive Unix timestamp");
  const manifestFile = readPublicExact(required("pending-manifest"));
  const capsuleFile = readPublicExact(required("capsule"));
  const preserved = preserveRoleAcceptanceInputs({ manifestFile, capsuleFile, artifactRoot: required("artifact-root") });
  const requestSet = prepareRoleAcceptance({
    manifestFile,
    capsuleFile,
    expectedExplorerDossierDigest: digestArg("expected-explorer-dossier-sha256"),
    expiresAt,
  });
  const outputDigest = writeExclusivePrivateJson(required("output"), trustedRoot, requestSet);
  process.stdout.write(`${requestSet.requestSetDigest} ${outputDigest} ${preserved.pendingManifest.path} ${preserved.capsule.path}\n`);
}

export function roleAcceptanceAssembleMain() {
  assertNoSecretsOrRpc();
  const trustedRoot = realpathSync(resolve(required("trusted-root")));
  const requestSet = readPrivate(required("request-set"), trustedRoot);
  const signatureArtifacts = args("signature").map((path) => readPrivate(path, trustedRoot));
  for (const artifact of signatureArtifacts) if (artifact?.schema !== ROLE_ACCEPTANCE_SIGNATURE_SCHEMA) throw new Error("invalid detached role acceptance signature schema");
  const packet = assembleRoleAcceptance({
    manifestFile: readPreservedExact(required("pending-manifest"), requestSet.pendingManifestBytesDigest, "pending manifest"),
    capsuleFile: readPreservedExact(required("capsule"), requestSet.capsuleBytesDigest, "capsule"),
    expectedExplorerDossierDigest: digestArg("expected-explorer-dossier-sha256"),
    requestSet,
    signatureArtifacts,
  });
  const outputDigest = writeExclusivePrivateJson(required("output"), trustedRoot, packet);
  process.stdout.write(`${packet.packetDigest} ${outputDigest}\n`);
}

const invoked = process.argv[1] ? basename(process.argv[1]) : "";
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const main = invoked.includes("assemble") ? roleAcceptanceAssembleMain : roleAcceptancePrepareMain;
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}

export { canonicalRoleAcceptanceJson };
