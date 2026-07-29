#!/usr/bin/env node

import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { stableStringify, validateMultiBoardCheckpoint } from "./indexer.mjs";
import { readStrictJsonFileSyncWithBytes, writeTrustedFileSync } from "./strict-json.mjs";

const MAX_BYTES = 16 * 1024 * 1024;
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function buildCheckpointAttestation(checkpointBytes, privateSeedHex, signedAtUtc = new Date().toISOString()) {
  if (!Buffer.isBuffer(checkpointBytes) || checkpointBytes.length === 0 || checkpointBytes.length > MAX_BYTES) throw new Error("checkpoint bytes are invalid");
  if (!/^[0-9a-f]{64}$/.test(privateSeedHex)) throw new Error("P42_INDEXER_ATTESTATION_PRIVATE_KEY must be 32 lowercase hex bytes");
  if (!Number.isFinite(Date.parse(signedAtUtc))) throw new Error("signedAtUtc must be an RFC 3339 timestamp");
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(privateSeedHex, "hex")]), format: "der", type: "pkcs8" });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKey = `ed25519:${publicDer.subarray(-32).toString("hex")}`;
  const checkpointDigest = `sha256:${createHash("sha256").update(checkpointBytes).digest("hex")}`;
  const schema = "p42-indexer-checkpoint-attestation/v1";
  const signerRole = "indexer-checkpoint-authority";
  const message = Buffer.from(`P42-ATTESTATION-V2\n${schema}\n${signerRole}\n${checkpointDigest}\n${signedAtUtc}`, "ascii");
  return { schema, signerRole, publicKey, checkpointDigest, signedAtUtc, signature: `ed25519:${sign(null, message, privateKey).toString("hex")}` };
}

export function checkpointAttestMain(argv = process.argv.slice(2), env = process.env) {
  const value = (name) => { const index = argv.indexOf(`--${name}`); return index < 0 ? null : argv[index + 1]; };
  const checkpointPath = value("checkpoint");
  const outputPath = value("output");
  const trustedRootArg = value("trusted-root");
  if (!checkpointPath || !outputPath || !trustedRootArg) throw new Error("required: --trusted-root <dir> --checkpoint <path> --output <path>");
  const seed = env.P42_INDEXER_ATTESTATION_PRIVATE_KEY;
  if (!seed) throw new Error("P42_INDEXER_ATTESTATION_PRIVATE_KEY is required");
  const trustedRoot = realpathSync(resolve(trustedRootArg));
  const checkpoint = readStrictJsonFileSyncWithBytes(resolve(checkpointPath), { maxBytes: MAX_BYTES, maxDepth: 128, privateFile: true, trustedRoot });
  validateMultiBoardCheckpoint(checkpoint.value);
  const attestation = buildCheckpointAttestation(checkpoint.bytes, seed);
  writeTrustedFileSync(resolve(outputPath), trustedRoot, `${stableStringify(attestation)}\n`);
  return attestation;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try { checkpointAttestMain(); } catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }
}
