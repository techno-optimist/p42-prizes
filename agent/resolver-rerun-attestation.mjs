import { createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { acquireEnvelopeLock, releaseEnvelopeLock } from "./challenge-envelope.mjs";
import { canonicalJson, sha256Canonical } from "./lib.mjs";
import { readCredentialJson } from "./runtime-credentials.mjs";
import {
  readStrictJsonFileSync,
  writeTrustedFileExclusiveSync,
  writeTrustedFileSync,
} from "./strict-json.mjs";

export const RESOLVER_RERUN_SCHEMA = "p42-resolver-rerun/v1";
export const RESOLVER_RERUN_TRUST_SCHEMA = "p42-resolver-rerun-executor-trust/v1";
export const RESOLVER_RERUN_CHALLENGE_SCHEMA = "p42-resolver-rerun-challenge/v1";

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const BYTES32_RE = /^0x[0-9a-f]{64}$/;
const ADDRESS_RE = /^0x[0-9a-f]{40}$/;
const PUBLIC_KEY_RE = /^ed25519:[0-9a-f]{64}$/;
const SIGNATURE_RE = /^ed25519:[0-9a-f]{128}$/;
const KEY_ID_RE = /^[a-z0-9][a-z0-9._-]{2,63}$/;
const DEFAULT_CHALLENGE_TTL_MS = 15 * 60 * 1000;
const RECEIPT_LIMITS = Object.freeze({
  maxBytes: 256 * 1024,
  maxDepth: 24,
  canonicalBytes: true,
  trailingNewline: "require",
  privateFile: true,
});

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());
}

function normalizePacketIdentity(packet) {
  return {
    packet_hash: String(packet.packet_hash).toLowerCase(),
    decision_digest: String(packet.decision_digest).toLowerCase(),
    challenge_instance_hash: String(packet.decision.challengeInstanceHash).toLowerCase(),
  };
}

function packetStateName(packet) {
  if (!SHA256_RE.test(String(packet.packet_hash))) throw new Error("resolver rerun packet hash is invalid");
  return packet.packet_hash.slice(7);
}

export function resolverRerunChallengePath(signatureRoot, packet) {
  return join(signatureRoot, "rerun-challenges", `${packetStateName(packet)}.json`);
}

export function resolverRerunConsumptionPath(signatureRoot, packet) {
  const challenge = readResolverRerunChallenge(signatureRoot, packet);
  return resolverRerunAttemptPaths(signatureRoot, packet, challenge.orchestrator_nonce).receipt;
}

export function resolverRerunAttemptPaths(signatureRoot, packet, nonce) {
  if (!BYTES32_RE.test(nonce ?? "")) throw new Error("resolver rerun attempt nonce is invalid");
  const root = join(signatureRoot, "rerun-attempts", packetStateName(packet), nonce.slice(2));
  return Object.freeze({
    root,
    receipt: join(root, "receipt.json"),
    authorization: join(root, "authorization.json"),
    signature: join(root, "signature.json"),
  });
}

export function issueResolverRerunChallenge(signatureRoot, packet, options = {}) {
  const now = options.now ?? Date.now();
  const ttlMs = options.ttlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > DEFAULT_CHALLENGE_TTL_MS) {
    throw new Error("resolver rerun challenge clock or TTL is invalid");
  }
  const directory = join(signatureRoot, "rerun-challenges");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = resolverRerunChallengePath(signatureRoot, packet);
  const lockPath = `${path}.lock`;
  const owner = acquireEnvelopeLock(lockPath, { timeoutMs: options.lockTimeoutMs ?? 5000 });
  try {
    let replacement = null;
    if (existsSync(path)) {
      const prior = readResolverRerunChallenge(signatureRoot, packet);
      if (now < Date.parse(prior.expires_at_utc)) {
        const currentRenewal = join(signatureRoot, "rerun-renewals", `current-${packetStateName(packet)}.json`);
        if (existsSync(currentRenewal)) {
          const intent = readStrictJsonFileSync(currentRenewal, { ...RECEIPT_LIMITS, trustedRoot: signatureRoot });
          if (intent.packet_hash === packet.packet_hash && intent.replacement_nonce === prior.orchestrator_nonce
              && intent.replacement_issued_at_utc === prior.issued_at_utc
              && intent.replacement_expires_at_utc === prior.expires_at_utc) return { challenge: prior, path };
        }
        throw new Error("resolver rerun challenge already active for this packet");
      }
      const priorPaths = resolverRerunAttemptPaths(signatureRoot, packet, prior.orchestrator_nonce);
      if ([priorPaths.receipt, priorPaths.authorization, priorPaths.signature].some(existsSync)) {
        throw new Error("resolver rerun challenge cannot renew after receipt, authorization, or signature");
      }
      const renewalDir = join(signatureRoot, "rerun-renewals");
      mkdirSync(renewalDir, { recursive: true, mode: 0o700 });
      const renewalPath = join(renewalDir, `${packetStateName(packet)}-${prior.orchestrator_nonce.slice(2)}.json`);
      if (existsSync(renewalPath)) {
        replacement = readStrictJsonFileSync(renewalPath, { ...RECEIPT_LIMITS, trustedRoot: signatureRoot });
        if (!exactKeys(replacement, [
          "schema_version", "packet_hash", "prior_nonce", "superseded_at_utc",
          "replacement_nonce", "replacement_issued_at_utc", "replacement_expires_at_utc",
        ]) || replacement.schema_version !== "p42-resolver-rerun-renewal/v1"
            || replacement.packet_hash !== packet.packet_hash || replacement.prior_nonce !== prior.orchestrator_nonce) {
          throw new Error("resolver rerun renewal intent is malformed or substituted");
        }
      } else {
        const replacementBytes = (options.randomBytes ?? randomBytes)(32);
        if (!(replacementBytes instanceof Uint8Array) || replacementBytes.length !== 32) {
          throw new Error("resolver rerun nonce generator did not return 32 bytes");
        }
        replacement = {
          schema_version: "p42-resolver-rerun-renewal/v1", packet_hash: packet.packet_hash,
          prior_nonce: prior.orchestrator_nonce, superseded_at_utc: new Date(now).toISOString(),
          replacement_nonce: `0x${Buffer.from(replacementBytes).toString("hex")}`,
          replacement_issued_at_utc: new Date(now).toISOString(),
          replacement_expires_at_utc: new Date(now + ttlMs).toISOString(),
        };
        if (!writeTrustedFileExclusiveSync(renewalPath, signatureRoot, `${canonicalJson(replacement)}\n`)) {
          throw new Error("resolver rerun renewal intent raced another signer process");
        }
      }
      writeTrustedFileSync(
        join(renewalDir, `current-${packetStateName(packet)}.json`), signatureRoot,
        `${canonicalJson(replacement)}\n`,
      );
      options.crash?.("after-renewal-intent", replacement);
      const tombstoneDir = join(signatureRoot, "rerun-tombstones");
      mkdirSync(tombstoneDir, { recursive: true, mode: 0o700 });
      const tombstone = {
        schema_version: "p42-resolver-rerun-tombstone/v1",
        ...normalizePacketIdentity(packet),
        orchestrator_nonce: prior.orchestrator_nonce,
        issued_at_utc: prior.issued_at_utc,
        expires_at_utc: prior.expires_at_utc,
        superseded_at_utc: replacement.superseded_at_utc,
        reason: "expired-without-receipt-authorization-or-signature",
      };
      const tombstonePath = join(tombstoneDir, `${packetStateName(packet)}-${prior.orchestrator_nonce.slice(2)}.json`);
      if (!writeTrustedFileExclusiveSync(tombstonePath, signatureRoot, `${canonicalJson(tombstone)}\n`)) {
        const existing = readFileSync(tombstonePath, "utf8");
        if (existing !== `${canonicalJson(tombstone)}\n`) throw new Error("resolver rerun renewal tombstone conflicts");
      }
      options.crash?.("after-renewal-tombstone", replacement);
    }
    const bytes = replacement ? Buffer.from(replacement.replacement_nonce.slice(2), "hex")
      : (options.randomBytes ?? randomBytes)(32);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error("resolver rerun nonce generator did not return 32 bytes");
    const challenge = {
      schema_version: RESOLVER_RERUN_CHALLENGE_SCHEMA,
      ...normalizePacketIdentity(packet),
      orchestrator_nonce: `0x${Buffer.from(bytes).toString("hex")}`,
      issued_at_utc: replacement?.replacement_issued_at_utc ?? new Date(now).toISOString(),
      expires_at_utc: replacement?.replacement_expires_at_utc ?? new Date(now + ttlMs).toISOString(),
    };
    if (existsSync(path)) writeTrustedFileSync(path, signatureRoot, `${canonicalJson(challenge)}\n`);
    else if (!writeTrustedFileExclusiveSync(path, signatureRoot, `${canonicalJson(challenge)}\n`)) {
      throw new Error("resolver rerun challenge creation raced another signer process");
    }
    if (replacement) options.crash?.("after-renewal-replacement", replacement);
    return { challenge, path };
  } finally {
    releaseEnvelopeLock(lockPath, owner);
  }
}

export function readResolverRerunChallenge(signatureRoot, packet) {
  const path = resolverRerunChallengePath(signatureRoot, packet);
  if (!existsSync(path)) throw new Error("resolver rerun challenge was not issued by this signer");
  const value = readStrictJsonFileSync(path, { ...RECEIPT_LIMITS, trustedRoot: signatureRoot });
  if (!exactKeys(value, [
    "schema_version", "packet_hash", "decision_digest", "challenge_instance_hash",
    "orchestrator_nonce", "issued_at_utc", "expires_at_utc",
  ]) || value.schema_version !== RESOLVER_RERUN_CHALLENGE_SCHEMA) {
    throw new Error("resolver rerun challenge journal is malformed");
  }
  const expected = normalizePacketIdentity(packet);
  for (const key of Object.keys(expected)) {
    if (value[key] !== expected[key]) throw new Error(`resolver rerun challenge ${key} does not match the packet`);
  }
  if (!BYTES32_RE.test(value.orchestrator_nonce)
      || !Number.isFinite(Date.parse(value.issued_at_utc))
      || !Number.isFinite(Date.parse(value.expires_at_utc))
      || Date.parse(value.expires_at_utc) <= Date.parse(value.issued_at_utc)) {
    throw new Error("resolver rerun challenge nonce or validity window is malformed");
  }
  return value;
}

export function validateResolverRerunExecutorTrust(value) {
  if (!exactKeys(value, ["schema_version", "key_id", "purpose", "algorithm", "public_key"])
      || value.schema_version !== RESOLVER_RERUN_TRUST_SCHEMA
      || value.purpose !== "resolver-rerun"
      || value.algorithm !== "ed25519"
      || !KEY_ID_RE.test(value.key_id ?? "")
      || !PUBLIC_KEY_RE.test(value.public_key ?? "")) {
    throw new Error("resolver rerun executor trust credential is malformed or not dedicated to resolver reruns");
  }
  return Object.freeze({ ...value });
}

export function loadResolverRerunExecutorTrust(path) {
  return validateResolverRerunExecutorTrust(readCredentialJson(path, "resolver rerun executor trust credential"));
}

export function readResolverRerunReceipt(path, signatureRoot) {
  return readStrictJsonFileSync(path, signatureRoot
    ? { ...RECEIPT_LIMITS, trustedRoot: signatureRoot }
    : RECEIPT_LIMITS);
}

function receiptUnsignedBody(receipt) {
  return Object.fromEntries(Object.entries(receipt).filter(([key]) => !["receipt_hash", "signature"].includes(key)));
}

function receiptMessage(receiptHash) {
  return Buffer.concat([
    Buffer.from("P42-RESOLVER-RERUN-V1\0", "ascii"),
    Buffer.from(receiptHash.slice(7), "hex"),
  ]);
}

function ed25519PublicKey(value) {
  return createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(value.slice(8), "hex"),
    ]),
    format: "der",
    type: "spki",
  });
}

function executionBody(transcript) {
  const value = structuredClone(transcript);
  delete value.transcript_hash;
  delete value.job_id;
  delete value.generated_at_utc;
  delete value.started_at_utc;
  return value;
}

function expectedReceiptBindings({ packet, published, local, challenge, trust }) {
  const solutionHash = local.report?.solution_hash ?? local.transcript.da?.expected_hash;
  return {
    schema_version: RESOLVER_RERUN_SCHEMA,
    executor_key_id: trust.key_id,
    algorithm: "ed25519",
    packet_hash: packet.packet_hash,
    decision_digest: packet.decision_digest,
    chain_id: packet.decision.chainId,
    quorum: packet.decision.adapter,
    manager: packet.decision.manager,
    submission_id: packet.decision.submissionId,
    challenge_instance_hash: packet.decision.challengeInstanceHash,
    reveal_instance_hash: published.claim.reveal_instance_hash,
    published_transcript_hash: published.transcript.transcript_hash,
    solution_hash: solutionHash,
    da_expected_hash: local.transcript.da?.expected_hash,
    da_observed_hash: local.transcript.da?.observed_hash ?? null,
    verifier_image: local.registryBinding.verifier_image,
    verifier_source_digest: local.registryBinding.verifier_source_digest,
    resource_identity: local.boardIdentity.resource_identity,
    orchestrator_nonce: challenge.orchestrator_nonce,
    local_transcript_hash: local.transcript.transcript_hash,
  };
}

export function verifyResolverRerunReceipt({ receipt, trust, challenge, packet, published, local, now = Date.now(), allowExpired = false }) {
  const checkedTrust = validateResolverRerunExecutorTrust(trust);
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("resolver rerun verification clock is invalid");
  if (now < Date.parse(challenge.issued_at_utc)
      || (now >= Date.parse(challenge.expires_at_utc) && allowExpired !== true)) {
    throw new Error("resolver rerun challenge nonce is stale");
  }
  if (local.transcript.transcript_hash === published.transcript.transcript_hash) {
    throw new Error("resolver rerun rejects an exact copy of the published transcript");
  }
  if (canonicalJson(executionBody(local.transcript)) === canonicalJson(executionBody(published.transcript))) {
    throw new Error("resolver rerun rejects a timestamp-only transcript rewrap");
  }
  const keys = [
    "schema_version", "executor_key_id", "algorithm", "packet_hash", "decision_digest",
    "chain_id", "quorum", "manager", "submission_id", "challenge_instance_hash",
    "reveal_instance_hash", "published_transcript_hash", "solution_hash", "da_expected_hash",
    "da_observed_hash", "verifier_image", "verifier_source_digest", "resource_identity",
    "orchestrator_nonce", "local_transcript_hash", "receipt_hash", "signature",
  ];
  if (!exactKeys(receipt, keys)) throw new Error("resolver rerun receipt has unknown or missing fields");
  const expected = expectedReceiptBindings({ packet, published, local, challenge, trust: checkedTrust });
  for (const [key, value] of Object.entries(expected)) {
    if (receipt[key] !== value) throw new Error(`resolver rerun receipt ${key} binding mismatch`);
  }
  if (!SHA256_RE.test(receipt.packet_hash ?? "")
      || !BYTES32_RE.test(receipt.decision_digest ?? "")
      || !/^[1-9][0-9]*$/.test(receipt.chain_id ?? "")
      || !/^[1-9][0-9]*$/.test(receipt.submission_id ?? "")
      || !SHA256_RE.test(receipt.published_transcript_hash ?? "")
      || !SHA256_RE.test(receipt.local_transcript_hash ?? "")
      || !SHA256_RE.test(receipt.solution_hash ?? "")
      || !SHA256_RE.test(receipt.da_expected_hash ?? "")
      || !(receipt.da_observed_hash === null || SHA256_RE.test(receipt.da_observed_hash ?? ""))
      || !SHA256_RE.test(receipt.verifier_image ?? "")
      || !SHA256_RE.test(receipt.verifier_source_digest ?? "")
      || !SHA256_RE.test(receipt.resource_identity ?? "")
      || !ADDRESS_RE.test(receipt.quorum ?? "")
      || !ADDRESS_RE.test(receipt.manager ?? "")
      || !BYTES32_RE.test(receipt.challenge_instance_hash ?? "")
      || !BYTES32_RE.test(receipt.reveal_instance_hash ?? "")) {
    throw new Error("resolver rerun receipt contains malformed immutable bindings");
  }
  const unsigned = receiptUnsignedBody(receipt);
  const receiptHash = sha256Canonical(unsigned);
  if (receipt.receipt_hash !== receiptHash) throw new Error("resolver rerun receipt self-hash mismatch");
  if (!exactKeys(receipt.signature, ["algorithm", "key_id", "signature"])
      || receipt.signature.algorithm !== "ed25519"
      || receipt.signature.key_id !== checkedTrust.key_id
      || !SIGNATURE_RE.test(receipt.signature.signature ?? "")) {
    throw new Error("resolver rerun receipt signature envelope is malformed");
  }
  if (!verifySignature(
    null,
    receiptMessage(receiptHash),
    ed25519PublicKey(checkedTrust.public_key),
    Buffer.from(receipt.signature.signature.slice(8), "hex"),
  )) {
    throw new Error("resolver rerun receipt executor signature is invalid");
  }
  return Object.freeze({ ...receipt });
}

function persistAttemptArtifact(signatureRoot, packet, receipt, kind, value) {
  const paths = resolverRerunAttemptPaths(signatureRoot, packet, receipt.orchestrator_nonce);
  mkdirSync(paths.root, { recursive: true, mode: 0o700 });
  const path = paths[kind];
  const payload = `${canonicalJson(value)}\n`;
  if (!writeTrustedFileExclusiveSync(path, signatureRoot, payload) && readFileSync(path, "utf8") !== payload) {
    throw new Error(`resolver rerun attempt already binds different ${kind} content`);
  }
  return path;
}

export function bindResolverRerunReceipt(signatureRoot, packet, receipt) {
  const value = {
    schema_version: "p42-resolver-rerun-receipt-binding/v1",
    packet_hash: packet.packet_hash,
    decision_digest: packet.decision_digest,
    challenge_instance_hash: packet.decision.challengeInstanceHash,
    orchestrator_nonce: receipt.orchestrator_nonce,
    receipt_hash: receipt.receipt_hash,
    local_transcript_hash: receipt.local_transcript_hash,
  };
  return persistAttemptArtifact(signatureRoot, packet, receipt, "receipt", value);
}

export function isResolverRerunReceiptBound(signatureRoot, packet, receipt) {
  const path = resolverRerunAttemptPaths(signatureRoot, packet, receipt.orchestrator_nonce).receipt;
  if (!existsSync(path)) return false;
  const existing = readStrictJsonFileSync(path, { ...RECEIPT_LIMITS, trustedRoot: signatureRoot });
  const expected = {
    schema_version: "p42-resolver-rerun-receipt-binding/v1",
    packet_hash: packet.packet_hash,
    decision_digest: packet.decision_digest,
    challenge_instance_hash: packet.decision.challengeInstanceHash,
    orchestrator_nonce: receipt.orchestrator_nonce,
    receipt_hash: receipt.receipt_hash,
    local_transcript_hash: receipt.local_transcript_hash,
  };
  if (canonicalJson(existing) !== canonicalJson(expected)) {
    throw new Error("resolver rerun attempt already binds different receipt content");
  }
  return true;
}

export function markResolverRerunAuthorization(signatureRoot, packet, receipt, authorizationPath) {
  return persistAttemptArtifact(signatureRoot, packet, receipt, "authorization", {
    schema_version: "p42-resolver-rerun-authorization-marker/v1",
    packet_hash: packet.packet_hash,
    orchestrator_nonce: receipt.orchestrator_nonce,
    receipt_hash: receipt.receipt_hash,
    authorization_path: authorizationPath,
  });
}

export function markResolverRerunSignature(signatureRoot, packet, receipt, output, artifact) {
  return persistAttemptArtifact(signatureRoot, packet, receipt, "signature", {
    schema_version: "p42-resolver-rerun-signature-marker/v1",
    packet_hash: packet.packet_hash,
    orchestrator_nonce: receipt.orchestrator_nonce,
    receipt_hash: receipt.receipt_hash,
    output,
    signer: artifact.signer,
    decision_digest: artifact.decision_digest,
  });
}

export function resolverRerunReceiptSigningMessage(receiptHash) {
  if (!SHA256_RE.test(receiptHash ?? "")) throw new Error("resolver rerun receipt hash is invalid");
  return receiptMessage(receiptHash);
}
