#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ethers } from "ethers";

import {
  collectCanonicalOpenWitnessLaunchEvidence,
  collectMultiBoardFinalizedReconciliation,
  instantiateBoardContracts,
  loadContractArtifacts,
  manifestProblemForRegistryId,
  stableStringify,
  validateManifestEvidence,
  writeFileAtomicSync,
} from "./indexer.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

export const COLLECTOR_AUTHORITY_CLASS = "p42-open-witness-collector-authority/v1";
const DOMAIN = "P42-OPEN-WITNESS-COLLECTOR-AUTHORITY-V1";
const ED25519_PUBLIC_DER_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
export const PRODUCTION_POLICY_PATH = "/etc/p42/open-witness-collector-policy.json";
export const PRODUCTION_POLICY_ROOT = "/etc/p42/open-witness-collector-policy.sha256";
export const PRODUCTION_SIGNING_KEY_PATH = "/etc/p42/open-witness-collector-key.pem";
const JSON_LIMITS = { maxBytes: 4 * 1024 * 1024, maxDepth: 128, canonical: false, trailingNewline: "allow-one" };

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function canonicalSha256(value) {
  return `sha256:${createHash("sha256").update(stableStringify(value)).digest("hex")}`;
}

function requireDigest(value, label) {
  invariant(/^sha256:[0-9a-f]{64}$/.test(String(value)), `${label} must be sha256:<64-lowercase-hex>`);
  return value;
}

function requireProviderSet(policy, observations) {
  invariant(policy?.schema_version === "p42-open-witness-collector-policy/v1", "collector policy schema is invalid");
  const configured = policy.rpc_endpoints?.map((entry) => entry.identity);
  invariant(Array.isArray(configured) && configured.length === 3 && new Set(configured).size === 3, "collector policy must pin three distinct providers");
  invariant(policy.rpc_quorum === 2, "collector policy must require exact 2-of-3 quorum");
  invariant(policy.network?.name === "base-sepolia" && policy.network?.chain_id === 84532, "collector policy network is invalid");
  invariant(policy.finality_confirmations >= 12, "collector policy finality is too weak");
  invariant(policy.authority_class === COLLECTOR_AUTHORITY_CLASS, "collector policy authority class is invalid");
  const endpointUrls = policy.rpc_endpoints.map((entry) => {
    let parsed;
    try { parsed = new URL(entry.url); } catch { throw new Error(`collector RPC ${entry.identity} URL is invalid`); }
    invariant(parsed.protocol === "https:" && !parsed.username && !parsed.password && !parsed.search && !parsed.hash, `collector RPC ${entry.identity} URL must be credential-free HTTPS`);
    return parsed.href.toLowerCase();
  });
  invariant(new Set(endpointUrls).size === 3, "collector policy must pin three distinct RPC URLs");
  invariant(Array.isArray(observations) && observations.length === 3, "collector quorum requires one observation per configured provider");
  const observed = observations.map((entry) => entry?.provider_id);
  invariant(new Set(observed).size === 3, "collector observations must use distinct provider identities");
  invariant(stableStringify([...observed].sort()) === stableStringify([...configured].sort()), "collector observations do not match the pinned provider set");
}

function readProtectedFile(path, { maxBytes, ascii = false }) {
  invariant(typeof constants.O_NOFOLLOW === "number" && constants.O_NOFOLLOW !== 0, "protected files require O_NOFOLLOW support");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    invariant(before.isFile(), `protected file ${path} must be regular`);
    invariant(before.uid === 0, `protected file ${path} must be root-owned`);
    invariant((before.mode & 0o222) === 0, `protected file ${path} must not be writable`);
    invariant(before.size <= maxBytes, `protected file ${path} is oversized`);
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    invariant(bytes.length === before.size && before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeMs === after.mtimeMs, `protected file ${path} changed while reading`);
    if (ascii) invariant(bytes.every((byte) => byte <= 0x7f), `protected file ${path} must be ASCII`);
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function readProductionPolicy() {
  const policy = readStrictJsonFileSync(PRODUCTION_POLICY_PATH, JSON_LIMITS);
  invariant(policy.environment === "production", "fixed collector policy must be production");
  requireProviderSet(policy, policy.rpc_endpoints.map((entry) => ({ provider_id: entry.identity })));
  const expected = readProtectedFile(PRODUCTION_POLICY_ROOT, { maxBytes: 256, ascii: true }).toString("ascii").trim();
  requireDigest(expected, "protected policy root");
  invariant(canonicalSha256(policy) === expected, "collector policy does not match protected root");
  return { policy, policyDigest: expected };
}

function digestToBytes32(value, label) {
  const digest = requireDigest(value, label);
  return `0x${digest.slice(7)}`;
}

export function agreeCollectorEvidence({ policy, policyDigest, manifestDigest, launchEvidenceHash, observations }) {
  requireDigest(policyDigest, "policyDigest");
  requireDigest(manifestDigest, "manifestDigest");
  requireDigest(launchEvidenceHash, "launchEvidenceHash");
  requireProviderSet(policy, observations);
  invariant(canonicalSha256(policy) === policyDigest, "collector policy digest mismatch");
  invariant(policy.release_binding?.manifest_sha256 === manifestDigest, "collector manifest digest does not match policy");
  invariant(policy.environment === "production" || policy.environment === "test", "collector policy environment is invalid");
  const groups = new Map();
  for (const observation of observations) {
    invariant(observation && typeof observation === "object", "collector observation must be an object");
    const evidence = observation.evidence;
    invariant(evidence?.schema === "p42-prizes/open-witness-launch-evidence/v1", "collector observation evidence schema is invalid");
    invariant(evidence.collector_authoritative === false, "provider observations must begin non-authoritative");
    invariant(observation.policy_digest === policyDigest, "collector observation policy digest mismatch");
    invariant(observation.manifest_digest === manifestDigest, "collector observation manifest digest mismatch");
    const digest = canonicalSha256(evidence);
    invariant(observation.evidence_digest === digest, "collector observation evidence digest mismatch");
    const group = groups.get(digest) ?? [];
    group.push(observation.provider_id);
    groups.set(digest, group);
  }
  const agreed = [...groups.entries()].filter(([, ids]) => ids.length >= policy.rpc_quorum);
  invariant(agreed.length === 1, "collector providers did not produce one exact quorum proof");
  const [evidenceDigest, providerIds] = agreed[0];
  const evidence = observations.find((entry) => entry.evidence_digest === evidenceDigest).evidence;
  return {
    schema_version: "p42-open-witness-quorum/v1",
    environment: policy.environment,
    policy_digest: policyDigest,
    manifest_digest: manifestDigest,
    launch_evidence_hash: launchEvidenceHash,
    evidence_digest: evidenceDigest,
    provider_ids: [...providerIds].sort(),
    finalized_evidence: evidence.finalizedEvidence,
    evidence,
  };
}

export async function collectPinnedProviderQuorum({
  policy,
  policyDigest,
  manifestDigest,
  launchEvidenceHash,
  providerFactory,
  collectEvidence,
}) {
  invariant(typeof providerFactory === "function" && typeof collectEvidence === "function", "collector adapter functions are required");
  invariant(canonicalSha256(policy) === policyDigest, "collector policy digest mismatch");
  const endpoints = policy.rpc_endpoints;
  invariant(Array.isArray(endpoints) && endpoints.length === 3, "collector policy must pin three RPC endpoints");
  const clients = [];
  try {
    for (const endpoint of endpoints) {
      const provider = await providerFactory(endpoint);
      invariant(provider && typeof provider.getBlockNumber === "function", `provider ${endpoint.identity} is unavailable`);
      clients.push({ endpoint, provider });
    }
    invariant(new Set(clients.map((entry) => entry.provider)).size === 3, "collector provider factory reused a client across endpoint identities");
    const heads = await Promise.all(clients.map(({ provider }) => provider.getBlockNumber()));
    invariant(heads.every(Number.isSafeInteger), "collector provider returned an invalid chain head");
    const finalityAnchorBlockNumber = Math.min(...heads.map((head) => head - policy.finality_confirmations));
    invariant(finalityAnchorBlockNumber >= 0, "collector providers have no shared finalized anchor");
    const observations = await Promise.all(clients.map(async ({ endpoint, provider }) => {
      const evidence = await collectEvidence({ endpoint, provider, finalityAnchorBlockNumber });
      return {
        provider_id: endpoint.identity,
        policy_digest: policyDigest,
        manifest_digest: manifestDigest,
        evidence_digest: canonicalSha256(evidence),
        evidence,
      };
    }));
    return agreeCollectorEvidence({ policy, policyDigest, manifestDigest, launchEvidenceHash, observations });
  } finally {
    await Promise.allSettled(clients.map(({ provider }) => typeof provider.destroy === "function" ? provider.destroy() : undefined));
  }
}

export function collectorAuthorityMessage(quorum, metadata) {
  invariant(quorum?.schema_version === "p42-open-witness-quorum/v1", "collector quorum schema is invalid");
  const binding = {
    authority_class: COLLECTOR_AUTHORITY_CLASS,
    environment: quorum.environment,
    policy_digest: quorum.policy_digest,
    manifest_digest: quorum.manifest_digest,
    launch_evidence_hash: quorum.launch_evidence_hash,
    evidence_digest: quorum.evidence_digest,
    provider_ids: quorum.provider_ids,
    finalized_evidence: quorum.finalized_evidence,
    key_id: metadata?.key_id,
    signed_at_utc: metadata?.signed_at_utc,
  };
  return Buffer.from(`${DOMAIN}\n${stableStringify(binding)}`, "utf8");
}

export function signCollectorQuorum({ quorum, policy, keyId, privateKey, signedAtUtc }) {
  invariant(quorum.environment === "production", "test collector policy can never produce an authority envelope");
  invariant(canonicalSha256(policy) === quorum.policy_digest, "collector signing policy digest mismatch");
  invariant(policy.authority_class === COLLECTOR_AUTHORITY_CLASS && policy.authority_key_ids?.includes(keyId), "collector signing key is not authorized by policy");
  invariant(typeof keyId === "string" && keyId.length >= 3, "collector authority key id is invalid");
  invariant(typeof signedAtUtc === "string" && Number.isFinite(Date.parse(signedAtUtc)), "collector authority signing time is invalid");
  const key = typeof privateKey === "string" || Buffer.isBuffer(privateKey) ? createPrivateKey(privateKey) : privateKey;
  const metadata = { key_id: keyId, signed_at_utc: signedAtUtc };
  const signature = sign(null, collectorAuthorityMessage(quorum, metadata), key);
  return {
    schema_version: COLLECTOR_AUTHORITY_CLASS,
    policy_digest: quorum.policy_digest,
    manifest_digest: quorum.manifest_digest,
    launch_evidence_hash: quorum.launch_evidence_hash,
    evidence_digest: quorum.evidence_digest,
    provider_ids: quorum.provider_ids,
    finalized_evidence: quorum.finalized_evidence,
    key_id: keyId,
    signed_at_utc: signedAtUtc,
    signature: `ed25519:${signature.toString("hex")}`,
  };
}

export function verifyCollectorAuthorityEnvelope({ quorum, envelope, registration }) {
  invariant(envelope?.schema_version === COLLECTOR_AUTHORITY_CLASS, "collector authority envelope schema is invalid");
  invariant(registration?.attestation_class === COLLECTOR_AUTHORITY_CLASS, "collector key registration class is invalid");
  invariant(registration.signer_role === "collector-authority", "collector key registration role is invalid");
  invariant(envelope.key_id === registration.key_id, "collector authority key id is not registered");
  for (const field of ["policy_digest", "manifest_digest", "launch_evidence_hash", "evidence_digest"]) {
    invariant(envelope[field] === quorum[field], `collector authority ${field} mismatch`);
  }
  invariant(stableStringify(envelope.provider_ids) === stableStringify(quorum.provider_ids), "collector authority provider quorum mismatch");
  invariant(stableStringify(envelope.finalized_evidence) === stableStringify(quorum.finalized_evidence), "collector authority finality binding mismatch");
  const rawPublicKey = String(registration.public_key).match(/^ed25519:([0-9a-f]{64})$/)?.[1];
  const rawSignature = String(envelope.signature).match(/^ed25519:([0-9a-f]{128})$/)?.[1];
  invariant(rawPublicKey && rawSignature, "collector authority signature encoding is invalid");
  const publicKey = createPublicKey({ key: Buffer.concat([ED25519_PUBLIC_DER_PREFIX, Buffer.from(rawPublicKey, "hex")]), format: "der", type: "spki" });
  invariant(verify(null, collectorAuthorityMessage(quorum, envelope), publicKey, Buffer.from(rawSignature, "hex")), "collector authority signature is invalid");
  return true;
}

export function evidenceDigest(evidence) {
  return canonicalSha256(evidence);
}

export function requireRawLaunchEvidence(report) {
  const launchEvidenceHash = requireDigest(report?.evidence_hash, "report.evidence_hash");
  invariant(report.gate_passed !== true, "collector rejects caller-authored gate_passed=true");
  invariant(report.evidence_valid !== true, "collector rejects caller-authored evidence_valid=true");
  invariant(report.attestation_valid !== true, "collector rejects caller-authored attestation_valid=true");
  invariant(report.collector_authoritative !== true, "collector rejects caller-authored collector_authoritative=true");
  return launchEvidenceHash;
}

export async function runProductionOpenWitnessCollection({ reportPath, outPath }) {
  invariant(reportPath && outPath, "required: --report <raw-launch-evidence.json> --out <collector.json>");
  const { policy, policyDigest } = readProductionPolicy();
  const manifest = readStrictJsonFileSync(policy.release_binding.manifest_path, JSON_LIMITS);
  validateManifestEvidence(manifest);
  const manifestDigest = canonicalSha256(manifest);
  invariant(manifestDigest === policy.release_binding.manifest_sha256, "deployment manifest digest does not match collector policy");
  invariant(manifest.deploymentCommit === policy.release_binding.git_commit, "deployment commit does not match collector policy");
  invariant(manifest.deploymentConfigHash === policy.release_binding.deployment_config_hash, "deployment config hash does not match collector policy");
  invariant(manifest.network.chainId === policy.network.chain_id, "deployment network does not match collector policy");
  invariant(policy.finality_confirmations >= manifest.indexer.finalityPolicy.confirmations, "collector finality cannot weaken deployment finality");

  const report = readStrictJsonFileSync(resolve(reportPath), JSON_LIMITS);
  const launchEvidenceHash = requireRawLaunchEvidence(report);
  const registryProblemId = String(report.board?.registry_problem_id ?? "");
  const submissionId = String(report.witness?.submission_id ?? "");
  const problem = manifestProblemForRegistryId(manifest, registryProblemId);
  invariant(problem.problemSlug === report.board?.slug, "collector report board does not match manifest");
  const artifacts = loadContractArtifacts();

  const quorum = await collectPinnedProviderQuorum({
    policy, policyDigest, manifestDigest, launchEvidenceHash,
    providerFactory: async (endpoint) => new ethers.JsonRpcProvider(endpoint.url, policy.network.chain_id, { staticNetwork: true }),
    collectEvidence: async ({ provider, finalityAnchorBlockNumber }) => {
      const contractsByProblem = manifest.problems.map((entry) => ({
        problem: entry, contracts: instantiateBoardContracts(provider, manifest, entry, artifacts),
      }));
      const { boards } = await collectMultiBoardFinalizedReconciliation({
        provider, contractsByProblem, artifacts, manifest,
        fromBlock: manifest.indexer.startBlock, toBlock: finalityAnchorBlockNumber,
        policy: manifest.indexer.finalityPolicy,
      });
      const board = boards.find((entry) => String(entry.problem.problemId) === registryProblemId);
      invariant(board, "collector reconciliation omitted selected board");
      return collectCanonicalOpenWitnessLaunchEvidence({
        replay: board.replay, manifest, problemId: registryProblemId, submissionId,
        transcriptHash: digestToBytes32(report.witness.transcript_hash, "report witness transcript hash"),
        reportHash: digestToBytes32(report.witness.report_hash, "report witness report hash"),
        provider, finalityAnchorBlockNumber,
      });
    },
  });

  const privateKeyBytes = readProtectedFile(PRODUCTION_SIGNING_KEY_PATH, { maxBytes: 16 * 1024 });
  const keyId = policy.authority_key_ids[0];
  const authorityEnvelope = signCollectorQuorum({
    quorum, policy, keyId, privateKey: privateKeyBytes,
    signedAtUtc: new Date().toISOString(),
  });
  const output = { quorum, authority_envelope: authorityEnvelope };
  writeFileAtomicSync(resolve(outPath), `${stableStringify(output)}\n`);
  return output;
}

function parseArg(argv, name) {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? undefined : argv[index + 1];
}

export async function cli(argv = process.argv) {
  return runProductionOpenWitnessCollection({ reportPath: parseArg(argv, "report"), outPath: parseArg(argv, "out") });
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  cli().catch((error) => {
    console.error(`FAILED: ${error.shortMessage ?? error.message}`);
    process.exitCode = 1;
  });
}
