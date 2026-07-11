import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

export const COLLECTOR_AUTHORITY_CLASS = "p42-open-witness-collector-authority/v1";
const DOMAIN = "P42-OPEN-WITNESS-COLLECTOR-AUTHORITY-V1";
const ED25519_PUBLIC_DER_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function canonicalize(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

export function stableStringify(value) {
  return JSON.stringify(canonicalize(value));
}

export function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

export function canonicalSha256(value) {
  return `sha256:${createHash("sha256").update(stableStringify(value)).digest("hex")}`;
}

export function requireDigest(value, label) {
  invariant(/^sha256:[0-9a-f]{64}$/.test(String(value)), `${label} must be sha256:<64-lowercase-hex>`);
  return value;
}

export function requireProviderSet(policy, observations) {
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
  const providerObservations = [...observations]
    .sort((left, right) => left.provider_id.localeCompare(right.provider_id))
    .map((entry) => ({ provider_id: entry.provider_id, evidence_digest: entry.evidence_digest, evidence: entry.evidence }));
  return {
    schema_version: "p42-open-witness-quorum/v1",
    environment: policy.environment,
    policy_digest: policyDigest,
    manifest_digest: manifestDigest,
    launch_evidence_hash: launchEvidenceHash,
    evidence_digest: evidenceDigest,
    provider_ids: [...providerIds].sort(),
    observation_transcript_digest: canonicalSha256(providerObservations),
    provider_observations: providerObservations,
    finalized_evidence: evidence.finalizedEvidence,
    evidence,
  };
}

export async function collectPinnedProviderQuorum({ policy, policyDigest, manifestDigest, launchEvidenceHash, providerFactory, collectEvidence }) {
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
    observation_transcript_digest: quorum.observation_transcript_digest,
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
    observation_transcript_digest: quorum.observation_transcript_digest,
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
  for (const field of ["policy_digest", "manifest_digest", "launch_evidence_hash", "evidence_digest", "observation_transcript_digest"]) {
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
