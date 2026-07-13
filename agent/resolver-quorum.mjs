import { ethers } from "ethers";

import { canonicalJson, sha256Canonical } from "./lib.mjs";

export const RESOLVER_QUORUM_DECISION_TYPES = Object.freeze({
  Decision: Object.freeze([
    { name: "chainId", type: "uint256" },
    { name: "adapter", type: "address" },
    { name: "manager", type: "address" },
    { name: "submissionId", type: "uint256" },
    { name: "challengeInstanceHash", type: "bytes32" },
    { name: "challengerWins", type: "bool" },
    { name: "transcriptHash", type: "bytes32" },
    { name: "transcriptURIHash", type: "bytes32" },
    { name: "verdictHash", type: "bytes32" },
    { name: "bondBeneficiary", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "expiry", type: "uint64" },
    { name: "signerEpoch", type: "uint64" },
  ]),
});

const PACKET_KEYS = Object.freeze([
  "schema_version",
  "domain",
  "decision",
  "transcript_uri",
  "decision_digest",
  "packet_hash",
]);
const DOMAIN_KEYS = Object.freeze(["name", "version", "chainId", "verifyingContract"]);
const DECISION_KEYS = Object.freeze(RESOLVER_QUORUM_DECISION_TYPES.Decision.map(({ name }) => name));
const SIGNATURE_KEYS = Object.freeze([
  "schema_version",
  "decision_digest",
  "signer",
  "signature",
  "artifact_hash",
]);

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const missing = keys.filter((key) => !(key in value));
  const extra = Object.keys(value).filter((key) => !keys.includes(key));
  if (missing.length || extra.length) {
    throw new Error(`${label} keys mismatch (missing=${missing.join(",") || "none"}; extra=${extra.join(",") || "none"})`);
  }
  return value;
}

function address(value, label) {
  if (!ethers.isAddress(value)) throw new Error(`${label} must be an EVM address`);
  return ethers.getAddress(value).toLowerCase();
}

function bytes32(value, label) {
  if (!ethers.isHexString(value, 32) || String(value).toLowerCase() === ethers.ZeroHash) {
    throw new Error(`${label} must be a nonzero bytes32`);
  }
  return String(value).toLowerCase();
}

function unsignedDecimal(value, label, { nonzero = false, max = null } = {}) {
  const text = String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`${label} must be an unsigned canonical integer`);
  const parsed = BigInt(text);
  if (nonzero && parsed === 0n) throw new Error(`${label} must be nonzero`);
  if (max !== null && parsed > max) throw new Error(`${label} exceeds its integer width`);
  return text;
}

function packetWithoutHash(packet) {
  const copy = { ...packet };
  delete copy.packet_hash;
  return copy;
}

function artifactWithoutHash(artifact) {
  const copy = { ...artifact };
  delete copy.artifact_hash;
  return copy;
}

export function deterministicResolverNonce(challengeInstanceHash) {
  return unsignedDecimal(BigInt(bytes32(challengeInstanceHash, "challengeInstanceHash")), "resolver nonce", { nonzero: true });
}

export function buildResolverQuorumDecisionPacket({
  chainId,
  adapter,
  manager,
  submissionId,
  challengeInstanceHash,
  challengerWins,
  transcriptHash,
  transcriptURI,
  verdictHash,
  nonce = deterministicResolverNonce(challengeInstanceHash),
  expiry,
  signerEpoch,
}) {
  if (typeof transcriptURI !== "string" || !transcriptURI) throw new Error("transcriptURI must be non-empty");
  const chain = unsignedDecimal(chainId, "chainId", { nonzero: true });
  const adapterAddress = address(adapter, "adapter");
  const decision = {
    chainId: chain,
    adapter: adapterAddress,
    manager: address(manager, "manager"),
    submissionId: unsignedDecimal(submissionId, "submissionId", { nonzero: true }),
    challengeInstanceHash: bytes32(challengeInstanceHash, "challengeInstanceHash"),
    challengerWins: Boolean(challengerWins),
    transcriptHash: bytes32(transcriptHash, "transcriptHash"),
    transcriptURIHash: ethers.keccak256(ethers.toUtf8Bytes(transcriptURI)),
    verdictHash: bytes32(verdictHash, "verdictHash"),
    bondBeneficiary: adapterAddress,
    nonce: unsignedDecimal(nonce, "nonce", { nonzero: true }),
    expiry: unsignedDecimal(expiry, "expiry", { nonzero: true, max: (1n << 64n) - 1n }),
    signerEpoch: unsignedDecimal(signerEpoch, "signerEpoch", { nonzero: true, max: (1n << 64n) - 1n }),
  };
  const domain = {
    name: "P42ResolverQuorum",
    version: "1",
    chainId: chain,
    verifyingContract: adapterAddress,
  };
  const decisionDigest = ethers.TypedDataEncoder.hash(domain, RESOLVER_QUORUM_DECISION_TYPES, decision).toLowerCase();
  const packet = {
    schema_version: "p42-resolver-quorum-decision/v1",
    domain,
    decision,
    transcript_uri: transcriptURI,
    decision_digest: decisionDigest,
  };
  packet.packet_hash = sha256Canonical(packet);
  return packet;
}

export function validateResolverQuorumDecisionPacket(value) {
  const packet = exactObject(value, PACKET_KEYS, "resolver quorum decision packet");
  if (packet.schema_version !== "p42-resolver-quorum-decision/v1") throw new Error("unsupported resolver quorum decision packet");
  exactObject(packet.domain, DOMAIN_KEYS, "resolver quorum domain");
  exactObject(packet.decision, DECISION_KEYS, "resolver quorum decision");
  const rebuilt = buildResolverQuorumDecisionPacket({
    chainId: packet.decision.chainId,
    adapter: packet.decision.adapter,
    manager: packet.decision.manager,
    submissionId: packet.decision.submissionId,
    challengeInstanceHash: packet.decision.challengeInstanceHash,
    challengerWins: packet.decision.challengerWins,
    transcriptHash: packet.decision.transcriptHash,
    transcriptURI: packet.transcript_uri,
    verdictHash: packet.decision.verdictHash,
    nonce: packet.decision.nonce,
    expiry: packet.decision.expiry,
    signerEpoch: packet.decision.signerEpoch,
  });
  if (canonicalJson(packet.domain) !== canonicalJson(rebuilt.domain)
      || canonicalJson(packet.decision) !== canonicalJson(rebuilt.decision)
      || packet.decision_digest !== rebuilt.decision_digest
      || packet.packet_hash !== sha256Canonical(packetWithoutHash(packet))) {
    throw new Error("resolver quorum decision packet binding mismatch");
  }
  return packet;
}

export async function buildResolverQuorumSignatureArtifact(packetValue, signer) {
  const packet = validateResolverQuorumDecisionPacket(packetValue);
  if (!signer?.signTypedData || !signer?.getAddress) throw new Error("resolver quorum signer is not EIP-712 capable");
  const signerAddress = address(await signer.getAddress(), "signer");
  const signature = await signer.signTypedData(packet.domain, RESOLVER_QUORUM_DECISION_TYPES, packet.decision);
  const recovered = address(ethers.verifyTypedData(packet.domain, RESOLVER_QUORUM_DECISION_TYPES, packet.decision, signature), "recovered signer");
  if (recovered !== signerAddress) throw new Error("resolver quorum signature did not recover to signer");
  const artifact = {
    schema_version: "p42-resolver-quorum-signature/v1",
    decision_digest: packet.decision_digest,
    signer: signerAddress,
    signature,
  };
  artifact.artifact_hash = sha256Canonical(artifact);
  return artifact;
}

export function validateResolverQuorumSignatureArtifact(value, packetValue) {
  const packet = validateResolverQuorumDecisionPacket(packetValue);
  const artifact = exactObject(value, SIGNATURE_KEYS, "resolver quorum signature artifact");
  if (artifact.schema_version !== "p42-resolver-quorum-signature/v1") throw new Error("unsupported resolver quorum signature artifact");
  if (artifact.decision_digest !== packet.decision_digest) throw new Error("resolver quorum signature belongs to another decision");
  const claimed = address(artifact.signer, "signature signer");
  if (!ethers.isHexString(artifact.signature, 65)) throw new Error("resolver quorum signature must be 65 bytes");
  const recovered = address(
    ethers.verifyTypedData(packet.domain, RESOLVER_QUORUM_DECISION_TYPES, packet.decision, artifact.signature),
    "recovered signer",
  );
  if (claimed !== recovered) throw new Error("resolver quorum signature signer mismatch");
  if (artifact.artifact_hash !== sha256Canonical(artifactWithoutHash(artifact))) {
    throw new Error("resolver quorum signature artifact self-hash mismatch");
  }
  return { artifact, signer: recovered };
}

export async function collectResolverQuorumSignatures({ packet: packetValue, artifacts, quorum }) {
  const packet = validateResolverQuorumDecisionPacket(packetValue);
  if (!Array.isArray(artifacts)) throw new Error("resolver quorum signature artifacts must be an array");
  const epoch = BigInt(packet.decision.signerEpoch);
  const [liveEpoch, threshold] = await Promise.all([quorum.signerEpoch(), quorum.epochThreshold(epoch)]);
  if (BigInt(liveEpoch) !== epoch) throw new Error("resolver quorum decision signer epoch is stale");
  if (BigInt(threshold) < 1n) throw new Error("resolver quorum signer epoch has no threshold");
  const accepted = [];
  const rejected = [];
  const seen = new Set();
  for (const [index, value] of artifacts.entries()) {
    try {
      const checked = validateResolverQuorumSignatureArtifact(value, packet);
      if (seen.has(checked.signer)) {
        rejected.push({ index, reason: `duplicate resolver quorum signer artifact: ${checked.signer}` });
        continue;
      }
      seen.add(checked.signer);
      if (await quorum.isEpochSigner(epoch, checked.signer) !== true) {
        rejected.push({ index, reason: `resolver quorum signature is not from an epoch signer: ${checked.signer}` });
        continue;
      }
      accepted.push(checked);
    } catch (error) {
      rejected.push({ index, reason: error.message });
    }
  }
  accepted.sort((left, right) => left.signer.localeCompare(right.signer));
  return {
    ready: BigInt(accepted.length) >= BigInt(threshold),
    threshold: Number(threshold),
    signers: accepted.map(({ signer }) => signer),
    signatures: accepted.map(({ artifact }) => artifact.signature),
    rejected,
  };
}
