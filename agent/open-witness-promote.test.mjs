import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";

import {
  COLLECTOR_AUTHORITY_CLASS,
  agreeCollectorEvidence,
  collectPinnedProviderQuorum,
  evidenceDigest,
  requireRawLaunchEvidence,
  signCollectorQuorum,
  verifyCollectorAuthorityEnvelope,
} from "./open-witness-promote.mjs";

const hash = (value) => `sha256:${String(value).padStart(64, "0")}`;
const policy = {
  schema_version: "p42-open-witness-collector-policy/v1", environment: "production",
  network: { name: "base-sepolia", chain_id: 84532 },
  rpc_endpoints: [{ identity: "a", url: "https://a.example" }, { identity: "b", url: "https://b.example" }, { identity: "c", url: "https://c.example" }], rpc_quorum: 2,
  release_binding: { manifest_sha256: hash(2) }, finality_confirmations: 12,
  authority_class: COLLECTOR_AUTHORITY_CLASS, authority_key_ids: ["collector-1"],
};
const evidence = (block = 50) => ({
  schema: "p42-prizes/open-witness-launch-evidence/v1", collector_authoritative: false,
  finalizedEvidence: { blockNumber: block, blockHash: `0x${"ab".repeat(32)}` }, value: "bound",
});
const observation = (providerId, value) => ({
  provider_id: providerId, policy_digest: evidenceDigest(policy), manifest_digest: hash(2),
  evidence_digest: evidenceDigest(value), evidence: value,
});

describe("production open-witness quorum authority", () => {
  it("requires exact 2-of-3 agreement and verifies an Ed25519 authority envelope", () => {
    const agreed = evidence(); const dissent = evidence(51);
    const quorum = agreeCollectorEvidence({
      policy, policyDigest: evidenceDigest(policy), manifestDigest: hash(2), launchEvidenceHash: hash(3),
      observations: [observation("a", agreed), observation("b", agreed), observation("c", dissent)],
    });
    assert.deepEqual(quorum.provider_ids, ["a", "b"]);
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    const envelope = signCollectorQuorum({ quorum, policy, keyId: "collector-1", privateKey, signedAtUtc: "2026-07-11T00:00:00Z" });
    const registration = {
      key_id: "collector-1", attestation_class: COLLECTOR_AUTHORITY_CLASS,
      signer_role: "collector-authority", public_key: `ed25519:${publicDer.subarray(-32).toString("hex")}`,
    };
    assert.equal(verifyCollectorAuthorityEnvelope({ quorum, envelope, registration }), true);
    assert.throws(() => verifyCollectorAuthorityEnvelope({ quorum: { ...quorum, evidence_digest: hash(9) }, envelope, registration }), /evidence_digest mismatch/);
    const relabeledTime = { ...envelope, signed_at_utc: "2026-07-11T00:00:01Z" };
    assert.throws(() => verifyCollectorAuthorityEnvelope({ quorum, envelope: relabeledTime, registration }), /signature is invalid/);
  });

  it("rejects provider identity, digest, authority, and quorum confusion", () => {
    const a = evidence(); const b = evidence(51); const c = evidence(52);
    const base = { policy, policyDigest: evidenceDigest(policy), manifestDigest: hash(2), launchEvidenceHash: hash(3) };
    assert.throws(() => agreeCollectorEvidence({ ...base, observations: [observation("a", a), observation("a", a), observation("c", a)] }), /distinct provider/);
    assert.throws(() => agreeCollectorEvidence({ ...base, observations: [observation("a", a), observation("b", b), observation("c", c)] }), /did not produce one exact quorum/);
    const forged = observation("a", a); forged.evidence_digest = hash(8);
    assert.throws(() => agreeCollectorEvidence({ ...base, observations: [forged, observation("b", a), observation("c", a)] }), /evidence digest mismatch/);
    assert.throws(() => agreeCollectorEvidence({ ...base, observations: [observation("a", { ...a, collector_authoritative: true }), observation("b", a), observation("c", a)] }), /begin non-authoritative/);
  });

  it("never signs authority under a test policy", () => {
    const testPolicy = { ...policy, environment: "test" };
    const value = evidence();
    const observations = ["a", "b", "c"].map((providerId) => ({
      ...observation(providerId, value), policy_digest: evidenceDigest(testPolicy),
    }));
    const quorum = agreeCollectorEvidence({
      policy: testPolicy, policyDigest: evidenceDigest(testPolicy), manifestDigest: hash(2), launchEvidenceHash: hash(3),
      observations,
    });
    const { privateKey } = generateKeyPairSync("ed25519");
    assert.throws(() => signCollectorQuorum({ quorum, policy: testPolicy, keyId: "collector-1", privateKey, signedAtUtc: "2026-07-11T00:00:00Z" }), /test collector policy/);
  });

  it("accepts only raw fail-closed launch evidence", () => {
    const raw = { evidence_hash: hash(3) };
    assert.equal(requireRawLaunchEvidence(raw), hash(3));
    assert.equal(requireRawLaunchEvidence({ ...raw, gate_passed: false, evidence_valid: false, attestation_valid: false }), hash(3));
    for (const field of ["gate_passed", "evidence_valid", "attestation_valid", "collector_authoritative"]) {
      assert.throws(() => requireRawLaunchEvidence({ ...raw, [field]: true }), new RegExp(field));
    }
  });

  it("collects each pinned endpoint independently at one shared finalized anchor", async () => {
    const calls = [];
    const providers = new Map([["a", { head: 100 }], ["b", { head: 102 }], ["c", { head: 101 }]]);
    const quorum = await collectPinnedProviderQuorum({
      policy, policyDigest: evidenceDigest(policy), manifestDigest: hash(2), launchEvidenceHash: hash(3),
      providerFactory: async (endpoint) => {
        const state = providers.get(endpoint.identity);
        return { async getBlockNumber() { return state.head; }, destroy() { state.destroyed = true; } };
      },
      collectEvidence: async ({ endpoint, finalityAnchorBlockNumber }) => {
        calls.push([endpoint.identity, finalityAnchorBlockNumber]);
        return evidence(finalityAnchorBlockNumber);
      },
    });
    assert.deepEqual(calls, [["a", 88], ["b", 88], ["c", 88]]);
    assert.deepEqual(quorum.provider_ids, ["a", "b", "c"]);
    assert.equal([...providers.values()].every((entry) => entry.destroyed), true);
    const shared = { async getBlockNumber() { return 100; } };
    await assert.rejects(() => collectPinnedProviderQuorum({
      policy, policyDigest: evidenceDigest(policy), manifestDigest: hash(2), launchEvidenceHash: hash(3),
      providerFactory: async () => shared, collectEvidence: async () => evidence(),
    }), /reused a client/);
  });
});
