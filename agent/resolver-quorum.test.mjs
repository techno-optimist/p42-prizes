import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { ethers } from "ethers";

import {
  buildResolverQuorumDecisionPacket,
  buildResolverQuorumSignatureArtifact,
  collectResolverQuorumSignatures,
  deterministicResolverNonce,
  validateResolverQuorumDecisionPacket,
  validateResolverQuorumSignatureArtifact,
} from "./resolver-quorum.mjs";

const wallets = [ethers.Wallet.createRandom(), ethers.Wallet.createRandom(), ethers.Wallet.createRandom()];
const adapter = ethers.Wallet.createRandom().address;
const manager = ethers.Wallet.createRandom().address;

function packet(overrides = {}) {
  return buildResolverQuorumDecisionPacket({
    chainId: 84532,
    adapter,
    manager,
    submissionId: 7,
    challengeInstanceHash: ethers.id("challenge"),
    challengerWins: true,
    transcriptHash: ethers.id("transcript"),
    transcriptURI: "ipfs://canonical-transcript",
    verdictHash: ethers.id("verdict"),
    expiry: 2_000_000_000,
    signerEpoch: 3,
    ...overrides,
  });
}

function fakeQuorum(epochSigners = wallets, threshold = 2n) {
  const allowed = new Set(epochSigners.map((wallet) => wallet.address.toLowerCase()));
  return {
    signerEpoch: async () => 3n,
    epochThreshold: async (epoch) => epoch === 3n ? threshold : 0n,
    isEpochSigner: async (epoch, signer) => epoch === 3n && allowed.has(signer.toLowerCase()),
  };
}

describe("resolver quorum decision transport", () => {
  it("builds a deterministic self-hashed EIP-712 packet and challenge nonce", () => {
    const built = packet();
    assert.equal(validateResolverQuorumDecisionPacket(built), built);
    assert.equal(built.decision.nonce, deterministicResolverNonce(ethers.id("challenge")));
    assert.equal(built.decision.adapter, adapter.toLowerCase());
    assert.equal(built.decision.bondBeneficiary, adapter.toLowerCase());
    assert.equal(built.decision.transcriptURIHash, ethers.keccak256(ethers.toUtf8Bytes(built.transcript_uri)));
  });

  it("rejects packet drift, zero bindings, and extra fields", () => {
    const drifted = structuredClone(packet());
    drifted.decision.verdictHash = ethers.id("other");
    assert.throws(() => validateResolverQuorumDecisionPacket(drifted), /binding mismatch/);
    assert.throws(() => packet({ challengeInstanceHash: ethers.ZeroHash }), /nonzero bytes32/);
    const extra = { ...packet(), approval: true };
    assert.throws(() => validateResolverQuorumDecisionPacket(extra), /keys mismatch/);
  });

  it("recovers, epoch-checks, deduplicates, and sorts independent signatures", async () => {
    const decision = packet();
    const artifacts = await Promise.all([
      buildResolverQuorumSignatureArtifact(decision, wallets[1]),
      buildResolverQuorumSignatureArtifact(decision, wallets[0]),
    ]);
    const collected = await collectResolverQuorumSignatures({ packet: decision, artifacts, quorum: fakeQuorum() });
    assert.equal(collected.ready, true);
    assert.equal(collected.threshold, 2);
    assert.deepEqual(collected.signers, [...collected.signers].sort());
    assert.equal(collected.signatures.length, 2);
    const duplicate = await collectResolverQuorumSignatures({
      packet: decision,
      artifacts: [artifacts[0], artifacts[0], artifacts[1]],
      quorum: fakeQuorum(),
    });
    assert.equal(duplicate.ready, true);
    assert.match(duplicate.rejected[0].reason, /duplicate resolver quorum signer/);
  });

  it("waits below threshold and rejects nonmembers, stale epochs, and forged artifacts", async () => {
    const decision = packet();
    const one = await buildResolverQuorumSignatureArtifact(decision, wallets[0]);
    assert.equal((await collectResolverQuorumSignatures({ packet: decision, artifacts: [one], quorum: fakeQuorum() })).ready, false);
    const nonmember = await collectResolverQuorumSignatures({
      packet: decision,
      artifacts: [one],
      quorum: fakeQuorum([wallets[1], wallets[2]]),
    });
    assert.equal(nonmember.ready, false);
    assert.match(nonmember.rejected[0].reason, /not from an epoch signer/);
    const stale = { ...fakeQuorum(), signerEpoch: async () => 4n };
    await assert.rejects(collectResolverQuorumSignatures({ packet: decision, artifacts: [one], quorum: stale }), /epoch is stale/);
    const forged = { ...one, signer: wallets[1].address.toLowerCase() };
    forged.artifact_hash = one.artifact_hash;
    assert.throws(() => validateResolverQuorumSignatureArtifact(forged, decision), /signer mismatch/);
  });

  it("reaches threshold despite malformed, duplicate, and nonmember artifacts", async () => {
    const decision = packet();
    const valid = await Promise.all([
      buildResolverQuorumSignatureArtifact(decision, wallets[0]),
      buildResolverQuorumSignatureArtifact(decision, wallets[1]),
    ]);
    const outsider = await buildResolverQuorumSignatureArtifact(decision, ethers.Wallet.createRandom());
    const collected = await collectResolverQuorumSignatures({
      packet: decision,
      artifacts: [{ bad: true }, valid[0], valid[0], outsider, valid[1]],
      quorum: fakeQuorum(),
    });
    assert.equal(collected.ready, true);
    assert.equal(collected.signatures.length, 2);
    assert.equal(collected.rejected.length, 3);
  });
});
