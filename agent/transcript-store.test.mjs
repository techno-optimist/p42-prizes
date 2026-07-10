import assert from "node:assert/strict";
import test from "node:test";

import { sha256Canonical } from "./lib.mjs";
import {
  boundedFetchBytes,
  canonicalTranscriptArtifact,
  fetchTranscriptClientBytes,
  parseTranscriptUri,
  publishAndVerifyTranscript,
} from "./transcript-store.mjs";

function transcript() {
  const body = { schema_version: "p42-runner-transcript/v1", value: 7 };
  return { ...body, transcript_hash: sha256Canonical(body) };
}

test("canonical artifact has exactly one newline and a separate artifact digest", () => {
  const artifact = canonicalTranscriptArtifact(transcript());
  assert.equal(artifact.bytes.at(-1), 10);
  assert.notEqual(artifact.artifact_sha256, artifact.transcript_hash);
  assert.equal(artifact.bytes.toString().match(/\n/g)?.length, 1);
  assert.throws(() => canonicalTranscriptArtifact({ ...transcript(), value: 8 }), /self-hash mismatch/);
});

test("strict transcript URI parser accepts exact Arweave ids and CID paths only", () => {
  const txid = "a".repeat(43);
  assert.equal(parseTranscriptUri(`ar://${txid}`).identifier, txid);
  assert.equal(parseTranscriptUri("ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pte3dr2l7w4qv3q2x4x5b5ha/path/file.json").path, "/path/file.json");
  for (const uri of [
    `ar://${txid}/extra`, `ar://${"a".repeat(42)}`, `ar://${txid}?x=1`,
    "ipfs://user@bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pte3dr2l7w4qv3q2x4x5b5ha",
    "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pte3dr2l7w4qv3q2x4x5b5ha/a/../b",
  ]) assert.throws(() => parseTranscriptUri(uri));
});

test("publication requires a receipt and exact bytes from two independent endpoints", async () => {
  const value = transcript();
  const artifact = canonicalTranscriptArtifact(value);
  const uri = `ar://${"z".repeat(43)}`;
  const publisher = { publishTranscript: async () => ({ uri, artifact_sha256: artifact.artifact_sha256, length: artifact.length }) };
  const fetchClient = { fetchTranscript: async () => artifact.bytes };
  const result = await publishAndVerifyTranscript({
    transcript: value, publisher, fetchClient, endpoints: ["https://one.example", "https://two.example"],
  });
  assert.equal(result.status, "published");
  assert.equal(result.publication.uri, uri);
  assert.equal((await publishAndVerifyTranscript({ transcript: value })).status, "awaiting_publication");
  await assert.rejects(
    publishAndVerifyTranscript({ transcript: value, publisher, fetchClient, endpoints: ["https://one.example/a", "https://one.example/b"] }),
    /independent origins/,
  );
  await assert.rejects(
    publishAndVerifyTranscript({
      transcript: value, publisher,
      fetchClient: { fetchTranscript: async ({ endpoint }) => endpoint.includes("two") ? Buffer.from("bad\n") : artifact.bytes },
      endpoints: ["https://one.example", "https://two.example"],
    }),
    /non-canonical transcript bytes/,
  );
});

test("HTTP retrieval refuses redirects and oversized declared bodies", async () => {
  await assert.rejects(boundedFetchBytes("https://example.test/x", {
    fetchImpl: async (_url, options) => {
      assert.equal(options.redirect, "manual");
      return { status: 302, ok: false, headers: { get: () => null } };
    },
  }), /redirects are forbidden/);
  await assert.rejects(boundedFetchBytes("https://example.test/x", {
    fetchImpl: async () => ({ status: 200, ok: true, headers: { get: () => String(20 * 1024 * 1024) } }),
  }), /byte limit/);
});

test("injected retrieval clients are bounded too", async () => {
  await assert.rejects(fetchTranscriptClientBytes(
    { fetchTranscript: async () => Buffer.alloc(20) }, {}, { maxBytes: 10, timeoutMs: 50 },
  ), /byte limit/);
  await assert.rejects(fetchTranscriptClientBytes(
    { fetchTranscript: async () => new Promise(() => {}) }, {}, { timeoutMs: 5 },
  ), /timed out/);
});
