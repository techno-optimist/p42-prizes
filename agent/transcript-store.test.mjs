import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";

import { canonicalJson, sha256Canonical } from "./lib.mjs";
import {
  boundedFetchBytes,
  canonicalTranscriptArtifact,
  configuredTranscriptEndpoints,
  fetchTranscriptClientBytes,
  httpTranscriptFetchClient,
  parseTranscriptUri,
  pinnedHttpsFetchBytes,
  publishAndVerifyTranscript,
  receiptSpoolPublisher,
  validatePublicationReceipt,
  validateRetrievalEndpoints,
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
  assert.equal(parseTranscriptUri("ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pte3dr2l7w4qv3q2x4x5b5ha/a%20b").path, "/a%20b");
  for (const uri of [
    `ar://${txid}/extra`, `ar://${"a".repeat(42)}`, `ar://${txid}?x=1`,
    "ipfs://user@bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pte3dr2l7w4qv3q2x4x5b5ha",
    "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pte3dr2l7w4qv3q2x4x5b5ha/a/../b",
    "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pte3dr2l7w4qv3q2x4x5b5ha/a b",
    "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3pte3dr2l7w4qv3q2x4x5b5ha/%61",
  ]) assert.throws(() => parseTranscriptUri(uri));
});

test("publication requires a receipt and exact bytes from two independent endpoints", async () => {
  const value = transcript();
  const artifact = canonicalTranscriptArtifact(value);
  const uri = `ar://${"z".repeat(43)}`;
  const publisher = { publishTranscript: async () => ({ uri, artifact_sha256: artifact.artifact_sha256, length: artifact.length }) };
  const fetchClient = { fetchTranscript: async () => artifact.bytes };
  const result = await publishAndVerifyTranscript({
    transcript: value, publisher, fetchClient, endpoints: ["https://one.example", "https://two.test"],
  });
  assert.equal(result.status, "published");
  assert.equal(result.publication.uri, uri);
  assert.equal((await publishAndVerifyTranscript({ transcript: value })).status, "awaiting_publication");
  await assert.rejects(
    publishAndVerifyTranscript({ transcript: value, publisher, fetchClient, endpoints: ["https://a.one.example", "https://b.one.example"] }),
    /independently operated sites/,
  );
  await assert.rejects(
    publishAndVerifyTranscript({
      transcript: value, publisher,
      fetchClient: { fetchTranscript: async ({ endpoint }) => endpoint.includes("two") ? Buffer.from("bad\n") : artifact.bytes },
      endpoints: ["https://one.example", "https://two.test"],
    }),
    /non-canonical transcript bytes/,
  );
});

test("publication receipts have an exact crash-journal shape", () => {
  const artifact = canonicalTranscriptArtifact(transcript());
  const receipt = {
    uri: `ar://${"j".repeat(43)}`,
    artifact_sha256: artifact.artifact_sha256,
    length: artifact.length,
  };
  assert.deepEqual(validatePublicationReceipt({ artifact, receipt }).receipt, receipt);
  assert.throws(
    () => validatePublicationReceipt({ artifact, receipt: { ...receipt, endpoint: "https://attacker.example" } }),
    /keys must be exactly/,
  );
});

test("trusted endpoints reject SSRF targets and ignore receipt endpoint injection", async () => {
  for (const endpoints of [
    ["http://public.example", "https://other.test"],
    ["https://localhost", "https://other.test"],
    ["https://127.0.0.1", "https://other.test"],
    ["https://169.254.1.2", "https://other.test"],
    ["https://[::ffff:127.0.0.1]", "https://other.test"],
    ["https://[::ffff:7f00:1]", "https://other.test"],
    ["https://[::ffff:0a00:1]", "https://other.test"],
    ["https://service.local", "https://other.test"],
  ]) assert.throws(() => validateRetrievalEndpoints(endpoints));
  assert.deepEqual(
    configuredTranscriptEndpoints(["--transcript-endpoint", "https://one.example", "--transcript-endpoint", "https://two.test"], {}),
    ["https://one.example", "https://two.test"],
  );
  const artifact = canonicalTranscriptArtifact(transcript());
  const receipt = {
    uri: `ar://${"z".repeat(43)}`, artifact_sha256: artifact.artifact_sha256, length: artifact.length,
  };
  await assert.rejects(publishAndVerifyTranscript({
    transcript: transcript(),
    publisher: { publishTranscript: async () => receipt },
    fetchClient: { fetchTranscript: async () => artifact.bytes },
  }), /trusted retrieval endpoints are required/);
  const dnsGuarded = httpTranscriptFetchClient(
    async () => { throw new Error("fetch must not run"); },
    async () => [{ address: "10.0.0.4", family: 4 }],
  );
  await assert.rejects(dnsGuarded.fetchTranscript({
    endpoint: "https://public.example", uri: `ar://${"a".repeat(43)}`,
  }), /DNS resolved to private/);
});

test("HTTPS retrieval pins the validated DNS address and keeps hostname SNI", async () => {
  let options;
  const requestImpl = (_target, requestOptions, callback) => {
    options = requestOptions;
    const request = new EventEmitter();
    request.setTimeout = () => {};
    request.end = () => {
      const response = new PassThrough();
      response.statusCode = 200;
      response.headers = {};
      callback(response);
      response.end("bound");
    };
    request.destroy = (error) => request.emit("error", error);
    return request;
  };
  const bytes = await pinnedHttpsFetchBytes("https://gateway.example/object", {
    addresses: [{ address: "8.8.8.8", family: 4 }], requestImpl,
  });
  assert.equal(bytes.toString(), "bound");
  assert.equal(options.servername, "gateway.example");
  await new Promise((resolveLookup, rejectLookup) => options.lookup("gateway.example", {}, (error, address) => {
    if (error) rejectLookup(error);
    else { assert.equal(address, "8.8.8.8"); resolveLookup(); }
  }));
  const unpinned = httpTranscriptFetchClient(async () => {}, async () => [{ address: "8.8.8.8", family: 4 }]);
  await assert.rejects(unpinned.fetchTranscript({
    endpoint: "https://gateway.example", uri: `ar://${"a".repeat(43)}`,
  }), /cannot guarantee DNS address pinning/);
});

test("receipt spool provides a real prepublished production adapter", async () => {
  const value = transcript();
  const artifact = canonicalTranscriptArtifact(value);
  const dir = mkdtempSync(join(tmpdir(), "p42-receipts-"));
  const receipt = { uri: `ar://${"r".repeat(43)}`, artifact_sha256: artifact.artifact_sha256, length: artifact.length };
  writeFileSync(join(dir, `${value.transcript_hash.slice(7)}.json`), `${canonicalJson(receipt)}\n`);
  assert.deepEqual(await receiptSpoolPublisher(dir).publishTranscript(artifact.bytes, artifact), receipt);
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

test("streaming HTTP retrieval aborts at maxBytes plus one without arrayBuffer allocation", async () => {
  let cancelled = false;
  let signal;
  const body = new ReadableStream({
    pull(controller) {
      controller.enqueue(new Uint8Array(6));
      controller.enqueue(new Uint8Array(5));
    },
    cancel() { cancelled = true; },
  });
  await assert.rejects(boundedFetchBytes("https://public.example/x", {
    maxBytes: 10,
    fetchImpl: async (_url, options) => {
      signal = options.signal;
      return { status: 200, ok: true, headers: { get: () => null }, body };
    },
  }), /byte limit/);
  assert.equal(cancelled, true);
  assert.equal(signal.aborted, true);
});
