import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";

import { arweaveTranscriptPublisher } from "./transcript-arweave.mjs";

const TXID = "t".repeat(43);
const BYTES = Buffer.from('{"answer":42}\n');
const SHA256 = `sha256:${createHash("sha256").update(BYTES).digest("hex")}`;
const METADATA = { artifact_sha256: SHA256, length: BYTES.length };
const OWNER = "w".repeat(43);
const createPublisher = (options) => arweaveTranscriptPublisher({
  owner: OWNER,
  confirmArweaveTransactionImpl: async (bytes, txid) => ({ cid: cidFor(bytes), txid }),
  ...options,
});
const cidFor = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

describe("Arweave transcript publisher", () => {
  it("recovers an existing CID without uploading again", async () => {
    let uploads = 0;
    const options = { graphqlEndpoint: "https://graphql.example" };
    const publisher = createPublisher({
      ...options,
      findTxidsByCidImpl: async (cid, received) => {
        assert.equal(cid, SHA256);
        assert.deepEqual(received, { owner: OWNER, ...options, limit: 10 });
        return [TXID];
      },
      fetchFromArweaveImpl: async () => BYTES,
      uploadToArweaveImpl: async () => { uploads += 1; },
    });

    assert.deepEqual(await publisher.publishTranscript(BYTES, METADATA), {
      uri: `ar://${TXID}`,
      artifact_sha256: SHA256,
      length: BYTES.length,
    });
    assert.equal(uploads, 0);
  });

  it("uploads only when the CID is absent", async () => {
    let uploaded;
    let prepared;
    const publisher = createPublisher({
      findTxidsByCidImpl: async () => [],
      uploadToArweaveImpl: async (bytes, options) => {
        uploaded = bytes;
        assert.equal(options.expectedOwner, OWNER);
        await options.onPrepared?.({ schema_version: "p42-arweave-signed-upload/v1", txid: TXID });
        await options.onPosted?.({ cid: SHA256, txid: TXID });
        return { cid: SHA256, txid: TXID, ignored: "not part of the receipt" };
      },
    });

    let accepted;
    const receipt = await publisher.publishTranscript(BYTES, {
      ...METADATA,
      onReceipt: async (value) => { accepted = value; },
      onPrepared: async (value) => { prepared = value; },
    });
    assert.deepEqual(uploaded, BYTES);
    assert.deepEqual(receipt, { uri: `ar://${TXID}`, artifact_sha256: SHA256, length: BYTES.length });
    assert.deepEqual(accepted, receipt);
    assert.equal(prepared.txid, TXID);
  });

  it("does not trust a CID tag whose transaction bytes do not match", async () => {
    let uploads = 0;
    const publisher = createPublisher({
      findTxidsByCidImpl: async () => [TXID],
      fetchFromArweaveImpl: async () => Buffer.from("poison"),
      uploadToArweaveImpl: async () => {
        uploads += 1;
        return { cid: SHA256, txid: "u".repeat(43) };
      },
    });
    assert.equal((await publisher.publishTranscript(BYTES, METADATA)).uri, `ar://${"u".repeat(43)}`);
    assert.equal(uploads, 1);
  });

  it("searches older candidates when the newest CID tag is poisoned", async () => {
    const older = "o".repeat(43);
    const publisher = createPublisher({
      findTxidsByCidImpl: async () => [TXID, older],
      fetchFromArweaveImpl: async (txid) => txid === older ? BYTES : Buffer.from("poison"),
      uploadToArweaveImpl: async () => { throw new Error("must recover older valid transaction"); },
    });
    assert.equal((await publisher.publishTranscript(BYTES, METADATA)).uri, `ar://${older}`);
  });

  it("fails closed on transient recovery errors instead of duplicating an upload", async () => {
    let uploads = 0;
    const publisher = createPublisher({
      findTxidsByCidImpl: async () => [TXID],
      fetchFromArweaveImpl: async () => { throw new Error("gateway unavailable"); },
      uploadToArweaveImpl: async () => { uploads += 1; },
    });
    await assert.rejects(publisher.publishTranscript(BYTES, METADATA), /not yet retrievable/);
    assert.equal(uploads, 0);
  });

  it("reconfirms an accepted receipt before resolver signing", async () => {
    let confirmations = 0;
    const publisher = createPublisher({
      confirmArweaveTransactionImpl: async (bytes, txid) => {
        confirmations += 1;
        return { cid: cidFor(bytes), txid };
      },
    });
    const receipt = { uri: `ar://${TXID}`, artifact_sha256: SHA256, length: BYTES.length };
    assert.equal((await publisher.confirmReceipt(BYTES, receipt)).txid, TXID);
    assert.equal(confirmations, 1);
    await assert.rejects(
      publisher.confirmReceipt(BYTES, { ...receipt, uri: "ar://short" }),
      /invalid Arweave transaction id/,
    );
  });

  it("reposts a journaled signed transaction without a CID lookup", async () => {
    const preparedTransaction = { schema_version: "p42-arweave-signed-upload/v1", txid: TXID };
    let observed;
    const publisher = createPublisher({
      findTxidsByCidImpl: async () => { throw new Error("must not query before repost"); },
      uploadToArweaveImpl: async (_bytes, options) => {
        observed = options.preparedTransaction;
        return { cid: SHA256, txid: TXID };
      },
    });
    const receipt = await publisher.publishTranscript(BYTES, { ...METADATA, preparedTransaction });
    assert.equal(receipt.uri, `ar://${TXID}`);
    assert.equal(observed, preparedTransaction);
  });

  it("rejects digest and length metadata mismatches before lookup", async () => {
    let lookups = 0;
    const publisher = createPublisher({
      findTxidsByCidImpl: async () => { lookups += 1; return [TXID]; },
    });

    await assert.rejects(
      () => publisher.publishTranscript(BYTES, { ...METADATA, artifact_sha256: `sha256:${"0".repeat(64)}` }),
      /artifact_sha256 metadata mismatch/,
    );
    await assert.rejects(
      () => publisher.publishTranscript(BYTES, { ...METADATA, length: BYTES.length + 1 }),
      /length metadata mismatch/,
    );
    await assert.rejects(
      () => publisher.publishTranscript(BYTES, { ...METADATA, length: "14" }),
      /non-negative safe integer/,
    );
    assert.equal(lookups, 0);
  });

  it("rejects malformed lookup and upload results", async () => {
    for (const found of [undefined, false, {}, "short"]) {
      const publisher = createPublisher({
        findTxidsByCidImpl: async () => [found],
        fetchFromArweaveImpl: async () => BYTES,
      });
      await assert.rejects(() => publisher.publishTranscript(BYTES, METADATA), /invalid Arweave transaction id/);
    }

    for (const uploaded of [undefined, [], { cid: SHA256, txid: "short" }, { cid: `sha256:${"0".repeat(64)}`, txid: TXID }]) {
      const publisher = createPublisher({
        findTxidsByCidImpl: async () => [],
        uploadToArweaveImpl: async () => uploaded,
      });
      await assert.rejects(
        () => publisher.publishTranscript(BYTES, METADATA),
        /malformed result|invalid Arweave transaction id|mismatched CID/,
      );
    }
  });
});
