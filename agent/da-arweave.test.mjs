import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  cidOf,
  daHashForTxid,
  findTxidByCid,
  uploadToArweave,
} from "./da-arweave.mjs";

const TXID = "a".repeat(43);
const BYTES = Buffer.from('{"answer":"42"}');

function response(body, { status = 200, json = false } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    arrayBuffer: async () => Buffer.from(body),
    json: async () => json ? body : JSON.parse(String(body)),
  };
}

describe("Arweave permanent DA", () => {
  it("uses the exact SHA-256 content anchor", () => {
    assert.match(cidOf(BYTES), /^sha256:[0-9a-f]{64}$/);
    assert.match(daHashForTxid(TXID), /^0x[0-9a-f]{64}$/);
  });

  it("uses GraphQL variables and rejects malformed solver-controlled CIDs", async () => {
    const cid = cidOf(BYTES);
    let request;
    const found = await findTxidByCid(cid, {
      fetchImpl: async (_url, options) => {
        request = JSON.parse(options.body);
        return response({ data: { transactions: { edges: [{ node: { id: TXID } }] } } }, { json: true });
      },
    });
    assert.equal(found, TXID);
    assert.equal(request.variables.cid, cid);
    assert.doesNotMatch(request.query, new RegExp(cid));
    await assert.rejects(() => findTxidByCid('sha256:"}] } mutation { x', { fetchImpl: async () => null }), /CID must/);
  });

  it("fails closed without a funded wallet", async () => {
    const previous = process.env.ARWEAVE_JWK_JSON;
    delete process.env.ARWEAVE_JWK_JSON;
    try {
      await assert.rejects(() => uploadToArweave(BYTES, {
        arweaveClient: { createTransaction: async () => { throw new Error("should not run"); } },
        gateways: ["https://one.example", "https://two.example"],
        maxAttempts: 1,
      }), /ARWEAVE_JWK_JSON/);
    } finally {
      if (previous === undefined) delete process.env.ARWEAVE_JWK_JSON;
      else process.env.ARWEAVE_JWK_JSON = previous;
    }
  });

  it("requires confirmation and byte-identical retrieval from two gateways", async () => {
    const tags = [];
    const transaction = { id: TXID, addTag: (name, value) => tags.push([name, value]) };
    const client = {
      createTransaction: async ({ data }, wallet) => {
        assert.deepEqual(Buffer.from(data), BYTES);
        assert.equal(wallet.kty, "RSA");
        return transaction;
      },
      transactions: {
        sign: async (tx, wallet) => {
          assert.equal(tx, transaction);
          assert.equal(wallet.kty, "RSA");
        },
        post: async () => ({ status: 200 }),
        getStatus: async () => ({ status: 200, confirmed: { number_of_confirmations: 2 } }),
      },
    };
    const seen = [];
    const receipt = await uploadToArweave(BYTES, {
      wallet: { kty: "RSA" },
      arweaveClient: client,
      gateways: ["https://one.example", "https://two.example"],
      fetchImpl: async (url) => {
        seen.push(url);
        return response(BYTES);
      },
      maxAttempts: 1,
    });
    assert.equal(receipt.cid, cidOf(BYTES));
    assert.equal(receipt.confirmations, 2);
    assert.deepEqual(receipt.replicatedBy, ["one.example", "two.example"]);
    assert.equal(seen.length, 2);
    assert.deepEqual(tags, [
      ["P42-CID", cidOf(BYTES)],
      ["App-Name", "P42-Prizes"],
      ["Content-Type", "application/json"],
    ]);
  });

  it("rejects a mismatched second gateway instead of declaring DA ready", async () => {
    const transaction = { id: TXID, addTag: () => {} };
    const client = {
      createTransaction: async () => transaction,
      transactions: {
        sign: async () => {},
        post: async () => ({ status: 200 }),
        getStatus: async () => ({ status: 200, confirmed: { number_of_confirmations: 1 } }),
      },
    };
    await assert.rejects(() => uploadToArweave(BYTES, {
      wallet: { kty: "RSA" },
      arweaveClient: client,
      gateways: ["https://one.example", "https://two.example"],
      fetchImpl: async (url) => response(url.includes("one") ? BYTES : Buffer.from("tampered")),
      maxAttempts: 1,
    }), /lacks two-gateway replication/);
  });
});
