import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  cidOf,
  daHashForTxid,
  findTxidByCid,
  findTxidsByCid,
  uploadToArweave,
} from "./da-arweave.mjs";

const TXID = "a".repeat(43);
const BYTES = Buffer.from('{"answer":"42"}');

function response(body, { status = 200, json = false } = {}) {
  const bytes = Buffer.from(json ? JSON.stringify(body) : String(body));
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => String(bytes.length) },
    body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }),
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

  it("binds the funded JWK to the configured publication owner", async () => {
    let created = 0;
    const client = {
      wallets: { jwkToAddress: async () => "a".repeat(43) },
      createTransaction: async () => { created += 1; },
    };
    await assert.rejects(uploadToArweave(BYTES, {
      wallet: { kty: "RSA" },
      expectedOwner: "b".repeat(43),
      arweaveClient: client,
      gateways: ["https://one.example", "https://two.example"],
      maxAttempts: 1,
    }), /does not match P42_ARWEAVE_OWNER/);
    assert.equal(created, 0);
  });

  it("strictly parses wallet and bounded GraphQL JSON", async () => {
    const previous = process.env.ARWEAVE_JWK_JSON;
    process.env.ARWEAVE_JWK_JSON = '{"kty":"RSA","kty":"forged"}';
    try {
      await assert.rejects(() => uploadToArweave(BYTES, {
        arweaveClient: { createTransaction: async () => { throw new Error("should not run"); } },
        gateways: ["https://one.example", "https://two.example"],
        maxAttempts: 1,
      }), /duplicate object key/);
    } finally {
      if (previous === undefined) delete process.env.ARWEAVE_JWK_JSON;
      else process.env.ARWEAVE_JWK_JSON = previous;
    }

    const cid = cidOf(BYTES);
    await assert.rejects(() => findTxidByCid(cid, {
      fetchImpl: async () => response('{"data":{},"data":{"transactions":{"edges":[]}}}'),
    }), /duplicate object key/);
  });

  it("requires confirmation and byte-identical retrieval from two gateways", async () => {
    const tags = [];
    const transaction = {
      id: TXID,
      addTag: (name, value) => tags.push([name, value]),
      toJSON: () => ({ id: TXID, data: BYTES.toString("base64") }),
    };
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
    const lifecycle = [];
    const receipt = await uploadToArweave(BYTES, {
      wallet: { kty: "RSA" },
      arweaveClient: client,
      gateways: ["https://one.example", "https://two.example"],
      fetchImpl: async (url) => {
        seen.push(url);
        return response(BYTES);
      },
      maxAttempts: 1,
      onPosted: async ({ cid, txid }) => lifecycle.push([cid, txid]),
    });
    assert.equal(receipt.cid, cidOf(BYTES));
    assert.equal(receipt.confirmations, 2);
    assert.deepEqual(receipt.replicatedBy, ["one.example", "two.example"]);
    assert.equal(seen.length, 2);
    assert.deepEqual(lifecycle, [[cidOf(BYTES), TXID]]);
    assert.deepEqual(tags, [
      ["P42-CID", cidOf(BYTES)],
      ["App-Name", "P42-Prizes"],
      ["Content-Type", "application/json"],
    ]);
  });

  it("returns multiple CID candidates and bounds a hung GraphQL request", async () => {
    const cid = cidOf(BYTES);
    const second = "b".repeat(43);
    const owner = "w".repeat(43);
    let request;
    assert.deepEqual(await findTxidsByCid(cid, {
      owner,
      fetchImpl: async (_url, options) => {
        request = JSON.parse(options.body);
        return response({
          data: { transactions: { edges: [{ node: { id: TXID } }, { node: { id: second } }] } },
        }, { json: true });
      },
    }), [TXID, second]);
    assert.equal(request.variables.owner, owner);
    assert.match(request.query, /owners: \[\$owner\]/);

    await assert.rejects(findTxidsByCid(cid, {
      networkTimeoutMs: 5,
      fetchImpl: async (_url, { signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      }),
    }), /timed out/);
  });

  it("journals signed bytes before POST and resumes the same transaction id", async () => {
    let prepared;
    let posts = 0;
    const transaction = {
      id: TXID,
      data: BYTES,
      owner: "owner-key",
      addTag: () => {},
      toJSON: () => ({ id: TXID, owner: "owner-key", data: BYTES.toString("base64") }),
    };
    const client = {
      createTransaction: async () => transaction,
      transactions: {
        sign: async () => {},
        fromRaw: () => transaction,
        post: async () => {
          posts += 1;
          if (posts === 1) throw new Error("response lost after acceptance");
          return { status: 208 };
        },
        getStatus: async () => ({ status: 200, confirmed: { number_of_confirmations: 1 } }),
      },
    };
    const options = {
      wallet: { kty: "RSA" },
      arweaveClient: client,
      gateways: ["https://one.example", "https://two.example"],
      fetchImpl: async () => response(BYTES),
      maxAttempts: 1,
      onPrepared: async (value) => { prepared = value; },
    };
    await assert.rejects(uploadToArweave(BYTES, options), /response lost/);
    assert.equal(prepared.txid, TXID);
    const resumed = await uploadToArweave(BYTES, { ...options, preparedTransaction: prepared });
    assert.equal(resumed.txid, TXID);
    assert.equal(posts, 2);
  });

  it("rejects a mismatched second gateway instead of declaring DA ready", async () => {
    const transaction = {
      id: TXID,
      addTag: () => {},
      toJSON: () => ({ id: TXID, data: BYTES.toString("base64") }),
    };
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
