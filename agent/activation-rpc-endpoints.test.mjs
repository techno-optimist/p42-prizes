import assert from "node:assert/strict";
import { test } from "node:test";
import { ethers } from "ethers";

import {
  activationRpcFetchRequest,
  rejectActivationRpcRedirects,
} from "./activation-rpc-endpoints.mjs";

const CHAIN_ID = 84532;
const ENDPOINTS = Object.freeze({
  primary: "https://rpc-primary.example/",
  secondary: "https://rpc-secondary.example/",
});

function jsonRpcResponse(request) {
  const payload = JSON.parse(Buffer.from(request.body).toString("utf8"));
  const respond = ({ id }) => ({ jsonrpc: "2.0", id, result: ethers.toQuantity(CHAIN_ID) });
  return {
    statusCode: 200,
    statusMessage: "OK",
    headers: { "content-type": "application/json" },
    body: Buffer.from(JSON.stringify(Array.isArray(payload) ? payload.map(respond) : respond(payload))),
  };
}

function mockedProvider(url, responseForRequest) {
  const request = new ethers.FetchRequest(url);
  const wrappedGetUrlFunc = rejectActivationRpcRedirects(responseForRequest);
  request.getUrlFunc = wrappedGetUrlFunc;
  assert.equal(request.clone().getUrlFunc, wrappedGetUrlFunc);
  assert.equal(request.clone().clone().getUrlFunc, wrappedGetUrlFunc);
  return new ethers.JsonRpcProvider(request, CHAIN_ID, { staticNetwork: true });
}

test("production activation RPC requests retain their no-redirect transport across clones", () => {
  const request = activationRpcFetchRequest(ENDPOINTS.primary);
  assert.equal(request.clone().getUrlFunc, request.getUrlFunc);
  assert.equal(request.clone().clone().getUrlFunc, request.getUrlFunc);
});

for (const role of Object.keys(ENDPOINTS)) {
  for (const statusCode of [301, 302, 307, 308]) {
    for (const destinationKind of ["same", "distinct"]) {
      test(`${role} RPC rejects ${statusCode} redirect to ${destinationKind} destination before following it`, async () => {
        const source = ENDPOINTS[role];
        const destination = destinationKind === "same" ? source : "https://redirected.example/";
        const calls = [];
        const provider = mockedProvider(source, async (request) => {
          calls.push(request.url);
          if (request.url === source) {
            return {
              statusCode,
              statusMessage: "Redirect",
              headers: { location: destination },
              body: null,
            };
          }
          return jsonRpcResponse(request);
        });
        try {
          await assert.rejects(
            () => provider.send("eth_chainId", []),
            new RegExp(`redirects are forbidden \\(${statusCode}\\)`),
          );
          assert.deepEqual(calls, [source]);
        } finally {
          provider.destroy();
        }
      });
    }
  }
}

for (const role of Object.keys(ENDPOINTS)) {
  test(`${role} RPC accepts a direct canonical HTTPS 200 response`, async () => {
    const source = ENDPOINTS[role];
    const calls = [];
    const provider = mockedProvider(source, async (request) => {
      calls.push(request.url);
      return jsonRpcResponse(request);
    });
    try {
      assert.equal(await provider.send("eth_chainId", []), ethers.toQuantity(CHAIN_ID));
      assert.deepEqual(calls, [source]);
    } finally {
      provider.destroy();
    }
  });
}
