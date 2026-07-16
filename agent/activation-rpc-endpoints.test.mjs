import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, linkSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ethers } from "ethers";
import { createHash } from "node:crypto";

import {
  activationRpcFetchRequest,
  bindActivationRpcAuthority,
  canonicalActivationRpcEndpoint,
  loadActivationRpcOperatorRegistry,
  observeActivationRpcChainId,
  rejectActivationRpcRedirects,
  validateActivationRpcEndpointPair,
  validateActivationRpcOperatorRegistry,
} from "./activation-rpc-endpoints.mjs";
import { canonicalJson, sha256Canonical } from "./lib.mjs";

const CHAIN_ID = 84532;
const ENDPOINTS = Object.freeze({
  primary: "https://rpc-primary.example",
  secondary: "https://rpc-secondary.example",
});
const REGISTRY_DIGEST = `sha256:${"9".repeat(64)}`;
const MAX_DNS_HOST = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`;
const OVERLONG_DNS_HOST = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(62)}`;
const WHATWG_IPV4_ALIASES = Object.freeze([
  ["127.0.0.1", "127.0.0.1"], ["127.1", "127.0.0.1"], ["127.0.1", "127.0.0.1"],
  ["2130706433", "127.0.0.1"], ["0x7f000001", "127.0.0.1"], ["017700000001", "127.0.0.1"],
  ["0x7f.0.0.1", "127.0.0.1"], ["127.0x0.0.1", "127.0.0.1"], ["0177.0.0.1", "127.0.0.1"],
  ["127.0.65535", "127.0.255.255"], ["127.16777215", "127.255.255.255"],
  ["1.2.65535", "1.2.255.255"], ["0xffffffff", "255.255.255.255"],
  ["0300.0250.0001.0001", "192.168.1.1"],
]);
const SAFE_DNS_HOSTS = Object.freeze(["127.0.0.1.example", "0x7f.rpc.example", "127.0x0.0.1.example", "123.example"]);
const registry = () => validateActivationRpcOperatorRegistry({
  schema: "p42-activation-rpc-operator-registry/v1",
  profiles: [
    { operatorId: "operator-primary", endpointOrigin: "https://rpc-primary.example", endpointProfileDigest: sha256Canonical({ operatorId: "operator-primary", endpointOrigin: "https://rpc-primary.example" }) },
    { operatorId: "operator-secondary", endpointOrigin: "https://rpc-secondary.example", endpointProfileDigest: sha256Canonical({ operatorId: "operator-secondary", endpointOrigin: "https://rpc-secondary.example" }) },
  ],
}, REGISTRY_DIGEST);

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

test("raw eth_chainId is checked before a static-network provider can exist", async () => {
  let calls = 0;
  const transport = async () => {
    calls += 1;
    return { statusCode: 200, headers: { "content-type": "application/json" }, body: Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1" })) };
  };
  await assert.rejects(() => observeActivationRpcChainId(ENDPOINTS.primary, CHAIN_ID, transport), /raw eth_chainId mismatch/);
  assert.equal(calls, 1);
});

test("canonical origins reject normalization aliases and enforce port semantics", () => {
  for (const value of [
    "https://rpc.example/", "https://RPC.example", "https://rpc.example:443", "https://rpc.example:0",
    "https://rpc.example:65536", "https://rpc.example:99999", "https://rpc.example:01",
    "https://127.0.0.1", "https://2130706433", "https://0x7f000001", "https://0177.0.0.1",
    "https://%72pc.example", "https://user@rpc.example", "https://rpc.example?x=1",
    `https://${OVERLONG_DNS_HOST}`, `https://${"a".repeat(64)}.example`,
    `https://${Array(5).fill("a".repeat(63)).join(".")}`,
  ]) assert.throws(() => canonicalActivationRpcEndpoint(value), /canonical|port|ASCII|syntax/);
  assert.equal(canonicalActivationRpcEndpoint("https://rpc.example").port, 443);
  assert.equal(canonicalActivationRpcEndpoint("https://rpc.example:1").port, 1);
  assert.equal(canonicalActivationRpcEndpoint("https://rpc.example:65535").port, 65535);
  assert.equal(canonicalActivationRpcEndpoint(`https://${MAX_DNS_HOST}:65535`).origin.length, 267);
});

test("rejects the complete syntactic WHATWG IPv4 alias family before endpoint use or pair distinctness", () => {
  for (const [rawHost, normalizedHost] of WHATWG_IPV4_ALIASES) {
    assert.equal(new URL(`https://${rawHost}`).hostname, normalizedHost, rawHost);
    assert.throws(() => canonicalActivationRpcEndpoint(`https://${rawHost}`), /canonical/);
  }
  assert.throws(
    () => validateActivationRpcEndpointPair("https://0x7f.0.0.1", "https://127.0x0.0.1"),
    /canonical/,
  );
  for (const host of SAFE_DNS_HOSTS) {
    assert.equal(new URL(`https://${host}`).hostname, host);
    assert.equal(canonicalActivationRpcEndpoint(`https://${host}`).hostname, host);
  }
});

test("published registry schema has the same canonical port boundary", () => {
  const schema = JSON.parse(readFileSync(new URL("../schemas/activation-rpc-operator-registry.schema.json", import.meta.url), "utf8"));
  const pattern = new RegExp(schema.properties.profiles.items.properties.endpointOrigin.pattern);
  const accepts = (value) => value.length <= schema.properties.profiles.items.properties.endpointOrigin.maxLength && pattern.test(value);
  for (const value of ["https://rpc.example", "https://rpc.example:1", "https://rpc.example:65535", `https://${MAX_DNS_HOST}:65535`, ...SAFE_DNS_HOSTS.map((host) => `https://${host}`)]) {
    assert.equal(accepts(value), true, value);
  }
  for (const value of [
    "https://rpc.example:0", "https://rpc.example:01", "https://rpc.example:443",
    "https://rpc.example:65536", "https://rpc.example:99999", "https://127.0.0.1",
    "https://127.1", "https://0177.0.0.1", `https://${OVERLONG_DNS_HOST}`,
    `https://${"a".repeat(64)}.example`, `https://${Array(5).fill("a".repeat(63)).join(".")}`,
    ...WHATWG_IPV4_ALIASES.map(([host]) => `https://${host}`),
  ]) assert.equal(accepts(value), false, value);
});

test("protected registry loader requires immutable canonical bytes and trusted paths", () => {
  const registryValue = { schema: "p42-activation-rpc-operator-registry/v1", profiles: registry().profiles };
  const canonicalBytes = Buffer.from(`${canonicalJson(registryValue)}\n`);
  const make = ({ mode = 0o400, bytes = canonicalBytes } = {}) => {
    const root = mkdtempSync(join(tmpdir(), "p42-rpc-protected-")); chmodSync(root, 0o700);
    const path = join(root, "registry.json");
    writeFileSync(path, bytes); chmodSync(path, mode);
    return { root, path, digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}` };
  };
  for (const mode of [0o400, 0o444]) {
    const good = make({ mode });
    assert.equal(loadActivationRpcOperatorRegistry(good.path, good.digest, good.root).profiles.length, 2);
    assert.throws(() => loadActivationRpcOperatorRegistry(join(good.root, "missing.json"), good.digest, good.root));
  }
  const writableFile = make({ mode: 0o600 });
  assert.throws(() => loadActivationRpcOperatorRegistry(writableFile.path, writableFile.digest, writableFile.root), /unsafe/);
  for (const bytes of [
    Buffer.from(`${JSON.stringify(registryValue, null, 2)}\n`),
    Buffer.from(`${JSON.stringify(registryValue)}\n`),
    Buffer.from(canonicalJson(registryValue)),
    Buffer.from(`${canonicalJson(registryValue)}\n\n`),
    Buffer.from(`${canonicalJson(registryValue)} \n`),
  ]) {
    const noncanonical = make({ bytes });
    assert.throws(() => loadActivationRpcOperatorRegistry(noncanonical.path, noncanonical.digest, noncanonical.root), /canonical|trailing/);
  }
  const writable = make(); chmodSync(writable.root, 0o777);
  assert.throws(() => loadActivationRpcOperatorRegistry(writable.path, writable.digest, writable.root), /unsafe/);
  const hard = make(); linkSync(hard.path, join(hard.root, "alias.json"));
  assert.throws(() => loadActivationRpcOperatorRegistry(hard.path, hard.digest, hard.root), /unsafe/);
  const linked = make(); const symlink = join(linked.root, "link.json"); symlinkSync(linked.path, symlink);
  assert.throws(() => loadActivationRpcOperatorRegistry(symlink, linked.digest, linked.root));
  const substituted = make();
  assert.throws(() => loadActivationRpcOperatorRegistry(substituted.path, `sha256:${"0".repeat(64)}`, substituted.root), /digest/);
});

test("authorization-bound profiles reject same operators, endpoint substitution, and registry substitution", () => {
  assert.throws(
    () => bindActivationRpcAuthority(registry(), ENDPOINTS.primary, ENDPOINTS.secondary, "operator-primary", "operator-primary"),
    /distinct stable operator IDs/,
  );
  assert.throws(
    () => bindActivationRpcAuthority(registry(), "https://substitute.example/", ENDPOINTS.secondary, "operator-primary", "operator-secondary"),
    /canonical|does not match/,
  );
  const root = mkdtempSync(join(tmpdir(), "p42-rpc-registry-")); chmodSync(root, 0o700);
  const path = join(root, "registry.json");
  writeFileSync(path, `${canonicalJson({ schema: "p42-activation-rpc-operator-registry/v1", profiles: registry().profiles })}\n`);
  chmodSync(path, 0o400);
  assert.throws(() => loadActivationRpcOperatorRegistry(path, `sha256:${"8".repeat(64)}`, root), /digest does not match/);
  const substituted = { schema: "p42-activation-rpc-operator-registry/v1", profiles: registry().profiles.map((profile) => ({ ...profile })) };
  substituted.profiles[0].operatorId = "operator-substitute";
  assert.throws(() => validateActivationRpcOperatorRegistry(substituted, REGISTRY_DIGEST), /digest or origin/);
  assert.throws(
    () => bindActivationRpcAuthority(registry(), "https://rpc-primary.example.", ENDPOINTS.secondary, "operator-primary", "operator-secondary"),
    /canonical/,
  );
});

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
