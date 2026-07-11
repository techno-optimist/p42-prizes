import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BASE_SEPOLIA_FINALITY_POLICY, collectFinalityAnchor, recheckFinalityAnchor } from "../scripts/finality-anchor.js";

const hash = (n) => `0x${n.toString(16).padStart(64, "0")}`;
const point = (n) => ({ number: `0x${n.toString(16)}`, hash: hash(n) });
const status = (finalized = 100, origin = 80, l1 = 90) => ({ finalized_l2: { ...point(finalized), l1origin: point(origin) }, finalized_l1: point(l1) });
function provider({ finalized = 100, safe = 105, sync = status(), historicalHashes = {}, missingTag = null } = {}) {
  return { async send(method, params) {
    if (method === "eth_chainId") return "0x14a34";
    if (method === "optimism_syncStatus") return sync;
    if (method === "eth_getBlockByNumber") {
      if (params[0] === "finalized") return missingTag === "finalized" ? null : point(finalized);
      if (params[0] === "safe") return missingTag === "safe" ? null : point(safe);
      const number = Number(BigInt(params[0]));
      return { ...point(number), hash: historicalHashes[number] ?? hash(number) };
    }
    throw new Error(`unexpected ${method}`);
  } };
}
const endpoints = (a = provider(), b = provider(), overrides = {}) => [
  { operatorId: "operator-a", url: "https://rpc-a.example/v1", provider: a, ...overrides.primary },
  { operatorId: "operator-b", url: "https://rpc-b.example/v1", provider: b, ...overrides.secondary },
];

describe("Base Sepolia finalized anchor", () => {
  it("binds agreed finalized/safe L2 and finalized L1-origin evidence", async () => {
    const anchor = await collectFinalityAnchor({ endpoints: endpoints(), policy: BASE_SEPOLIA_FINALITY_POLICY });
    assert.equal(anchor.l2.finalized.number, 100); assert.equal(anchor.l1.origin.number, 80);
    assert.equal(anchor.rpcEvidence.primaryOrigin, "https://rpc-a.example");
    assert.equal(anchor.rpcEvidence.secondaryHost, "rpc-b.example");
  });
  it("rejects policy mutation and downgrade", async () => {
    await assert.rejects(() => collectFinalityAnchor({ endpoints: endpoints(), policy: { ...BASE_SEPOLIA_FINALITY_POLICY, finalizedTag: "latest" } }), /immutable release policy/);
    const previous = await collectFinalityAnchor({ endpoints: endpoints(), policy: BASE_SEPOLIA_FINALITY_POLICY });
    await assert.rejects(() => recheckFinalityAnchor({ endpoints: endpoints(provider({ finalized: 99, sync: status(99) }), provider({ finalized: 99, sync: status(99) })), policy: BASE_SEPOLIA_FINALITY_POLICY, previous }), /downgraded/);
  });
  it("keeps safe/latest-style divergence distinct from finalized", async () => {
    const anchor = await collectFinalityAnchor({ endpoints: endpoints(provider({ safe: 400 }), provider({ safe: 400 })), policy: BASE_SEPOLIA_FINALITY_POLICY });
    assert.equal(anchor.l2.finalized.number, 100); assert.equal(anchor.l2.safe.number, 400);
  });
  it("fails closed for unavailable tags or L1 evidence", async () => {
    await assert.rejects(() => collectFinalityAnchor({ endpoints: endpoints(provider({ missingTag: "finalized" }), provider()), policy: BASE_SEPOLIA_FINALITY_POLICY }), /unavailable/);
    await assert.rejects(() => collectFinalityAnchor({ endpoints: endpoints(provider({ sync: {} }), provider({ sync: {} })), policy: BASE_SEPOLIA_FINALITY_POLICY }), /lacks finalized_l2/);
  });
  it("rejects cross-RPC disagreement and reorg", async () => {
    await assert.rejects(() => collectFinalityAnchor({ endpoints: endpoints(provider(), provider({ finalized: 101, sync: status(101) })), policy: BASE_SEPOLIA_FINALITY_POLICY }), /disagree/);
    const previous = await collectFinalityAnchor({ endpoints: endpoints(), policy: BASE_SEPOLIA_FINALITY_POLICY });
    await assert.rejects(() => recheckFinalityAnchor({ endpoints: endpoints(provider({ historicalHashes: { 100: hash(999) } }), provider()), policy: BASE_SEPOLIA_FINALITY_POLICY, previous }), /reorged/);
  });
  it("rejects same provider, endpoint, origin, host, or operator identities", async () => {
    const shared = provider();
    await assert.rejects(() => collectFinalityAnchor({ endpoints: endpoints(shared, shared), policy: BASE_SEPOLIA_FINALITY_POLICY }), /distinct objects/);
    await assert.rejects(() => collectFinalityAnchor({ endpoints: endpoints(provider(), provider(), { secondary: { url: "https://rpc-a.example/v1" } }), policy: BASE_SEPOLIA_FINALITY_POLICY }), /distinct endpoint/);
    await assert.rejects(() => collectFinalityAnchor({ endpoints: endpoints(provider(), provider(), { secondary: { url: "https://rpc-a.example/other" } }), policy: BASE_SEPOLIA_FINALITY_POLICY }), /distinct endpoint/);
    await assert.rejects(() => collectFinalityAnchor({ endpoints: endpoints(provider(), provider(), { secondary: { url: "https://RPC-A.EXAMPLE:443/other" } }), policy: BASE_SEPOLIA_FINALITY_POLICY }), /distinct endpoint/);
    await assert.rejects(() => collectFinalityAnchor({ endpoints: endpoints(provider(), provider(), { secondary: { operatorId: "operator-a" } }), policy: BASE_SEPOLIA_FINALITY_POLICY }), /distinct endpoint/);
  });
  it("rejects regression or same-height hash mutation in every dimension", async () => {
    const previous = await collectFinalityAnchor({ endpoints: endpoints(), policy: BASE_SEPOLIA_FINALITY_POLICY });
    const cases = [
      ["l2.safe", { safe: 104 }],
      ["l1.origin", { sync: status(100, 79, 90) }],
      ["l1.finalized", { sync: status(100, 80, 89) }],
      ["l1.origin", { sync: { ...status(), finalized_l2: { ...status().finalized_l2, l1origin: { ...point(80), hash: hash(999) } } } }],
      ["l1.finalized", { sync: { ...status(), finalized_l1: { ...point(90), hash: hash(999) } } }],
    ];
    for (const [label, options] of cases) {
      await assert.rejects(() => recheckFinalityAnchor({ endpoints: endpoints(provider(options), provider(options)), policy: BASE_SEPOLIA_FINALITY_POLICY, previous }), new RegExp(label.replace(".", "\\.")));
    }
  });
});
