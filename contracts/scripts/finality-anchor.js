import { buildTrustedRpcEvidence } from "./signed-deployment-journal.js";

export const BASE_SEPOLIA_FINALITY_POLICY = Object.freeze({
  schema: "p42-prizes/base-sepolia-finality-policy/v1",
  chainId: 84532,
  finalizedTag: "finalized",
  safeTag: "safe",
  l1EvidenceMethod: "optimism_syncStatus",
  rpcQuorum: 2,
});

const HASH = /^0x[0-9a-fA-F]{64}$/;

function quantity(value, label) {
  if (typeof value !== "string" || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value)) {
    throw new Error(`${label} is not a canonical RPC quantity`);
  }
  const number = Number(BigInt(value));
  if (!Number.isSafeInteger(number)) throw new Error(`${label} is outside the safe integer range`);
  return number;
}

function block(value, label) {
  if (!value || !HASH.test(String(value.hash)) || value.number == null) {
    throw new Error(`${label} tag is unavailable or lacks canonical block evidence`);
  }
  return { number: quantity(value.number, `${label}.number`), hash: value.hash.toLowerCase() };
}

function syncPoint(value, label) {
  if (!value || !HASH.test(String(value.hash)) || value.number == null) {
    throw new Error(`optimism_syncStatus lacks ${label} evidence`);
  }
  return { number: quantity(value.number, `${label}.number`), hash: value.hash.toLowerCase() };
}

export function assertProductionFinalityPolicy(policy) {
  if (JSON.stringify(policy) !== JSON.stringify(BASE_SEPOLIA_FINALITY_POLICY)) {
    throw new Error("production finality policy differs from the immutable release policy");
  }
  return policy;
}

async function observation(endpoint, policy) {
  const [chainId, finalizedValue, safeValue, status] = await Promise.all([
    endpoint.provider.send("eth_chainId", []),
    endpoint.provider.send("eth_getBlockByNumber", [policy.finalizedTag, false]),
    endpoint.provider.send("eth_getBlockByNumber", [policy.safeTag, false]),
    endpoint.provider.send(policy.l1EvidenceMethod, []),
  ]);
  if (quantity(chainId, `${endpoint.operatorId}.chainId`) !== policy.chainId) throw new Error(`${endpoint.operatorId} is not Base Sepolia`);
  const finalized = block(finalizedValue, `${endpoint.operatorId}.finalized`);
  const safe = block(safeValue, `${endpoint.operatorId}.safe`);
  const finalizedL2 = syncPoint(status?.finalized_l2, "finalized_l2");
  const finalizedL1 = syncPoint(status?.finalized_l1, "finalized_l1");
  const origin = syncPoint(status?.finalized_l2?.l1origin, "finalized_l2.l1origin");
  if (finalized.number !== finalizedL2.number || finalized.hash !== finalizedL2.hash) throw new Error(`${endpoint.operatorId} finalized tag disagrees with optimism_syncStatus`);
  if (safe.number < finalized.number) throw new Error(`${endpoint.operatorId} safe anchor is behind finalized`);
  if (origin.number > finalizedL1.number) throw new Error(`${endpoint.operatorId} finalized L2 origin is not finalized on L1`);
  return { operatorId: endpoint.operatorId, finalized, safe, l1Origin: origin, finalizedL1 };
}

function agreed(observations, rpcEvidence) {
  const [first, second] = observations;
  for (const field of ["finalized", "safe", "l1Origin", "finalizedL1"]) {
    if (first[field].number !== second[field].number || first[field].hash !== second[field].hash) {
      throw new Error(`operator-distinct RPCs disagree on ${field} anchor`);
    }
  }
  return {
    schema: "p42-prizes/base-sepolia-finality-anchor/v1",
    checkedAt: new Date().toISOString(),
    l2: { finalized: first.finalized, safe: first.safe },
    l1: { origin: first.l1Origin, finalized: first.finalizedL1 },
    operators: observations.map(({ operatorId }) => operatorId),
    rpcEvidence,
  };
}

export async function collectFinalityAnchor({ endpoints, policy }) {
  assertProductionFinalityPolicy(policy);
  if (!Array.isArray(endpoints) || endpoints.length !== 2 || !endpoints.every((item) => item?.provider && item?.operatorId && item?.url)) throw new Error("exactly two configured RPC endpoints are required");
  if (endpoints[0].provider === endpoints[1].provider) throw new Error("finality RPC providers must be distinct objects");
  const rpcEvidence = buildTrustedRpcEvidence({ primaryUrl: endpoints[0].url, secondaryUrl: endpoints[1].url, primaryOperatorId: endpoints[0].operatorId, secondaryOperatorId: endpoints[1].operatorId });
  return agreed(await Promise.all(endpoints.map((endpoint) => observation(endpoint, policy))), rpcEvidence);
}

export async function collectCanonicalFinalizedBlockEvidence({ endpoints, anchor }) {
  if (!Array.isArray(endpoints) || endpoints.length !== 2 || endpoints[0].provider === endpoints[1].provider) throw new Error("completion block evidence requires two distinct RPC providers");
  const point = anchor?.l2?.finalized;
  if (!Number.isSafeInteger(point?.number) || !HASH.test(String(point?.hash))) throw new Error("completion block evidence requires a finalized anchor");
  const tag = `0x${point.number.toString(16)}`;
  const rows = await Promise.all(endpoints.map(async (endpoint) => {
    const value = await endpoint.provider.send("eth_getBlockByNumber", [tag, false]);
    const parsed = block(value, `${endpoint.operatorId}.completionBlock`);
    const timestamp = quantity(value.timestamp, `${endpoint.operatorId}.completionBlock.timestamp`);
    return { operatorId: endpoint.operatorId, ...parsed, timestamp };
  }));
  if (rows.some((row) => row.number !== point.number || row.hash !== point.hash.toLowerCase())) throw new Error("completion block is not canonical at the finalized anchor on both RPCs");
  if (rows[0].timestamp !== rows[1].timestamp) throw new Error("operator-distinct RPCs disagree on completion block timestamp");
  return { blockNumber: point.number, blockHash: point.hash.toLowerCase(), timestamp: rows[0].timestamp, primaryOperatorId: rows[0].operatorId, secondaryOperatorId: rows[1].operatorId, primaryBlockHash: rows[0].hash, secondaryBlockHash: rows[1].hash };
}

export async function validateMonotonicFinalityAnchor({ previous, current, endpoints = null }) {
  const dimensions = [["l2.finalized", previous.l2.finalized, current.l2.finalized], ["l2.safe", previous.l2.safe, current.l2.safe], ["l1.origin", previous.l1.origin, current.l1.origin], ["l1.finalized", previous.l1.finalized, current.l1.finalized]];
  for (const [label, before, after] of dimensions) {
    if (after.number < before.number) throw new Error(`${label} anchor downgraded during recheck`);
    if (after.number === before.number && after.hash !== before.hash) throw new Error(`${label} anchor hash changed during recheck`);
  }
  if (endpoints) {
    for (const [label, priorPoint] of [["finalized", previous.l2.finalized], ["safe", previous.l2.safe]]) {
      const tag = `0x${priorPoint.number.toString(16)}`;
      const prior = await Promise.all(endpoints.map((endpoint) => endpoint.provider.send("eth_getBlockByNumber", [tag, false])));
      if (prior.some((value) => block(value, `prior ${label}`).hash !== priorPoint.hash)) throw new Error(`L2 ${label} anchor reorged during recheck`);
    }
  }
  if (current.l2.safe.number < current.l2.finalized.number || current.l1.origin.number > current.l1.finalized.number) throw new Error("finality anchor cross-relations failed during recheck");
  return current;
}

export async function recheckFinalityAnchor({ endpoints, policy, previous }) {
  const current = await collectFinalityAnchor({ endpoints, policy });
  return validateMonotonicFinalityAnchor({ previous, current, endpoints });
}
