// Permanent off-chain data availability through the Arweave mainnet.
// Uploads are considered ready only after confirmation and identical,
// content-addressed retrieval from two independent gateways.

import Arweave from "arweave";
import { ethers } from "ethers";
import { parseStrictJsonText } from "./strict-json.mjs";

const DEFAULT_GATEWAYS = ["https://arweave.net", "https://arweave.dev"];
const DEFAULT_GRAPHQL = "https://arweave.net/graphql";
const CID_PATTERN = /^sha256:[0-9a-f]{64}$/;
const TXID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const MAX_JWK_BYTES = 1024 * 1024;
const MAX_GRAPHQL_BYTES = 1024 * 1024;
const MAX_DA_BYTES = 16 * 1024 * 1024;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function assertCid(cid) {
  if (!CID_PATTERN.test(cid)) throw new Error("CID must be sha256:<64 lowercase hex characters>");
  return cid;
}

function assertTxid(txid) {
  if (!TXID_PATTERN.test(txid)) throw new Error("invalid Arweave transaction id");
  return txid;
}

function configuredWallet(wallet) {
  if (wallet && typeof wallet === "object") return wallet;
  const encoded = process.env.ARWEAVE_JWK_JSON;
  if (!encoded) throw new Error("set ARWEAVE_JWK_JSON to a funded Arweave mainnet JWK");
  try {
    const parsed = parseStrictJsonText(encoded, {
      label: "ARWEAVE_JWK_JSON",
      maxBytes: MAX_JWK_BYTES,
      maxDepth: 32,
    });
    if (!parsed || typeof parsed !== "object") throw new Error("not an object");
    return parsed;
  } catch (error) {
    throw new Error(`ARWEAVE_JWK_JSON is not valid JSON: ${error.message}`);
  }
}

function defaultClient() {
  return Arweave.init({ host: "arweave.net", port: 443, protocol: "https" });
}

export function cidOf(bytes) {
  return "sha256:" + ethers.sha256(bytes).slice(2);
}

export function daHashForTxid(txid) {
  return ethers.keccak256(ethers.toUtf8Bytes(assertTxid(txid)));
}

async function gatewayBytes(gateway, txid, fetchImpl) {
  const response = await fetchImpl(`${gateway}/${txid}`, {
    headers: { Accept: "application/octet-stream" },
  });
  if (!response.ok) throw new Error(`${gateway} returned HTTP ${response.status}`);
  return readBoundedResponse(response, MAX_DA_BYTES, `${gateway} response`);
}

async function readBoundedResponse(response, maxBytes, label) {
  const declared = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`);
  if (!response.body?.getReader) throw new Error(`${label} has no bounded response stream`);
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      length += chunk.length;
      if (length > maxBytes) {
        await reader.cancel();
        throw new Error(`${label} exceeds ${maxBytes} bytes`);
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, length);
}

async function waitForConfirmation(client, txid, {
  minConfirmations,
  maxAttempts,
  pollMs,
  sleepImpl,
}) {
  let lastStatus = "unavailable";
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const status = await client.transactions.getStatus(txid);
      const confirmations = Number(status?.confirmed?.number_of_confirmations ?? 0);
      lastStatus = `HTTP ${status?.status ?? "unknown"}, confirmations ${confirmations}`;
      if (status?.status === 200 && confirmations >= minConfirmations) return confirmations;
    } catch (error) {
      lastStatus = error.message;
    }
    if (attempt + 1 < maxAttempts) await sleepImpl(pollMs);
  }
  throw new Error(`Arweave transaction ${txid} was not confirmed: ${lastStatus}`);
}

async function verifyGatewayReplication(bytes, txid, {
  gateways,
  fetchImpl,
  maxAttempts,
  pollMs,
  sleepImpl,
}) {
  const expectedCid = cidOf(bytes);
  let lastError = "not yet retrievable";
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const verified = new Set();
    for (const gateway of gateways) {
      try {
        const fetched = await gatewayBytes(gateway, txid, fetchImpl);
        if (cidOf(fetched) !== expectedCid) {
          throw new Error(`${gateway} returned bytes that do not match ${expectedCid}`);
        }
        verified.add(new URL(gateway).host);
      } catch (error) {
        lastError = error.message;
      }
    }
    if (verified.size >= 2) return [...verified].sort();
    if (attempt + 1 < maxAttempts) await sleepImpl(pollMs);
  }
  throw new Error(`Arweave transaction ${txid} lacks two-gateway replication: ${lastError}`);
}

export async function uploadToArweave(bytes, {
  wallet,
  arweaveClient = defaultClient(),
  gateways = DEFAULT_GATEWAYS,
  fetchImpl = fetch,
  minConfirmations = 1,
  maxAttempts = 180,
  pollMs = 10_000,
  sleepImpl = sleep,
} = {}) {
  if (!Number.isInteger(minConfirmations) || minConfirmations < 1) {
    throw new Error("minConfirmations must be a positive integer");
  }
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new Error("maxAttempts must be a positive integer");
  }
  if (!Array.isArray(gateways) || new Set(gateways.map((value) => new URL(value).host)).size < 2) {
    throw new Error("at least two distinct Arweave gateway hosts are required");
  }

  const payload = Buffer.from(bytes);
  if (payload.length === 0) throw new Error("cannot upload an empty DA payload");
  const cid = cidOf(payload);
  const transaction = await arweaveClient.createTransaction({ data: payload }, configuredWallet(wallet));
  transaction.addTag("P42-CID", cid);
  transaction.addTag("App-Name", "P42-Prizes");
  transaction.addTag("Content-Type", "application/json");
  await arweaveClient.transactions.sign(transaction, configuredWallet(wallet));
  const posted = await arweaveClient.transactions.post(transaction);
  if (![200, 208].includes(posted?.status)) {
    throw new Error(`Arweave rejected transaction ${transaction.id || "<unsigned>"}: HTTP ${posted?.status ?? "unknown"}`);
  }

  const txid = assertTxid(transaction.id);
  const confirmations = await waitForConfirmation(arweaveClient, txid, {
    minConfirmations, maxAttempts, pollMs, sleepImpl,
  });
  const replicatedBy = await verifyGatewayReplication(payload, txid, {
    gateways, fetchImpl, maxAttempts, pollMs, sleepImpl,
  });
  return {
    cid,
    txid,
    txidBytes32: daHashForTxid(txid),
    url: `${gateways[0]}/${txid}`,
    network: "arweave-mainnet",
    confirmations,
    replicatedBy,
  };
}

export async function findTxidByCid(cid, {
  graphqlEndpoint = DEFAULT_GRAPHQL,
  fetchImpl = fetch,
} = {}) {
  assertCid(cid);
  const query = `query P42ByCid($cid: String!) {
    transactions(tags: [{ name: "P42-CID", values: [$cid] }], sort: HEIGHT_DESC, first: 1) {
      edges { node { id } }
    }
  }`;
  const response = await fetchImpl(graphqlEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables: { cid } }),
  });
  if (!response.ok) throw new Error(`Arweave GraphQL returned HTTP ${response.status}`);
  const bodyBytes = await readBoundedResponse(response, MAX_GRAPHQL_BYTES, "Arweave GraphQL response");
  const body = parseStrictJsonText(bodyBytes.toString("utf8"), {
    label: "Arweave GraphQL response",
    maxBytes: MAX_GRAPHQL_BYTES,
    maxDepth: 32,
  });
  if (body?.errors?.length) throw new Error(`Arweave GraphQL error: ${body.errors[0].message || "unknown"}`);
  const id = body?.data?.transactions?.edges?.[0]?.node?.id;
  return id ? assertTxid(id) : null;
}

export async function fetchFromArweave(txid, {
  gateways = DEFAULT_GATEWAYS,
  fetchImpl = fetch,
  attemptsPerGateway = 3,
  pollMs = 3_000,
  sleepImpl = sleep,
} = {}) {
  assertTxid(txid);
  let lastError = "not found";
  for (const gateway of gateways) {
    for (let attempt = 0; attempt < attemptsPerGateway; attempt += 1) {
      try {
        return await gatewayBytes(gateway, txid, fetchImpl);
      } catch (error) {
        lastError = error.message;
      }
      if (attempt + 1 < attemptsPerGateway) await sleepImpl(pollMs);
    }
  }
  throw new Error(`could not fetch ${txid} from any Arweave gateway: ${lastError}`);
}

export async function verifyRetrievable(cid, options = {}) {
  const txid = await findTxidByCid(cid, options);
  if (!txid) return { ok: false, reason: "not found on Arweave" };
  const bytes = await fetchFromArweave(txid, options);
  const observedCid = cidOf(bytes);
  return { ok: observedCid === cid, cid: observedCid, txid, bytes };
}
