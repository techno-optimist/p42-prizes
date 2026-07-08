// LIVE data-availability provider — Arweave via Irys (devnet by default).
//
// Solution bytes are uploaded to Arweave, TAGGED with their P42 content id (the
// sha256 CID), and retrievable from a public gateway. Retrieval is
// content-addressed: given the on-chain solutionCid, anyone (the operator, a
// challenger) queries Arweave/Irys for the data item tagged with that CID, gets
// its txid, and fetches the bytes — then confirms sha256(bytes) == CID. The
// on-chain `commitDaHash` binds keccak(txid), anchoring which Arweave upload the
// commit points at.
//
// Devnet = Phase-1 plumbing: real network, real txids, real gateway + GraphQL,
// free for small blobs, retained ~60 days. Switch `network` to "mainnet" and
// fund the Irys node for permanent storage (Phase 2+).
import Irys from "@irys/sdk";
import { ethers } from "ethers";

const GATEWAYS = ["https://gateway.irys.xyz", "https://devnet.irys.xyz"];
const GRAPHQL = { devnet: "https://devnet.irys.xyz/graphql", mainnet: "https://uploader.irys.xyz/graphql" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function cidOf(bytes) {
  return "sha256:" + ethers.sha256(bytes).slice(2);
}

// On-chain commitDaHash = keccak of the Arweave txid string (any length -> bytes32).
export function daHashForTxid(txid) {
  return ethers.keccak256(ethers.toUtf8Bytes(txid));
}

export async function uploadToArweave(bytes, { irysKey, providerUrl = "https://ethereum-sepolia-rpc.publicnode.com", network = "devnet" } = {}) {
  const key = irysKey || ethers.Wallet.createRandom().privateKey; // small devnet uploads are free; signer needs no funds
  const irys = new Irys({ network, token: "ethereum", key, config: { providerUrl } });
  const cid = cidOf(bytes);
  const r = await irys.upload(Buffer.from(bytes), {
    tags: [{ name: "P42-CID", value: cid }, { name: "Content-Type", value: "application/json" }],
  });
  return { cid, txid: r.id, txidBytes32: daHashForTxid(r.id), url: `${GATEWAYS[0]}/${r.id}`, network };
}

// Content-addressed lookup: find the Arweave txid for a given P42 CID.
export async function findTxidByCid(cid, { network = "devnet" } = {}) {
  const endpoint = GRAPHQL[network] || GRAPHQL.devnet;
  const query = `query { transactions(tags: [{ name: "P42-CID", values: ["${cid}"] }], order: DESC, limit: 1) { edges { node { id } } } }`;
  for (let i = 0; i < 10; i++) {
    try {
      const res = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query }) });
      const j = await res.json();
      const id = j?.data?.transactions?.edges?.[0]?.node?.id;
      if (id) return id;
    } catch { /* retry */ }
    await sleep(4000);
  }
  return null;
}

export async function fetchFromArweave(txid) {
  let lastErr;
  for (const gw of GATEWAYS) {
    for (let i = 0; i < 6; i++) {
      try {
        const res = await fetch(`${gw}/${txid}`);
        if (res.ok) return Buffer.from(await res.arrayBuffer());
        lastErr = `HTTP ${res.status}`;
      } catch (e) { lastErr = e.message; }
      await sleep(3000);
    }
  }
  throw new Error(`could not fetch ${txid} from any gateway: ${lastErr}`);
}

// The real "is the data still there?" check.
export async function verifyRetrievable(cid, { network = "devnet" } = {}) {
  const txid = await findTxidByCid(cid, { network });
  if (!txid) return { ok: false, reason: "not found on Arweave" };
  const bytes = await fetchFromArweave(txid);
  const got = cidOf(bytes);
  return { ok: got === cid, cid: got, txid, bytes };
}
