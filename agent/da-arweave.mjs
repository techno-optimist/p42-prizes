// OPTIONAL off-chain data-availability provider — Arweave via Irys (devnet by default).
//
// Since the on-chain-at-reveal redesign, the on-chain `commitDaHash` anchor is
// sha256(raw solution bytes) (== the CID digest), NOT keccak(txid). This module
// is now used in two OPTIONAL roles: (1) the off-chain content store for the
// large-certificate (onchainDa=false) problems whose bytes exceed calldata
// limits, and (2) a belt-and-suspenders mirror for on-chain problems. In both
// cases retrieval is content-addressed by the sha256 CID and any fetcher
// re-verifies sha256(bytes) == the on-chain anchor. `daHashForTxid` (keccak of
// the txid) is now only an OPTIONAL finalize mirror-receipt, never the anchor.
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

// OPTIONAL finalize mirror-receipt = keccak of the Arweave txid string (any
// length -> bytes32). This is NO LONGER the on-chain commitDaHash anchor (that
// is sha256(solution bytes)); it only records which Arweave mirror a finalize
// points at, when a mirror is used.
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
