// Minimal LOCAL content-addressed store. In the current design data
// availability rides the REVEAL-tx calldata for on-chain-DA problems, so this
// store plays two roles only: (1) a dev/test off-chain store for the large
// onchainDa=false problems (whose bytes exceed calldata limits and live
// off-chain, gated by the same on-chain sha256 anchor), and (2) an OPTIONAL
// local mirror for on-chain-DA problems. The solver can POST a solution blob
// and the operator can FETCH it back by CID and re-derive the verdict
// independently, instead of being handed the answer. A local directory is NOT
// durable DA for production off-chain problems — use a real store (e.g. the
// optional Arweave mirror in da-arweave.mjs) there.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { ethers } from "ethers";

export function cidOf(bytes) {
  return "sha256:" + ethers.sha256(bytes).slice(2);
}

// Canonical CID shape. CIDs arrive from untrusted sources (on-chain event
// args), and they name a file on disk — so anything not exactly
// "sha256:<64 lowercase hex>" is rejected before a path is ever built.
const CID_RE = /^sha256:[0-9a-f]{64}$/;

function pathFor(dir, cid) {
  if (!CID_RE.test(cid)) throw new Error(`invalid cid: ${String(cid).slice(0, 80)}`);
  // Defense-in-depth: even a validated CID is sanitized to a separator-free
  // path component (no "/", "\", ".." can survive), then confined to dir.
  return `${dir}/${cid.replace(/[^a-zA-Z0-9._-]/g, "_")}.blob`;
}

export function putBlob(dir, bytes) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const cid = cidOf(bytes); // self-derived, always canonical
  writeFileSync(pathFor(dir, cid), bytes);
  return cid;
}

export function getBlob(dir, cid) {
  // A malformed (attacker-supplied) CID is a MISS, not a crash or a path.
  if (!CID_RE.test(cid)) return null;
  const p = pathFor(dir, cid);
  return existsSync(p) ? readFileSync(p) : null;
}
