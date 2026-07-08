// Minimal LOCAL data-availability store — a Phase-1 PLACEHOLDER for a real
// provider (Arweave via Irys/Bundlr + a commit-time blob DA). It exists only so
// the solver can POST a solution blob and the operator can FETCH it back by CID
// and re-derive the verdict independently, instead of being handed the answer.
//
// A real provider replaces put/get with an upload that returns a txid and a
// gateway fetch that proves the bytes remain retrievable. NOT for production.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { ethers } from "ethers";

export function cidOf(bytes) {
  return "sha256:" + ethers.sha256(bytes).slice(2);
}

function pathFor(dir, cid) {
  return `${dir}/${cid.replace(":", "_")}.blob`;
}

export function putBlob(dir, bytes) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const cid = cidOf(bytes);
  writeFileSync(pathFor(dir, cid), bytes);
  return cid;
}

export function getBlob(dir, cid) {
  const p = pathFor(dir, cid);
  return existsSync(p) ? readFileSync(p) : null;
}
