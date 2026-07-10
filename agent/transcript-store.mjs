import { createHash } from "node:crypto";
import { CID } from "multiformats/cid";
import { canonicalJson, sha256Canonical } from "./lib.mjs";

export const MAX_TRANSCRIPT_ARTIFACT_BYTES = 16 * 1024 * 1024;
export const DEFAULT_TRANSCRIPT_TIMEOUT_MS = 10_000;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const AR_TXID_RE = /^[A-Za-z0-9_-]{43}$/;

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function noUrlDecorations(url, label) {
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(`${label} must not contain userinfo, query, or fragment`);
  }
}

export function parseTranscriptUri(value) {
  if (typeof value !== "string" || !value || /\s/.test(value)) {
    throw new Error("transcript URI must be a non-empty URI without whitespace");
  }
  if (/(?:^|\/)\.{1,2}(?:\/|$)/.test(value) || /%2f|%5c|%2e/i.test(value)) {
    throw new Error("transcript URI path is not canonical");
  }
  let url;
  try { url = new URL(value); } catch { throw new Error("transcript URI is malformed"); }
  noUrlDecorations(url, "transcript URI");
  if (url.protocol === "ar:") {
    const identifier = `${url.hostname}${url.pathname}`.replace(/^\/+|\/+$/g, "");
    if (identifier.includes("/") || !AR_TXID_RE.test(identifier)) {
      throw new Error("ar:// URI must contain exactly one 43-character transaction id");
    }
    return { scheme: "ar", identifier, path: "", uri: `ar://${identifier}` };
  }
  if (url.protocol === "ipfs:") {
    const raw = value.match(/^ipfs:\/\/([^/]+)(\/[^?#]*)?$/);
    if (!raw) throw new Error("ipfs:// URI is malformed");
    const segments = `${raw[1]}${raw[2] ?? ""}`.split("/").filter(Boolean);
    const cid = segments.shift() ?? "";
    try {
      const parsedCid = CID.parse(cid);
      if (parsedCid.toString() !== cid) throw new Error("non-canonical CID");
    } catch {
      throw new Error("ipfs:// URI contains an invalid or non-canonical CID");
    }
    for (const segment of segments) {
      let decoded;
      try { decoded = decodeURIComponent(segment); } catch { throw new Error("ipfs:// URI path has invalid encoding"); }
      if (!decoded || decoded === "." || decoded === ".." || decoded.includes("/") || decoded.includes("\\")) {
        throw new Error("ipfs:// URI path is not canonical");
      }
    }
    const path = segments.length ? `/${segments.join("/")}` : "";
    return { scheme: "ipfs", identifier: cid, path, uri: `ipfs://${cid}${path}` };
  }
  throw new Error("transcript URI must use ar:// or ipfs://");
}

export function canonicalTranscriptArtifact(transcript) {
  if (!transcript || typeof transcript !== "object" || Array.isArray(transcript)) throw new Error("transcript must be an object");
  if (!SHA256_RE.test(String(transcript.transcript_hash))) throw new Error("transcript has no canonical embedded self-hash");
  const unhashed = { ...transcript };
  delete unhashed.transcript_hash;
  if (sha256Canonical(unhashed) !== transcript.transcript_hash) throw new Error("transcript embedded self-hash mismatch");
  const bytes = Buffer.from(`${canonicalJson(transcript)}\n`, "utf8");
  if (bytes.length > MAX_TRANSCRIPT_ARTIFACT_BYTES) throw new Error("transcript artifact exceeds the byte limit");
  return { bytes, length: bytes.length, transcript_hash: transcript.transcript_hash, artifact_sha256: digest(bytes) };
}

function endpointOrigin(endpoint) {
  const url = new URL(endpoint);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("retrieval endpoint must use HTTP(S)");
  noUrlDecorations(url, "retrieval endpoint");
  return url.origin.toLowerCase();
}

export async function fetchTranscriptClientBytes(fetchClient, request, {
  timeoutMs = DEFAULT_TRANSCRIPT_TIMEOUT_MS,
  maxBytes = MAX_TRANSCRIPT_ARTIFACT_BYTES,
} = {}) {
  if (!fetchClient?.fetchTranscript) throw new Error("transcript fetch client is required");
  let timer;
  try {
    const value = await Promise.race([
      fetchClient.fetchTranscript({ ...request, timeoutMs, maxBytes }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("transcript retrieval timed out")), timeoutMs); }),
    ]);
    const bytes = Buffer.from(value);
    if (bytes.length > maxBytes) throw new Error("transcript retrieval exceeds the byte limit");
    return bytes;
  } finally { clearTimeout(timer); }
}

export async function boundedFetchBytes(url, {
  fetchImpl = fetch,
  timeoutMs = DEFAULT_TRANSCRIPT_TIMEOUT_MS,
  maxBytes = MAX_TRANSCRIPT_ARTIFACT_BYTES,
} = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { redirect: "manual", signal: controller.signal });
    if (response.status >= 300 && response.status < 400) throw new Error("transcript retrieval redirects are forbidden");
    if (!response.ok) throw new Error(`transcript retrieval returned HTTP ${response.status}`);
    const declared = Number(response.headers?.get?.("content-length"));
    if (Number.isFinite(declared) && declared > maxBytes) throw new Error("transcript retrieval exceeds the byte limit");
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > maxBytes) throw new Error("transcript retrieval exceeds the byte limit");
    return bytes;
  } catch (error) {
    if (error?.name === "AbortError") throw new Error("transcript retrieval timed out");
    throw error;
  } finally { clearTimeout(timer); }
}

export async function verifyPublicationReceipt({ artifact, receipt, endpoints, fetchClient }) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("publication receipt is required");
  const parsed = parseTranscriptUri(receipt.uri);
  if (receipt.artifact_sha256 !== artifact.artifact_sha256) throw new Error("publication receipt artifact_sha256 mismatch");
  if (receipt.length !== artifact.length) throw new Error("publication receipt length mismatch");
  const configured = endpoints ?? receipt.endpoints;
  if (!Array.isArray(configured) || configured.length < 2) throw new Error("two independent retrieval endpoints are required");
  const origins = configured.map(endpointOrigin);
  if (new Set(origins).size < 2) throw new Error("retrieval endpoints must have independent origins");
  const retrieve = fetchClient?.fetchTranscript
    ? (endpoint) => fetchTranscriptClientBytes(fetchClient, { endpoint, uri: parsed.uri })
    : (endpoint) => boundedFetchBytes(`${endpoint.replace(/\/$/, "")}/${parsed.identifier}${parsed.path}`,
      { fetchImpl: fetchClient?.fetch ?? fetchClient ?? fetch });
  for (const endpoint of configured) {
    const observed = Buffer.from(await retrieve(endpoint));
    if (!observed.equals(artifact.bytes)) throw new Error(`retrieval endpoint ${endpoint} returned non-canonical transcript bytes`);
  }
  return {
    schema_version: "p42-transcript-publication/v1",
    uri: parsed.uri,
    endpoints: [...configured],
    length: artifact.length,
    artifact_sha256: artifact.artifact_sha256,
    transcript_hash: artifact.transcript_hash,
    receipt,
  };
}

export async function publishAndVerifyTranscript({ transcript, publisher, endpoints, fetchClient }) {
  const artifact = canonicalTranscriptArtifact(transcript);
  if (!publisher?.publishTranscript) return { status: "awaiting_publication", artifact };
  const receipt = await publisher.publishTranscript(artifact.bytes, {
    transcript_hash: artifact.transcript_hash,
    artifact_sha256: artifact.artifact_sha256,
    length: artifact.length,
  });
  const publication = await verifyPublicationReceipt({ artifact, receipt, endpoints, fetchClient });
  return { status: "published", artifact, publication };
}
