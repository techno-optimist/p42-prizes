import { createHash } from "node:crypto";
import { statSync } from "node:fs";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { request as httpsRequest } from "node:https";
import { join, resolve } from "node:path";
import { CID } from "multiformats/cid";
import { canonicalJson, sha256Canonical } from "./lib.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

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

function canonicalPathSegment(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

export function parseTranscriptUri(value) {
  // Compatibility boundary for this clone. Replace with the shared strict
  // parser module when that integration commit is present; do not duplicate it.
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
      if (segment !== canonicalPathSegment(decoded)) throw new Error("ipfs:// URI path encoding is not canonical");
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

function isForbiddenIpv4(hostname) {
  const octets = hostname.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b] = octets;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19));
}

function isForbiddenAddress(address) {
  const version = isIP(address);
  if (version === 4) return isForbiddenIpv4(address);
  const normalized = address.toLowerCase();
  if (version === 6) {
    const marker = normalized.lastIndexOf("ffff:");
    if (marker !== -1 && /^[0:]*$/.test(normalized.slice(0, marker))) {
      const tail = normalized.slice(marker + 5);
      if (isIP(tail) === 4) return isForbiddenIpv4(tail);
      const words = tail.split(":");
      if (words.length === 2 && words.every((word) => /^[0-9a-f]{1,4}$/.test(word))) {
        const high = Number.parseInt(words[0], 16);
        const low = Number.parseInt(words[1], 16);
        return isForbiddenIpv4(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
      }
    }
  }
  return version === 6 && (
    normalized === "::1" || normalized === "::" || normalized.startsWith("fc") ||
    normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") ||
    normalized.startsWith("fea") || normalized.startsWith("feb")
  );
}

function endpointSite(hostname) {
  const labels = hostname.split(".");
  return labels.length >= 2 ? labels.slice(-2).join(".") : hostname;
}

export function validateRetrievalEndpoints(endpoints) {
  if (!Array.isArray(endpoints) || endpoints.length < 2) throw new Error("two trusted retrieval endpoints are required");
  const checked = endpoints.map((endpoint) => {
    const url = new URL(endpoint);
    if (url.protocol !== "https:") throw new Error("retrieval endpoint must use HTTPS");
    noUrlDecorations(url, "retrieval endpoint");
    if (url.pathname !== "/" && url.pathname !== "") throw new Error("retrieval endpoint must be an HTTPS origin without a path");
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local")) {
      throw new Error("retrieval endpoint must not target localhost or .local");
    }
    const ipVersion = isIP(hostname);
    if (ipVersion && isForbiddenAddress(hostname)) throw new Error("retrieval endpoint must not target private or link-local IP space");
    return { endpoint: url.origin, origin: url.origin.toLowerCase(), site: endpointSite(hostname) };
  });
  if (new Set(checked.map((entry) => entry.origin)).size !== checked.length) throw new Error("retrieval endpoints must have independent origins");
  if (new Set(checked.map((entry) => entry.site)).size !== checked.length) throw new Error("retrieval endpoints must use independently operated sites");
  return checked.map((entry) => entry.endpoint);
}

export function configuredTranscriptEndpoints(argv = [], env = process.env) {
  const values = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--transcript-endpoint" && argv[index + 1]) values.push(argv[index + 1]);
  }
  if (env.P42_TRANSCRIPT_ENDPOINTS) values.push(...env.P42_TRANSCRIPT_ENDPOINTS.split(",").map((value) => value.trim()).filter(Boolean));
  return validateRetrievalEndpoints(values);
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
    const chunks = [];
    let length = 0;
    const addChunk = (value) => {
      const chunkLength = value?.byteLength ?? value?.length;
      if (!Number.isSafeInteger(chunkLength) || chunkLength < 0) throw new Error("transcript retrieval returned an invalid stream chunk");
      if (length + chunkLength > maxBytes) {
        controller.abort();
        throw new Error("transcript retrieval exceeds the byte limit");
      }
      const chunk = Buffer.from(value);
      length += chunkLength;
      chunks.push(chunk);
    };
    if (response.body?.getReader) {
      const reader = response.body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          addChunk(value);
        }
      } catch (error) {
        await reader.cancel(error).catch(() => {});
        throw error;
      } finally { reader.releaseLock(); }
    } else if (response.body?.[Symbol.asyncIterator]) {
      for await (const chunk of response.body) addChunk(chunk);
    } else {
      throw new Error("transcript retrieval response body is not streamable");
    }
    return Buffer.concat(chunks, length);
  } catch (error) {
    if (error?.name === "AbortError") throw new Error("transcript retrieval timed out");
    throw error;
  } finally { clearTimeout(timer); }
}

export function validatePublicationReceipt({ artifact, receipt }) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("publication receipt is required");
  const keys = Object.keys(receipt).sort();
  if (keys.join(",") !== "artifact_sha256,length,uri") {
    throw new Error("publication receipt keys must be exactly artifact_sha256, length, and uri");
  }
  const parsed = parseTranscriptUri(receipt.uri);
  if (receipt.artifact_sha256 !== artifact.artifact_sha256) throw new Error("publication receipt artifact_sha256 mismatch");
  if (receipt.length !== artifact.length) throw new Error("publication receipt length mismatch");
  return { receipt: { ...receipt, uri: parsed.uri }, parsed };
}

export async function verifyPublicationReceipt({ artifact, receipt, endpoints, fetchClient }) {
  const validated = validatePublicationReceipt({ artifact, receipt });
  const { parsed } = validated;
  if (endpoints === undefined) throw new Error("trusted retrieval endpoints are required; receipt endpoints are ignored");
  const configured = validateRetrievalEndpoints(endpoints);
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
    receipt: validated.receipt,
  };
}

export function receiptSpoolPublisher(directory) {
  const spool = resolve(directory);
  if (!statSync(spool).isDirectory()) throw new Error("publication receipt spool must be a directory");
  return {
    async publishTranscript(_bytes, metadata) {
      const filename = `${metadata.transcript_hash.slice(7)}.json`;
      const receipt = readStrictJsonFileSync(join(spool, filename), {
        maxBytes: 1024 * 1024,
        maxDepth: 32,
        canonicalBytes: true,
        trailingNewline: "require",
      });
      return receipt;
    },
  };
}

export function httpTranscriptFetchClient(fetchImpl = fetch, lookupImpl = lookup) {
  return {
    async fetchTranscript({ endpoint, uri, timeoutMs, maxBytes }) {
      const parsed = parseTranscriptUri(uri);
      const hostname = new URL(endpoint).hostname.replace(/^\[|\]$/g, "");
      const addresses = await lookupImpl(hostname, { all: true, verbatim: true });
      if (!addresses.length || addresses.some(({ address }) => isForbiddenAddress(address))) {
        throw new Error("retrieval endpoint DNS resolved to private or link-local IP space");
      }
      if (fetchImpl !== fetch) {
        throw new Error("custom fetch adapters cannot guarantee DNS address pinning");
      }
      return pinnedHttpsFetchBytes(`${endpoint}/${parsed.identifier}${parsed.path}`, {
        addresses, timeoutMs, maxBytes,
      });
    },
  };
}

export function pinnedHttpsFetchBytes(url, {
  addresses,
  timeoutMs = DEFAULT_TRANSCRIPT_TIMEOUT_MS,
  maxBytes = MAX_TRANSCRIPT_ARTIFACT_BYTES,
  requestImpl = httpsRequest,
} = {}) {
  if (!Array.isArray(addresses) || addresses.length === 0 || addresses.some(({ address }) => isForbiddenAddress(address))) {
    throw new Error("pinned HTTPS retrieval requires validated public addresses");
  }
  const target = new URL(url);
  const selected = addresses[0];
  return new Promise((resolvePromise, rejectPromise) => {
    const request = requestImpl(target, {
      method: "GET",
      servername: target.hostname,
      lookup(_hostname, _options, callback) {
        callback(null, selected.address, selected.family);
      },
    }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400) {
        response.destroy();
        rejectPromise(new Error("transcript retrieval redirects are forbidden"));
        return;
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.destroy();
        rejectPromise(new Error(`transcript retrieval returned HTTP ${response.statusCode}`));
        return;
      }
      const declared = Number(response.headers["content-length"]);
      if (Number.isFinite(declared) && declared > maxBytes) {
        response.destroy();
        rejectPromise(new Error("transcript retrieval exceeds the byte limit"));
        return;
      }
      const chunks = [];
      let length = 0;
      response.on("data", (value) => {
        if (length + value.length > maxBytes) {
          response.destroy(new Error("transcript retrieval exceeds the byte limit"));
          return;
        }
        chunks.push(value);
        length += value.length;
      });
      response.once("end", () => resolvePromise(Buffer.concat(chunks, length)));
      response.once("error", rejectPromise);
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("transcript retrieval timed out")));
    request.once("error", rejectPromise);
    request.end();
  });
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
