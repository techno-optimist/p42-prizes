import { ethers } from "ethers";

function canonicalEndpoint(value) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
    throw new Error("activation checkpoint RPC URL must be a nonempty primitive string");
  }
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password
      || parsed.search || parsed.hash || parsed.pathname !== "/") {
    throw new Error("activation checkpoint RPC URLs must be credential-free root HTTPS endpoints");
  }
  const rawHostname = parsed.hostname.toLowerCase().replace(/\.+$/, "");
  const hostname = mappedIpv4(rawHostname) ?? rawHostname;
  if (!hostname) throw new Error("activation checkpoint RPC hostname is invalid");
  parsed.hostname = hostname;
  const port = parsed.port || "443";
  return Object.freeze({
    url: parsed.href,
    hostname,
    origin: `https://${hostname}:${port}`,
  });
}

function mappedIpv4(hostname) {
  if (!hostname.startsWith("[") || !hostname.endsWith("]")) return null;
  const raw = hostname.slice(1, -1);
  const halves = raw.split("::");
  if (halves.length > 2) return null;
  const words = (part) => part ? part.split(":").map((word) => Number.parseInt(word, 16)) : [];
  const left = words(halves[0]);
  const right = halves.length === 2 ? words(halves[1]) : [];
  const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
  const expanded = halves.length === 2 ? [...left, ...Array(missing).fill(0), ...right] : left;
  if (missing < 1 || expanded.length !== 8 || expanded.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)) return null;
  if (expanded.slice(0, 5).some((word) => word !== 0) || expanded[5] !== 0xffff) return null;
  return [expanded[6] >> 8, expanded[6] & 0xff, expanded[7] >> 8, expanded[7] & 0xff].join(".");
}

const FORBIDDEN_REDIRECT_STATUS_CODES = new Set([301, 302, 307, 308]);

export function rejectActivationRpcRedirects(getUrlFunc) {
  if (typeof getUrlFunc !== "function") {
    throw new Error("activation checkpoint RPC transport must be a function");
  }
  return async (request, signal) => {
    const response = await getUrlFunc(request, signal);
    if (FORBIDDEN_REDIRECT_STATUS_CODES.has(response?.statusCode)) {
      throw new Error(`activation checkpoint RPC redirects are forbidden (${response.statusCode})`);
    }
    return response;
  };
}

export function activationRpcFetchRequest(url) {
  const request = new ethers.FetchRequest(url);
  const originalGetUrlFunc = request.getUrlFunc;
  request.getUrlFunc = rejectActivationRpcRedirects(originalGetUrlFunc);
  return request;
}

export function validateActivationRpcEndpointPair(primaryValue, secondaryValue) {
  const primary = canonicalEndpoint(primaryValue);
  const secondary = canonicalEndpoint(secondaryValue);
  if (primary.origin === secondary.origin || primary.hostname === secondary.hostname) {
    throw new Error("activation checkpointing requires distinct HTTPS RPC origins and hosts");
  }
  return Object.freeze({ primary, secondary });
}
