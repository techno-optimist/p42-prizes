import { createHash } from "node:crypto";
import { ethers } from "ethers";

import { canonicalJson, sha256Canonical } from "./lib.mjs";
import { readStrictJsonFileSyncWithBytes } from "./strict-json.mjs";

export const ACTIVATION_RPC_REGISTRY_SCHEMA = "p42-activation-rpc-operator-registry/v1";
export const ACTIVATION_RPC_AUTHORITY_SCHEMA = "p42-activation-rpc-authority/v1";
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const OPERATOR_ID_RE = /^[a-z0-9][a-z0-9._-]{2,63}$/;
const LIMITS = Object.freeze({
  maxBytes: 1024 * 1024,
  maxDepth: 32,
  canonicalBytes: true,
  trailingNewline: "require",
  publicFile: true,
});
const DNS_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const NUMERIC_ALIAS_RE = /^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$/;

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());
}

export function canonicalActivationRpcEndpoint(value) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
    throw new Error("activation checkpoint RPC URL must be a nonempty primitive string");
  }
  if (!/^[\x21-\x7e]+$/.test(value) || value.includes("%")) {
    throw new Error("activation checkpoint RPC origin must be exact ASCII without percent escapes");
  }
  const match = /^https:\/\/([^/:?#]+)(?::([1-9][0-9]{0,4}))?$/.exec(value);
  if (!match) throw new Error("activation checkpoint RPC origin is not canonical HTTPS origin syntax");
  const [, hostname, portText] = match;
  const labels = hostname.split(".");
  if (hostname.length > 253 || labels.length < 2 || labels.some((label) => !DNS_LABEL_RE.test(label))
      || NUMERIC_ALIAS_RE.test(hostname)) {
    throw new Error("activation checkpoint RPC hostname is not canonical lowercase DNS");
  }
  const port = portText === undefined ? 443 : Number(portText);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535 || (portText !== undefined && port === 443)) {
    throw new Error("activation checkpoint RPC port is invalid, redundant, or out of range");
  }
  const origin = `https://${hostname}${port === 443 ? "" : `:${port}`}`;
  if (value !== origin) throw new Error("activation checkpoint RPC origin is not its canonical rendering");
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("activation checkpoint RPC origin is not accepted by the URL parser");
  }
  if (parsed.hostname !== hostname || parsed.origin !== origin || parsed.pathname !== "/"
      || parsed.search !== "" || parsed.hash !== "" || parsed.username !== "" || parsed.password !== "") {
    throw new Error("activation checkpoint RPC URL parser changes the canonical host or origin");
  }
  return Object.freeze({ url: origin, hostname, origin, port });
}

const FORBIDDEN_REDIRECT_STATUS_CODES = new Set([301, 302, 303, 305, 307, 308]);

export function rejectActivationRpcRedirects(getUrlFunc) {
  if (typeof getUrlFunc !== "function") throw new Error("activation checkpoint RPC transport must be a function");
  return async (request, signal) => {
    const response = await getUrlFunc(request, signal);
    if (FORBIDDEN_REDIRECT_STATUS_CODES.has(response?.statusCode)) {
      throw new Error(`activation checkpoint RPC redirects are forbidden (${response.statusCode})`);
    }
    return response;
  };
}

export function activationRpcFetchRequest(url, getUrlFunc = null) {
  const request = new ethers.FetchRequest(url);
  request.getUrlFunc = rejectActivationRpcRedirects(getUrlFunc ?? request.getUrlFunc);
  return request;
}

function profileBody(operatorId, endpointOrigin) {
  return { operatorId, endpointOrigin };
}

export function validateActivationRpcOperatorRegistry(value, expectedDigest) {
  if (!DIGEST_RE.test(expectedDigest ?? "")) throw new Error("activation RPC registry requires an authorization-bound digest");
  if (!exactKeys(value, ["schema", "profiles"]) || value.schema !== ACTIVATION_RPC_REGISTRY_SCHEMA
      || !Array.isArray(value.profiles) || value.profiles.length < 2 || value.profiles.length > 32) {
    throw new Error("activation RPC operator registry has invalid schema or shape");
  }
  const seenIds = new Set();
  const seenOrigins = new Set();
  const profiles = value.profiles.map((profile, index) => {
    if (!exactKeys(profile, ["operatorId", "endpointOrigin", "endpointProfileDigest"])
        || !OPERATOR_ID_RE.test(profile.operatorId ?? "")) {
      throw new Error(`activation RPC operator profile ${index} is invalid`);
    }
    const endpoint = canonicalActivationRpcEndpoint(profile.endpointOrigin);
    if (profile.endpointOrigin !== endpoint.origin
        || profile.endpointProfileDigest !== sha256Canonical(profileBody(profile.operatorId, endpoint.origin))) {
      throw new Error(`activation RPC operator profile ${index} digest or origin is invalid`);
    }
    if (seenIds.has(profile.operatorId) || seenOrigins.has(endpoint.origin)) {
      throw new Error("activation RPC operator registry contains duplicate operator IDs or origins");
    }
    seenIds.add(profile.operatorId); seenOrigins.add(endpoint.origin);
    return Object.freeze({ ...profile });
  });
  return Object.freeze({ schema: value.schema, registryDigest: expectedDigest, profiles: Object.freeze(profiles) });
}

export function loadActivationRpcOperatorRegistry(path, expectedDigest, trustedRoot) {
  if (typeof trustedRoot !== "string" || trustedRoot.length === 0) {
    throw new Error("activation RPC operator registry trusted root is required");
  }
  const loaded = readStrictJsonFileSyncWithBytes(path, { ...LIMITS, trustedRoot });
  const { bytes } = loaded;
  const observedDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  if (observedDigest !== expectedDigest) throw new Error("activation RPC operator registry digest does not match authorization");
  return validateActivationRpcOperatorRegistry(loaded.value, expectedDigest);
}

export function assertActivationRpcAuthorityRegistryMembership(registry, authorityValue) {
  const checked = validateActivationRpcOperatorRegistry(
    { schema: registry?.schema, profiles: registry?.profiles }, registry?.registryDigest,
  );
  const authority = assertActivationRpcAuthority(authorityValue);
  if (authority.registryDigest !== checked.registryDigest) {
    throw new Error("activation RPC authority registry digest mismatch");
  }
  for (const role of ["primary", "secondary"]) {
    if (!checked.profiles.some((profile) => canonicalJson(profile) === canonicalJson(authority[role]))) {
      throw new Error(`activation RPC ${role} authority is not an exact protected registry member`);
    }
  }
  return authority;
}

export function bindActivationRpcAuthority(registry, primaryValue, secondaryValue, primaryOperatorId, secondaryOperatorId) {
  const checked = validateActivationRpcOperatorRegistry(
    { schema: registry?.schema, profiles: registry?.profiles }, registry?.registryDigest,
  );
  if (primaryOperatorId === secondaryOperatorId) throw new Error("activation RPC endpoints must have distinct stable operator IDs");
  const bind = (role, value, operatorId) => {
    const endpoint = canonicalActivationRpcEndpoint(value);
    const matches = checked.profiles.filter((profile) => profile.operatorId === operatorId);
    if (matches.length !== 1 || matches[0].endpointOrigin !== endpoint.origin) {
      throw new Error(`${role} activation RPC endpoint does not match its authorization-bound operator profile`);
    }
    return Object.freeze({ operatorId, endpointOrigin: endpoint.origin, endpointProfileDigest: matches[0].endpointProfileDigest });
  };
  const primary = bind("primary", primaryValue, primaryOperatorId);
  const secondary = bind("secondary", secondaryValue, secondaryOperatorId);
  return Object.freeze({ schema: ACTIVATION_RPC_AUTHORITY_SCHEMA, registryDigest: checked.registryDigest, primary, secondary });
}

export function assertActivationRpcAuthority(value) {
  if (!exactKeys(value, ["schema", "registryDigest", "primary", "secondary"])
      || value.schema !== ACTIVATION_RPC_AUTHORITY_SCHEMA || !DIGEST_RE.test(value.registryDigest ?? "")) {
    throw new Error("activation RPC authority is missing or malformed");
  }
  for (const role of ["primary", "secondary"]) {
    const profile = value[role];
    if (!exactKeys(profile, ["operatorId", "endpointOrigin", "endpointProfileDigest"])
        || !OPERATOR_ID_RE.test(profile.operatorId ?? "") || !DIGEST_RE.test(profile.endpointProfileDigest ?? "")
        || canonicalActivationRpcEndpoint(profile.endpointOrigin).origin !== profile.endpointOrigin) {
      throw new Error(`activation RPC ${role} authority profile is malformed`);
    }
  }
  if (value.primary.operatorId === value.secondary.operatorId) {
    throw new Error("activation RPC authority requires distinct stable operator IDs");
  }
  return value;
}

export function assertObservedActivationRpcAuthority(value, planAuthority = null, expectedChainId = null) {
  if (!exactKeys(value, ["schema", "registryDigest", "primary", "secondary"])) {
    throw new Error("observed activation RPC authority is missing or malformed");
  }
  const stripped = { schema: value.schema, registryDigest: value.registryDigest };
  for (const role of ["primary", "secondary"]) {
    const profile = value[role];
    if (!exactKeys(profile, ["operatorId", "endpointOrigin", "endpointProfileDigest", "observedRawChainId"])
        || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(profile.observedRawChainId ?? "")) {
      throw new Error(`observed activation RPC ${role} authority is malformed`);
    }
    stripped[role] = {
      operatorId: profile.operatorId,
      endpointOrigin: profile.endpointOrigin,
      endpointProfileDigest: profile.endpointProfileDigest,
    };
  }
  assertActivationRpcAuthority(stripped);
  if (planAuthority && canonicalJson(stripped) !== canonicalJson(assertActivationRpcAuthority(planAuthority))) {
    throw new Error("observed activation RPC authority does not match the plan binding");
  }
  if (expectedChainId !== null) {
    const expected = ethers.toQuantity(expectedChainId);
    if (value.primary.observedRawChainId !== expected || value.secondary.observedRawChainId !== expected) {
      throw new Error("observed activation RPC raw chain IDs do not match the plan");
    }
  }
  return value;
}

export function validateActivationRpcEndpointPair(primaryValue, secondaryValue) {
  const primary = canonicalActivationRpcEndpoint(primaryValue);
  const secondary = canonicalActivationRpcEndpoint(secondaryValue);
  if (primary.origin === secondary.origin || primary.hostname === secondary.hostname) {
    throw new Error("activation checkpointing requires distinct HTTPS RPC origins and hosts");
  }
  return Object.freeze({ primary, secondary });
}

export async function observeActivationRpcChainId(url, expectedChainId, getUrlFunc = null) {
  if (!Number.isSafeInteger(expectedChainId) || expectedChainId < 1) throw new Error("activation plan chain ID is invalid");
  const request = activationRpcFetchRequest(url, getUrlFunc);
  request.method = "POST";
  request.setHeader("content-type", "application/json");
  request.body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] });
  const response = await request.send();
  const payload = response.bodyJson;
  if (!payload || payload.jsonrpc !== "2.0" || payload.id !== 1
      || typeof payload.result !== "string" || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(payload.result)) {
    throw new Error("activation RPC returned an invalid raw eth_chainId response");
  }
  const observed = Number(BigInt(payload.result));
  if (!Number.isSafeInteger(observed) || observed !== expectedChainId) {
    throw new Error(`activation RPC raw eth_chainId mismatch: expected ${expectedChainId}, observed ${payload.result}`);
  }
  return payload.result;
}

export async function constructActivationRpcProviders(registry, authorityValue, primaryUrl, secondaryUrl, chainId, transports = {}) {
  const authority = assertActivationRpcAuthorityRegistryMembership(registry, authorityValue);
  const endpoints = validateActivationRpcEndpointPair(primaryUrl, secondaryUrl);
  if (endpoints.primary.origin !== authority.primary.endpointOrigin
      || endpoints.secondary.origin !== authority.secondary.endpointOrigin) {
    throw new Error("activation RPC endpoint origins do not match the plan-bound authority");
  }
  const [primaryRawChainId, secondaryRawChainId] = await Promise.all([
    observeActivationRpcChainId(endpoints.primary.url, chainId, transports.primary),
    observeActivationRpcChainId(endpoints.secondary.url, chainId, transports.secondary),
  ]);
  const primaryRequest = activationRpcFetchRequest(endpoints.primary.url, transports.primary);
  const secondaryRequest = activationRpcFetchRequest(endpoints.secondary.url, transports.secondary);
  return Object.freeze({
    endpoints,
    authority: Object.freeze({
      ...authority,
      primary: Object.freeze({ ...authority.primary, observedRawChainId: primaryRawChainId }),
      secondary: Object.freeze({ ...authority.secondary, observedRawChainId: secondaryRawChainId }),
    }),
    primary: new ethers.JsonRpcProvider(primaryRequest, chainId, { staticNetwork: true }),
    secondary: new ethers.JsonRpcProvider(secondaryRequest, chainId, { staticNetwork: true }),
  });
}
