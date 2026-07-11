import { createHash, timingSafeEqual } from "node:crypto";
import { ApiError } from "@/lib/api";

const HASH_PREFIX = "sha256:";
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const MAX_POLICY_BYTES = 64 * 1024;
const MAX_CREDENTIALS = 64;
const MUTATION_SCOPES = new Set([
  "challenges.open",
  "solutions.verify",
  "submissions.commit",
  "submissions.reveal",
]);

export interface MutationPrincipal {
  rateLimitSubject?: string;
  authenticated: boolean;
}

export type MutationApiConfigurationStatus = "configured" | "unconfigured" | "misconfigured";

export interface MutationApiCapabilities {
  status: MutationApiConfigurationStatus;
  available: boolean;
  authentication: "api-key" | "local-development-opt-out" | "unavailable";
}

interface MutationApiAuthConfiguration {
  status: MutationApiConfigurationStatus;
  credentials: MutationCredential[];
  localOptOut: boolean;
}

interface MutationCredential {
  hash: string;
  scopes: string[];
  expiresAt?: string;
}

function canonicalExpiry(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    return false;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function parseCredentialPolicy(): MutationCredential[] | undefined {
  const raw = process.env.P42_MUTATION_API_CREDENTIALS_JSON;
  const legacy = process.env.P42_MUTATION_API_KEY_SHA256S;
  if (legacy !== undefined) return undefined;
  if (raw === undefined || raw === "") return [];
  if (Buffer.byteLength(raw, "utf8") > MAX_POLICY_BYTES) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (JSON.stringify(parsed) !== raw) return undefined;
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > MAX_CREDENTIALS) return undefined;
  const credentials: MutationCredential[] = [];
  const seenHashes = new Set<string>();
  for (const value of parsed) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const expectedKeys = record.expiresAt === undefined
      ? ["hash", "scopes"]
      : ["expiresAt", "hash", "scopes"];
    if (JSON.stringify(keys) !== JSON.stringify(expectedKeys)) return undefined;
    if (typeof record.hash !== "string" || !HASH_RE.test(record.hash) || seenHashes.has(record.hash)) {
      return undefined;
    }
    if (!Array.isArray(record.scopes) || record.scopes.length < 1) return undefined;
    const scopes = record.scopes;
    if (scopes.some((scope) => typeof scope !== "string" || !MUTATION_SCOPES.has(scope))) return undefined;
    if (new Set(scopes).size !== scopes.length) return undefined;
    if (record.expiresAt !== undefined && !canonicalExpiry(record.expiresAt)) return undefined;
    seenHashes.add(record.hash);
    credentials.push({
      hash: record.hash,
      scopes: [...scopes].sort(),
      ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
    });
  }
  return credentials;
}

function currentMutationApiAuthConfiguration(): MutationApiAuthConfiguration {
  const credentials = parseCredentialPolicy();
  const localOptOut = process.env.NODE_ENV !== "production"
    && process.env.P42_ALLOW_UNAUTHENTICATED_MUTATIONS === "1";

  if (credentials === undefined) {
    return { status: "misconfigured", credentials: [], localOptOut };
  }
  if (credentials.length === 0) {
    return { status: "unconfigured", credentials, localOptOut };
  }
  return { status: "configured", credentials, localOptOut };
}

// This is deliberately coarse-grained: callers can decide whether to attempt a
// mutation without learning how many keys exist or anything about their hashes.
export function mutationApiCapabilities(): MutationApiCapabilities {
  const configuration = currentMutationApiAuthConfiguration();
  if (configuration.status === "misconfigured") {
    return { status: "misconfigured", available: false, authentication: "unavailable" };
  }
  if (configuration.status === "unconfigured") {
    if (configuration.localOptOut) {
      return { status: "unconfigured", available: true, authentication: "local-development-opt-out" };
    }
    return { status: "unconfigured", available: false, authentication: "unavailable" };
  }
  const hasActiveCredential = configuration.credentials.some(
    (credential) => credential.expiresAt === undefined || Date.parse(credential.expiresAt) > Date.now(),
  );
  return {
    status: "configured",
    available: hasActiveCredential,
    authentication: hasActiveCredential ? "api-key" : "unavailable",
  };
}

function presentedKey(req: Request): string | undefined {
  const direct = req.headers.get("x-p42-api-key")?.trim();
  if (direct) return direct;

  const authorization = req.headers.get("authorization")?.trim();
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim();
}

function sha256Key(key: string): string {
  return `${HASH_PREFIX}${createHash("sha256").update(key, "utf8").digest("hex")}`;
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

export function enforceMutationApiKey(req: Request, scope: string): MutationPrincipal {
  if (!MUTATION_SCOPES.has(scope)) {
    throw new ApiError("mutation API route scope is invalid", 503);
  }
  const configuration = currentMutationApiAuthConfiguration();
  if (configuration.status === "misconfigured") {
    throw new ApiError("mutation API credential policy is invalid", 503);
  }

  if (configuration.status === "unconfigured") {
    if (configuration.localOptOut) return { authenticated: false };
    throw new ApiError("mutation API authentication is not configured", 503);
  }

  const key = presentedKey(req);
  if (!key) {
    throw new ApiError("P42 mutation API key required", 401, {
      "WWW-Authenticate": `Bearer realm="p42-prizes", error="missing_api_key", scope="${scope}"`,
    });
  }

  const keyHash = sha256Key(key);
  const matches = configuration.credentials.filter((credential) => safeEqual(credential.hash, keyHash));
  const credential = matches[0];
  if (!credential || (credential.expiresAt !== undefined && Date.parse(credential.expiresAt) <= Date.now())) {
    throw new ApiError("invalid P42 mutation API key", 403);
  }
  if (!credential.scopes.includes(scope)) {
    throw new ApiError("P42 mutation API key has insufficient scope", 403, {
      "WWW-Authenticate": `Bearer realm="p42-prizes", error="insufficient_scope", scope="${scope}"`,
    });
  }

  return {
    authenticated: true,
    rateLimitSubject: `api-key:${keyHash}`,
  };
}

export function mutationApiKeyHashForTests(key: string): string {
  return sha256Key(key);
}

export function mutationApiCredentialPolicyForTests(
  records: Array<{ key: string; scopes: string[]; expiresAt?: string }>,
): string {
  return JSON.stringify(records.map((record) => ({
    hash: sha256Key(record.key),
    scopes: record.scopes,
    ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
  })));
}
