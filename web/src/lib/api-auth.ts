import { createHash, timingSafeEqual } from "node:crypto";
import { ApiError } from "@/lib/api";

const HASH_PREFIX = "sha256:";
const HASH_RE = /^sha256:[a-f0-9]{64}$/;

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
  allowedHashes: string[];
  localOptOut: boolean;
}

function configuredKeyHashes(): string[] {
  const raw = process.env.P42_MUTATION_API_KEY_SHA256S ?? "";
  return raw
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function currentMutationApiAuthConfiguration(): MutationApiAuthConfiguration {
  const allowedHashes = configuredKeyHashes();
  const localOptOut = process.env.NODE_ENV !== "production"
    && process.env.P42_ALLOW_UNAUTHENTICATED_MUTATIONS === "1";

  if (allowedHashes.some((hash) => !HASH_RE.test(hash))) {
    return { status: "misconfigured", allowedHashes, localOptOut };
  }
  if (allowedHashes.length === 0) {
    return { status: "unconfigured", allowedHashes, localOptOut };
  }
  return { status: "configured", allowedHashes, localOptOut };
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
  return { status: "configured", available: true, authentication: "api-key" };
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
  const configuration = currentMutationApiAuthConfiguration();
  if (configuration.status === "misconfigured") {
    throw new ApiError("mutation API key configuration contains an invalid key hash", 503);
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
  if (!configuration.allowedHashes.some((allowed) => safeEqual(allowed, keyHash))) {
    throw new ApiError("invalid P42 mutation API key", 403);
  }

  return {
    authenticated: true,
    rateLimitSubject: `api-key:${keyHash}`,
  };
}

export function mutationApiKeyHashForTests(key: string): string {
  return sha256Key(key);
}
