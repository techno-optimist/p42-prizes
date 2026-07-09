import { ApiError } from "@/lib/api";

interface RateLimitBucket {
  count: number;
  resetAt: number;
}

interface RateLimitStore {
  buckets: Map<string, RateLimitBucket>;
}

export interface RateLimitPolicy {
  id: string;
  limit: number;
  windowMs: number;
}

const globalRateLimit = globalThis as typeof globalThis & {
  __p42RateLimitStore?: RateLimitStore;
};

function store(): RateLimitStore {
  globalRateLimit.__p42RateLimitStore ??= { buckets: new Map() };
  return globalRateLimit.__p42RateLimitStore;
}

function envNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function maxBuckets(): number {
  return Math.min(20_000, Math.max(100, Math.floor(envNumber("P42_RATE_LIMIT_MAX_BUCKETS", 5_000))));
}

export function rateLimitPolicy(id: string, defaults: { limit: number; windowMs: number }): RateLimitPolicy {
  const envPrefix = `P42_RATE_LIMIT_${id.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
  return {
    id,
    limit: envNumber(`${envPrefix}_LIMIT`, defaults.limit),
    windowMs: envNumber(`${envPrefix}_WINDOW_MS`, defaults.windowMs),
  };
}

export function rateLimitSubject(req: Request): string {
  const trustedHeader = process.env.P42_TRUSTED_CLIENT_IP_HEADER;
  if (!trustedHeader) return "anonymous";
  const value = req.headers.get(trustedHeader)?.split(",")[0]?.trim();
  return value ? `ip:${value.slice(0, 128)}` : "anonymous";
}

export function enforceRateLimit(req: Request, policy: RateLimitPolicy, subject = rateLimitSubject(req)): void {
  if (process.env.P42_DISABLE_RATE_LIMIT === "1") return;

  const now = Date.now();
  const key = `${policy.id}:${subject}`;
  const state = store();
  if (!state.buckets.has(key) && state.buckets.size >= maxBuckets()) {
    for (const [bucketKey, bucket] of state.buckets) {
      if (bucket.resetAt <= now) state.buckets.delete(bucketKey);
    }
    if (state.buckets.size >= maxBuckets()) {
      throw new ApiError("rate limiter capacity exceeded", 503);
    }
  }
  const existing = state.buckets.get(key);
  const bucket = existing && existing.resetAt > now
    ? existing
    : { count: 0, resetAt: now + policy.windowMs };

  if (bucket.count >= policy.limit) {
    const retryAfterSeconds = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
    throw new ApiError("rate limit exceeded", 429, {
      "Retry-After": String(retryAfterSeconds),
      "X-RateLimit-Limit": String(policy.limit),
      "X-RateLimit-Remaining": "0",
      "X-RateLimit-Reset": String(Math.ceil(bucket.resetAt / 1000)),
    });
  }

  bucket.count += 1;
  state.buckets.set(key, bucket);
}

export function resetRateLimitsForTests(): void {
  store().buckets.clear();
}
