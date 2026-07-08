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

// NOTE: This limiter is in-memory and per-process. It resets on restart and is NOT shared across
// serverless instances or replicas — a deployment must move this to a shared store (e.g. Redis)
// before it can be trusted at scale. It also keys unidentified traffic under a single "anonymous"
// bucket (see rateLimitSubject), so without a platform-injected client-IP header all anonymous
// callers share one global limit. Documented as a Phase-0 limitation.
const MAX_TRACKED_BUCKETS = 10_000;

function store(): RateLimitStore {
  globalRateLimit.__p42RateLimitStore ??= { buckets: new Map() };
  return globalRateLimit.__p42RateLimitStore;
}

// Bound memory: expired buckets are otherwise never removed, so a stream of distinct subjects
// (e.g. spoofed client IPs) would grow the Map without limit. Sweep lazily once it gets large.
function sweepExpiredBuckets(state: RateLimitStore, now: number): void {
  if (state.buckets.size <= MAX_TRACKED_BUCKETS) return;
  for (const [key, bucket] of state.buckets) {
    if (bucket.resetAt <= now) state.buckets.delete(key);
  }
}

function envNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
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
  sweepExpiredBuckets(state, now);
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
