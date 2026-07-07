import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { enforceRateLimit, rateLimitPolicy, rateLimitSubject, resetRateLimitsForTests } from "@/lib/rate-limit";

describe("rate limiting", () => {
  beforeEach(() => {
    resetRateLimitsForTests();
  });

  afterEach(() => {
    resetRateLimitsForTests();
    delete process.env.P42_TRUSTED_CLIENT_IP_HEADER;
  });

  it("ignores spoofable forwarded headers unless a trusted header is configured", () => {
    const req = new Request("http://localhost/api/solutions", {
      headers: { "x-forwarded-for": "203.0.113.10" },
    });
    expect(rateLimitSubject(req)).toBe("anonymous");

    process.env.P42_TRUSTED_CLIENT_IP_HEADER = "x-forwarded-for";
    expect(rateLimitSubject(req)).toBe("ip:203.0.113.10");
  });

  it("throws 429 with retry headers after the policy limit is exhausted", () => {
    const req = new Request("http://localhost/api/solutions");
    const policy = rateLimitPolicy("unit_test", { limit: 1, windowMs: 60_000 });

    expect(() => enforceRateLimit(req, policy)).not.toThrow();
    expect(() => enforceRateLimit(req, policy)).toThrow("rate limit exceeded");
  });
});
