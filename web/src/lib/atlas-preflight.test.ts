import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { POST } from "@/app/api/atlas/preflight/route";
import {
  ATLAS_PREFLIGHT_MAX_BODY_BYTES,
  AtlasPreflightInputError,
  assertNoDuplicateJsonKeys,
  coverageRecordMatches,
  computeAtlasPreflight,
  parseAtlasPreflightRequest,
} from "@/lib/atlas-preflight";

const FRESH_NOW = new Date("2026-07-13T12:00:00.000Z");

function post(body: string, headers: Record<string, string> = {}) {
  return POST(
    new Request("http://localhost/api/atlas/preflight", {
      method: "POST",
      body,
      headers: { "content-type": "application/json", ...headers },
    }),
  );
}

describe("Atlas compute preflight input", () => {
  it("accepts and normalizes the bounded request contract", () => {
    expect(
      parseAtlasPreflightRequest({
        problem_id: 86,
        parameter_region: { n: [7, 8], target: 305, exact: true },
        method: "  SAT+DRAT  ",
        hardware_profile: "DGX Spark",
        compute_budget: "48 core-hours",
      }),
    ).toEqual({
      problem_id: 86,
      parameter_region: { n: [7, 8], target: 305, exact: true },
      method: "SAT+DRAT",
      hardware_profile: "DGX Spark",
      compute_budget: "48 core-hours",
    });
  });

  it.each([
    [{}, "problem_id is required"],
    [{ problem_id: 0 }, "problem_id must be an integer"],
    [{ problem_id: 1.5 }, "problem_id must be an integer"],
    [{ problem_id: 1, surprise: true }, "unknown field: surprise"],
    [{ problem_id: 1, method: "" }, "method must not be empty"],
    [{ problem_id: 1, parameter_region: [] }, "parameter_region must be a JSON object"],
    [{ problem_id: 1, parameter_region: { n: Number.MAX_VALUE } }, "parameter_region.n must be a safe integer"],
  ])("rejects invalid request %#", (input, message) => {
    expect(() => parseAtlasPreflightRequest(input)).toThrow(message as string);
  });

  it("bounds nested parameter regions", () => {
    expect(() =>
      parseAtlasPreflightRequest({ problem_id: 1, parameter_region: { a: { b: { c: { d: 1 } } } } }),
    ).toThrow("parameter_region exceeds maximum depth 3");
    expect(() =>
      parseAtlasPreflightRequest({ problem_id: 1, parameter_region: { n: Array.from({ length: 33 }, (_, i) => i) } }),
    ).toThrow("parameter_region.n must contain at most 32 items");
  });

  it("detects duplicate keys after JSON escape decoding", () => {
    expect(() => assertNoDuplicateJsonKeys('{"problem_id":1,"\\u0070roblem_id":2}')).toThrow(
      "duplicate field: problem_id",
    );
    expect(() => assertNoDuplicateJsonKeys('{"problem_id":1,"parameter_region":{"n":7,"n":8}}')).toThrow(
      "duplicate field: n",
    );
  });
});

describe("Atlas compute preflight decisions", () => {
  it("matches compound coverage cells only when every constrained axis is exact", () => {
    const record = {
      axis: "m",
      start: 21,
      end: 21,
      status: "CERTIFIED" as const,
      result: "lower endpoint certified",
      where: { n: 17 },
    };
    expect(coverageRecordMatches(record, { problem_id: 552, parameter_region: { n: 17, m: 21 } })).toBe(true);
    expect(coverageRecordMatches(record, { problem_id: 552, parameter_region: { n: 17, m: 22 } })).toBe(false);
    expect(coverageRecordMatches(record, { problem_id: 552, parameter_region: { n: [16, 18], m: 21 } })).toBe(false);
    expect(coverageRecordMatches(record, { problem_id: 552, parameter_region: { m: 21 } })).toBe(false);
  });

  it("returns UNKNOWN for an unmapped problem without treating absence as clearance", () => {
    const result = computeAtlasPreflight({ problem_id: 999_999 }, FRESH_NOW);
    expect(result).toMatchObject({ decision: "UNKNOWN", reason_code: "UNKNOWN_UNMAPPED", go: false, entry: null });
    expect(result.limitations.campaigns).toMatchObject({ available: false, overlap_checked: false });
  });

  it("stops mapped requests at the deterministic expiry boundary", () => {
    const before = computeAtlasPreflight({ problem_id: 552 }, new Date("2026-07-19T23:59:59.999Z"));
    expect(before.reason_code).toBe("REVIEW_NO_CAMPAIGN_REGISTRY");

    const expired = computeAtlasPreflight({ problem_id: 552 }, new Date("2026-07-20T00:00:00.000Z"));
    expect(expired).toMatchObject({ decision: "STOP", reason_code: "STALE_ATLAS", go: false });
    expect(expired.valid_until).toBe("2026-07-20T00:00:00.000Z");
    expect(expired.snapshot).toMatchObject({
      generated: "2026-07-13",
      max_age_days: 7,
      provenance: { commit: "bd82a0ab34ffe4c33dffba0c402d54b61a5a0103" },
    });
    expect(expired.snapshot.digest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("lets global staleness override an expired snapshot's coverage claims", () => {
    expect(computeAtlasPreflight({ problem_id: 999_999 }, new Date("2026-07-20T00:00:00.000Z"))).toMatchObject({
      decision: "STOP",
      reason_code: "STALE_ATLAS",
      go: false,
      entry: null,
    });
  });

  it("stops NONE and WALL classifications with scoped reasons", () => {
    expect(computeAtlasPreflight({ problem_id: 2 }, FRESH_NOW)).toMatchObject({
      decision: "STOP",
      reason_code: "UNSUPPORTED_NONE",
      go: false,
    });
    expect(computeAtlasPreflight({ problem_id: 138 }, FRESH_NOW)).toMatchObject({
      decision: "STOP",
      reason_code: "SCOPED_WALL",
      go: false,
    });
  });

  it("requires review for HEAVY and UNKNOWN reach entries", () => {
    expect(computeAtlasPreflight({ problem_id: 13 }, FRESH_NOW)).toMatchObject({
      decision: "REVIEW",
      reason_code: "REVIEW_HEAVY_VERIFICATION",
      go: false,
    });
    expect(computeAtlasPreflight({ problem_id: 86 }, FRESH_NOW)).toMatchObject({
      decision: "REVIEW",
      reason_code: "REVIEW_UNKNOWN_REACH",
      go: false,
    });
  });

  it("never upgrades READY+MOVABLE evidence to GO without a campaign registry", () => {
    const result = computeAtlasPreflight(
      {
        problem_id: 552,
        parameter_region: { n: [18, 20] },
        method: "SAT+DRAT",
        hardware_profile: "large cluster",
        compute_budget: "10000 GPU-hours",
      },
      FRESH_NOW,
    );
    expect(result).toMatchObject({
      decision: "REVIEW",
      reason_code: "REVIEW_NO_CAMPAIGN_REGISTRY",
      go: false,
      entry: { id: 552, boardability: "READY", reach: "MOVABLE" },
      limitations: {
        immutable_evidence: { available: true },
        compute_coverage: { available: true },
        campaigns: { available: false, overlap_checked: false },
      },
    });
  });

  it("stops exact repeat compute inside a certified parameter region", () => {
    const result = computeAtlasPreflight({ problem_id: 552, parameter_region: { n: [12, 16] } }, FRESH_NOW);
    expect(result).toMatchObject({
      decision: "STOP",
      reason_code: "CERTIFIED_REGION",
      go: false,
      coverage_matches: [{ axis: "n", start: 12, end: 16, status: "CERTIFIED" }],
      limitations: {
        immutable_evidence: { available: true },
        compute_coverage: { available: true },
      },
    });
  });

  it("requires review when a request partially overlaps certified territory", () => {
    const result = computeAtlasPreflight({ problem_id: 552, parameter_region: { n: [15, 18] } }, FRESH_NOW);
    expect(result).toMatchObject({
      decision: "REVIEW",
      reason_code: "REVIEW_PARTIAL_COVERAGE",
      go: false,
    });
    expect(result.coverage_matches).toHaveLength(2);
    expect(result.coverage_matches).toEqual(expect.arrayContaining([
      expect.objectContaining({ axis: "n", start: 12, end: 16, status: "CERTIFIED" }),
      expect.objectContaining({ axis: "n", start: 17, end: 17, status: "UNKNOWN" }),
    ]));
  });

  it("surfaces the bounded unknown campaign at the open n=17 cell", () => {
    expect(computeAtlasPreflight({ problem_id: 552, parameter_region: { n: 17 } }, FRESH_NOW)).toMatchObject({
      decision: "REVIEW",
      reason_code: "REVIEW_UNKNOWN_COVERAGE",
      go: false,
      coverage_matches: [{ axis: "n", start: 17, end: 17, status: "UNKNOWN" }],
    });
  });
});

describe("POST /api/atlas/preflight", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FRESH_NOW);
  });

  afterEach(() => vi.useRealTimers());

  it("returns a no-store machine decision with snapshot provenance", async () => {
    const response = await post(JSON.stringify({ problem_id: 86, parameter_region: { n: 7 } }));
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store, max-age=0");
    expect(body).toMatchObject({
      decision: "REVIEW",
      reason_code: "REVIEW_UNKNOWN_REACH",
      go: false,
      checked_at: FRESH_NOW.toISOString(),
      snapshot: {
        schema: "p42-erdos-frontier-atlas-v1",
        provenance: { repository: "https://github.com/techno-optimist/erdos-frontier-atlas" },
      },
    });
  });

  it.each([
    ['{"problem_id":86,"problem_id":87}', 400, "duplicate field: problem_id"],
    ['{"problem_id":', 400, "malformed JSON body"],
    [JSON.stringify({ problem_id: 86, unknown: true }), 400, "unknown field: unknown"],
  ])("rejects malformed or ambiguous body %#", async (body, status, message) => {
    const response = await post(body);
    expect(response.status).toBe(status);
    await expect(response.json()).resolves.toEqual({ error: message, code: "INVALID_REQUEST" });
  });

  it("requires the JSON media type", async () => {
    const response = await post('{"problem_id":86}', { "content-type": "text/plain" });
    expect(response.status).toBe(415);
    await expect(response.json()).resolves.toEqual({
      error: "content-type must be application/json",
      code: "INVALID_REQUEST",
    });
  });

  it("rejects declared and streamed bodies over the byte cap", async () => {
    const declared = await post('{"problem_id":86}', { "content-length": String(ATLAS_PREFLIGHT_MAX_BODY_BYTES + 1) });
    expect(declared.status).toBe(413);

    const streamed = await post(
      JSON.stringify({ problem_id: 86, method: "x".repeat(ATLAS_PREFLIGHT_MAX_BODY_BYTES) }),
    );
    expect(streamed.status).toBe(413);
    await expect(streamed.json()).resolves.toEqual({ error: "request body is too large", code: "INVALID_REQUEST" });
  });

  it("rejects invalid UTF-8 as a bounded client error", async () => {
    const response = await POST(
      new Request("http://localhost/api/atlas/preflight", {
        method: "POST",
        body: new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d]),
        headers: { "content-type": "application/json" },
      }),
    );
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "request body must be valid UTF-8",
      code: "INVALID_REQUEST",
    });
  });
});
