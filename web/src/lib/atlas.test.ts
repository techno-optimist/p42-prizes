import { describe, expect, it } from "vitest";

import {
  AtlasQueryError,
  atlasEntries,
  getAtlasEntry,
  getAtlasMeta,
  listAtlasEntries,
  normalizeFrontier,
  parseAtlasListQuery,
} from "@/lib/atlas";

describe("Erdős frontier atlas", () => {
  it("loads all 51 pinned entries with unique numeric ids", () => {
    expect(atlasEntries).toHaveLength(51);
    expect(new Set(atlasEntries.map(({ id }) => id)).size).toBe(51);
  });

  it("normalizes string and structured frontiers without inventing fields", () => {
    expect(normalizeFrontier("  14 <= q(6) <= 18  ")).toEqual({ summary: "14 <= q(6) <= 18" });
    expect(normalizeFrontier({ value: "x >= 4", holder: "A. Author", year: 2025 })).toEqual({
      summary: "x >= 4",
      value: "x >= 4",
      holder: "A. Author",
      year: 2025,
    });
    expect(normalizeFrontier(null)).toBeUndefined();
    expect(getAtlasEntry(1)).not.toHaveProperty("evidence");
    expect(getAtlasEntry(1)).not.toHaveProperty("compute");
  });

  it("filters, sorts, and paginates deterministically", () => {
    const first = listAtlasEntries({ boardability: "READY", sort: "fit", limit: 3 });
    expect(first.total).toBe(13);
    expect(first.items).toHaveLength(3);
    expect(first.next_cursor).toEqual(expect.any(String));
    expect(first.items[0].fit_score).toBeGreaterThanOrEqual(first.items[1].fit_score);

    const second = listAtlasEntries({ boardability: "READY", sort: "fit", limit: 3, cursor: first.next_cursor! });
    expect(second.items.map(({ id }) => id)).not.toContain(first.items[0].id);
    expect(() => listAtlasEntries({ boardability: "HEAVY", sort: "fit", limit: 3, cursor: first.next_cursor! }))
      .toThrow("invalid cursor");
  });

  it("treats p42_slug as a six-entry join only", () => {
    const joined = listAtlasEntries({ p42: true, limit: 51 });
    expect(joined.total).toBe(6);
    expect(joined.items.every((entry) => typeof entry.p42_slug === "string")).toBe(true);
    expect(getAtlasMeta().settlement_authority).toBe(false);
  });

  it("reports exact facets and pinned provenance", () => {
    const meta = getAtlasMeta();
    expect(meta.facets.boardability).toEqual({ READY: 13, HEAVY: 14, NONE: 24 });
    expect(meta.facets.p42).toEqual({ true: 6, false: 45 });
    expect(meta.provenance.commit).toBe("0901734c487ab1e51ddc772ab45b08b42c86fc2c");
    expect(meta.provenance.sha256).toBe("cd1222e90a31d53c5d58549322eb211cfb9e5478d75e9230031141fdad940864");
    expect(getAtlasEntry(67)?.frontier?.summary).toContain("130,000");
    expect(getAtlasEntry(552)).toMatchObject({
      frontier: { summary: expect.stringContaining("a(12..16)") },
      evidence: { status: "verified", digest: "sha256:6fad85db5cc5925f5a5894446c56720433065652fecb284a1340262a70a914d3" },
      compute: { schema: "p42-atlas-compute-v1", coverage: expect.any(Array) },
    });
    expect(getAtlasEntry(21)?.lane).toBe("exact-backtracking");
  });

  it("parses supported query values and rejects ambiguous ones", () => {
    expect(parseAtlasListQuery(new URLSearchParams("reach=WALL&p42=false&limit=10"))).toMatchObject({
      reach: "WALL",
      p42: false,
      limit: 10,
    });
    expect(() => parseAtlasListQuery(new URLSearchParams("boardability=ready"))).toThrow(AtlasQueryError);
    expect(() => parseAtlasListQuery(new URLSearchParams("p42=1"))).toThrow("invalid p42");
    expect(() => parseAtlasListQuery(new URLSearchParams("limit=10&limit=11"))).toThrow("only be supplied once");
    expect(() => listAtlasEntries({ cursor: "not-a-cursor" })).toThrow("invalid cursor");
  });

  it("searches source text case-insensitively", () => {
    const result = listAtlasEntries({ q: "distinct subset sums", limit: 51 });
    expect(result.items.some(({ id }) => id === 1)).toBe(true);
  });

  it("recommends only movable, unpackaged entries", () => {
    const result = listAtlasEntries({ boardability: "READY", reach: "MOVABLE", p42: false, limit: 51 });
    expect(result.items).toEqual([]);
    expect(result.items.every(({ beatable, p42_slug }) => beatable === "MOVABLE" && p42_slug === undefined)).toBe(true);
  });
});
