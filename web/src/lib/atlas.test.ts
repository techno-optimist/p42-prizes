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
    expect(first.total).toBe(17);
    expect(first.items).toHaveLength(3);
    expect(first.next_cursor).toEqual(expect.any(String));
    expect(first.items[0].fit_score).toBeGreaterThanOrEqual(first.items[1].fit_score);

    const second = listAtlasEntries({ boardability: "READY", sort: "fit", limit: 3, cursor: first.next_cursor! });
    expect(second.items.map(({ id }) => id)).not.toContain(first.items[0].id);
    expect(() => listAtlasEntries({ boardability: "HEAVY", sort: "fit", limit: 3, cursor: first.next_cursor! }))
      .toThrow("invalid cursor");
  });

  it("treats p42_slug as a five-entry join only", () => {
    const joined = listAtlasEntries({ p42: true, limit: 51 });
    expect(joined.total).toBe(5);
    expect(joined.items.every((entry) => typeof entry.p42_slug === "string")).toBe(true);
    expect(getAtlasMeta().settlement_authority).toBe(false);
  });

  it("reports exact facets and pinned provenance", () => {
    const meta = getAtlasMeta();
    expect(meta.facets.boardability).toEqual({ READY: 17, HEAVY: 11, NONE: 23 });
    expect(meta.facets.p42).toEqual({ true: 5, false: 46 });
    expect(meta.provenance.commit).toBe("f2db29d0c47b61caad80b1a70e68e9702260f5e0");
    expect(meta.provenance.sha256).toBe("a0a7236cde326d57251209f1c8c0e2fb91a18c29747e408a73d2737a506e15c6");
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
});
