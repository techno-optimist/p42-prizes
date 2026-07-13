import { describe, expect, it } from "vitest";

import { GET as detailGet } from "@/app/api/atlas/[id]/route";
import { GET as metaGet } from "@/app/api/atlas/meta/route";
import { GET as listGet } from "@/app/api/atlas/route";

describe("atlas API routes", () => {
  it("serves a filtered list with immutable snapshot caching", async () => {
    const response = await listGet(new Request("http://localhost/api/atlas?boardability=HEAVY&limit=2"));
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(body.total).toBe(11);
    expect(body.items).toHaveLength(2);
    expect(response.headers.get("cache-control")).toContain("immutable");
  });

  it("returns 400 for invalid list filters", async () => {
    const response = await listGet(new Request("http://localhost/api/atlas?limit=999"));
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "limit must be between 1 and 51" });
  });

  it("serves detail only for numeric Erdős ids", async () => {
    const found = await detailGet(new Request("http://localhost/api/atlas/21"), {
      params: Promise.resolve({ id: "21" }),
    });
    expect(found.status).toBe(200);
    expect((await found.json()).id).toBe(21);

    const invalid = await detailGet(new Request("http://localhost/api/atlas/nope"), {
      params: Promise.resolve({ id: "nope" }),
    });
    expect(invalid.status).toBe(400);

    const missing = await detailGet(new Request("http://localhost/api/atlas/999999"), {
      params: Promise.resolve({ id: "999999" }),
    });
    expect(missing.status).toBe(404);
  });

  it("serves counts, facets, and provenance metadata", async () => {
    const response = await metaGet();
    const body = await response.json();
    expect(body.total).toBe(51);
    expect(body.facets.reach.MOVABLE + body.facets.reach.UNKNOWN + body.facets.reach.WALL).toBe(51);
    expect(body.provenance.license).toBe("MIT");
    expect(body.settlement_authority).toBe(false);
  });
});
