import { describe, expect, it } from "vitest";

import { GET as detailGet } from "@/app/api/atlas/[id]/route";
import { GET as metaGet } from "@/app/api/atlas/meta/route";
import { GET as listGet } from "@/app/api/atlas/route";
import { GET as exportGet } from "@/app/api/atlas/export/route";

describe("atlas API routes", () => {
  it("exports the complete revalidated snapshot with a reproducible digest", async () => {
    const first = await exportGet();
    const second = await exportGet();
    const body = await first.text();
    const parsed = JSON.parse(body);

    expect(parsed.entries).toHaveLength(51);
    expect(parsed.meta.total).toBe(51);
    expect(first.headers.get("cache-control")).toBe("public, max-age=0, must-revalidate");
    expect(first.headers.get("content-disposition")).toContain("p42-erdos-atlas-v1.json");
    expect(first.headers.get("x-content-sha256")).toMatch(/^[a-f0-9]{64}$/);
    expect(second.headers.get("x-content-sha256")).toBe(first.headers.get("x-content-sha256"));
  });

  it("serves a filtered list with bounded revalidation", async () => {
    const response = await listGet(new Request("http://localhost/api/atlas?boardability=HEAVY&limit=2"));
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(body.total).toBe(14);
    expect(body.items).toHaveLength(2);
    expect(response.headers.get("cache-control")).toBe("public, max-age=60, s-maxage=300, must-revalidate");
  });

  it("returns 400 for invalid list filters", async () => {
    const response = await listGet(new Request("http://localhost/api/atlas?limit=999"));
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "limit must be between 1 and 51" });
  });

  it("rejects unknown and repeated query parameters", async () => {
    const unknown = await listGet(new Request("http://localhost/api/atlas?nonce=cache-bust"));
    expect(unknown.status).toBe(400);
    await expect(unknown.json()).resolves.toEqual({ error: "unknown query parameter: nonce" });

    const repeated = await listGet(new Request("http://localhost/api/atlas?limit=1&limit=2"));
    expect(repeated.status).toBe(400);
    await expect(repeated.json()).resolves.toEqual({ error: "limit may only be supplied once" });
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
