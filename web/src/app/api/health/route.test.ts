import { afterEach, describe, expect, it } from "vitest";
import { GET } from "@/app/api/health/route";
import {
  resetPortalDatabasePoolForTests,
  setPortalDatabasePoolForTests,
} from "@/lib/portal-db";

function result(rows: unknown[]) {
  return { rows, rowCount: rows.length, command: "SELECT", oid: 0, fields: [] } as never;
}

afterEach(async () => {
  await resetPortalDatabasePoolForTests();
  delete process.env.P42_PORTAL_DATABASE_SCHEMA;
});

describe("portal health", () => {
  it("reports ready only for the configured schema and singleton state", async () => {
    process.env.P42_PORTAL_DATABASE_SCHEMA = "p42_portal";
    setPortalDatabasePoolForTests({
      connect: async () => { throw new Error("unused"); },
      query: async () => result([{ schema_name: "p42_portal", singleton_count: 1 }]),
    });

    const response = await GET();
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ status: "ok", database: "ready" });
  });

  it.each([
    [[], "missing row"],
    [[{ schema_name: "public", singleton_count: 1 }], "wrong schema"],
    [[{ schema_name: "p42_portal", singleton_count: 0 }], "missing singleton"],
  ])("fails closed for %s", async (rows) => {
    process.env.P42_PORTAL_DATABASE_SCHEMA = "p42_portal";
    setPortalDatabasePoolForTests({
      connect: async () => { throw new Error("unused"); },
      query: async () => result(rows),
    });

    const response = await GET();
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      status: "unavailable",
      database: "unavailable",
    });
  });

  it("fails closed when the database query fails", async () => {
    process.env.P42_PORTAL_DATABASE_SCHEMA = "p42_portal";
    setPortalDatabasePoolForTests({
      connect: async () => { throw new Error("unused"); },
      query: async () => { throw new Error("database unavailable"); },
    });

    const response = await GET();
    expect(response.status).toBe(503);
  });
});
