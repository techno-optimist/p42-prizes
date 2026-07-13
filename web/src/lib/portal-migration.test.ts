import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("portal database migration", () => {
  it("ignores PostgreSQL 18 NOT NULL catalog constraints", () => {
    const sql = readFileSync(resolve("migrations/001_portal_store.sql"), "utf8");
    const ownedConstraintFilters = sql.match(/AND contype IN \('c', 'p'\);/g) ?? [];

    expect(ownedConstraintFilters).toHaveLength(2);
  });

  it("fails closed on missing, extra, or mis-indexed schema constraints", () => {
    const sql = readFileSync(resolve("migrations/001_portal_store.sql"), "utf8");

    expect(sql.match(/IS DISTINCT FROM ARRAY\[/g)).toHaveLength(2);
    expect(sql).toContain("contype NOT IN ('c', 'p', 'n')");
    expect(sql).toContain("index_meta.indnkeyatts = 1");
    expect(sql).toContain("index_meta.indpred IS NULL");
    expect(sql).toContain("index_meta.indexprs IS NULL");
  });
});
