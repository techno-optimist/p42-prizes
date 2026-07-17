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

  it("preseeds and strictly validates the durable checkpoint lock row", () => {
    const sql = readFileSync(resolve("migrations/002_indexer_checkpoint_high_water.sql"), "utf8");

    expect(sql).toContain("INSERT INTO p42_indexer_checkpoint_high_water (singleton)");
    expect(sql).toContain("p42_indexer_checkpoint_high_water_complete");
    expect(sql).toContain("existing P42 indexer checkpoint high-water table does not match migration 2");
    expect(sql).toContain("version = 2 AND name = 'indexer_checkpoint_high_water'");
  });

  it("applies and verifies both migrations in production order", () => {
    const runner = readFileSync(resolve("scripts/migrate-portal-db.mjs"), "utf8");

    expect(runner).toContain('"001_portal_store.sql"');
    expect(runner).toContain('"002_indexer_checkpoint_high_water.sql"');
    expect(runner).toContain("for (const migration of migrations) await pool.query(migration.sql)");
    expect(runner).toContain("row.migration_2_name !== \"indexer_checkpoint_high_water\"");
    expect(runner).toContain("row.high_water_rows !== 1");
  });
});
