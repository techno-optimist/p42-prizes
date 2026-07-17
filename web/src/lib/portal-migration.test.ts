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

  it("preseeds control and exactly validates control and append-only history constraints", () => {
    const sql = readFileSync(resolve("migrations/002_indexer_checkpoint_high_water.sql"), "utf8");

    expect(sql).toContain("INSERT INTO p42_indexer_checkpoint_control (singleton)");
    expect(sql).toContain("p42_indexer_checkpoint_control_state_complete:CHECK");
    expect(sql).toContain("p42_indexer_checkpoint_acceptance_block_hash_format:CHECK");
    expect(sql).toContain("SECURITY DEFINER");
    expect(sql).toContain("SET search_path = pg_catalog");
    expect(sql).toContain("transition_function_source");
    expect(sql).toContain("exact_read_function_source");
    expect(sql).toContain("p42_read_exact_indexer_checkpoint");
    expect(sql).toContain("ORDER BY e.epoch_id DESC LIMIT 1");
    expect(sql).toContain("ORDER BY a.acceptance_id DESC LIMIT 1");
    expect(sql).toContain("existing checkpoint historical full identity replay");
    expect(sql).toContain("existing checkpoint semantic history regresses at acceptance");
    expect(sql).toContain("checkpoint control does not match immutable history maxima");
    expect(sql).toContain("has_function_privilege('public', function_row.function_oid, 'EXECUTE')");
    expect(sql).toContain("existing P42 indexer checkpoint epoch schema does not match migration 2");
    expect(sql).toContain("version=2 AND name='indexer_checkpoint_epoch_high_water'");
  });

  it("applies and verifies both migrations in production order", () => {
    const runner = readFileSync(resolve("scripts/migrate-portal-db.mjs"), "utf8");

    expect(runner).toContain('"001_portal_store.sql"');
    expect(runner).toContain('"002_indexer_checkpoint_high_water.sql"');
    expect(runner).toContain("for (const migration of migrations) await owner.query(migration.sql)");
    expect(runner).toContain("P42_PORTAL_MIGRATION_DATABASE_URL");
    expect(runner).toContain("ownerIdentity.role === runtimeIdentity.role");
    expect(runner).toContain("P42_PORTAL_DATABASE_SCHEMA");
    expect(runner).toContain("REVOKE ALL ON ${highWaterRelations} FROM ${runtimeRole}");
    expect(runner).toContain("GRANT EXECUTE ON FUNCTION ${functionIdentity} TO ${runtimeRole}");
    expect(runner).toContain("GRANT EXECUTE ON FUNCTION ${exactFunctionIdentity} TO ${runtimeRole}");
    expect(runner).toContain("pg_catalog.pg_has_role(r.oid,candidate.oid,'SET')");
    expect(runner).toContain("AS no_direct_writes");
    expect(runner).toContain("AS no_external_triggers");
    expect(runner).toContain('["INSERT", "UPDATE", "DELETE", "TRUNCATE", "TRIGGER"]');
    expect(runner).toContain("row.migration_2_name !== \"indexer_checkpoint_epoch_high_water\"");
    expect(runner).toContain("row.control_rows !== 1");
  });

  it("replaces the migration shell before starting the runtime process", () => {
    const render = readFileSync(resolve("../render.yaml"), "utf8");

    expect(render).toContain(
      "startCommand: npm run db:migrate && exec env -u P42_PORTAL_MIGRATION_DATABASE_URL npm run start:prizes",
    );
    expect(render).not.toContain("&& unset P42_PORTAL_MIGRATION_DATABASE_URL &&");
  });

  it("keeps unchanged checkpoint reads on indexed maxima without history scans", () => {
    const sql = readFileSync(resolve("migrations/002_indexer_checkpoint_high_water.sql"), "utf8");
    const exact = sql.split("CREATE OR REPLACE FUNCTION %1$I.p42_read_exact_indexer_checkpoint")[1]
      ?.split("$exact_function$")[1] ?? "";
    expect(exact).toContain("FOR SHARE");
    expect(exact).toContain("ORDER BY e.epoch_id DESC LIMIT 1");
    expect(exact).toContain("ORDER BY a.acceptance_id DESC LIMIT 1");
    expect(exact).not.toContain("count(*)");
    expect(exact).not.toContain("FOR UPDATE");
  });

  it("observes held exact reads in flight and enforces their release ceiling", () => {
    const rehearsal = readFileSync(resolve("scripts/rehearse-portal-db.mjs"), "utf8");
    expect(rehearsal).toContain("pg_advisory_xact_lock_shared");
    expect(rehearsal).toContain("pg_stat_activity");
    expect(rehearsal).toContain("transitionBlockedByExactReaders<1");
    expect(rehearsal).toContain("exactReadBlockingPids!==0");
    expect(rehearsal).toContain("exactReadReleaseLatencyCeilingMilliseconds = 2_000");
    expect(rehearsal).toContain("exactReadReleaseMilliseconds>exactReadReleaseLatencyCeilingMilliseconds");
  });
});
