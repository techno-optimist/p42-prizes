import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const connectionString = process.env.P42_PORTAL_DATABASE_URL?.trim();
if (!connectionString) throw new Error("P42_PORTAL_DATABASE_URL is required for portal database migration");

const migrations = await Promise.all([
  "001_portal_store.sql",
  "002_indexer_checkpoint_high_water.sql",
].map(async (name) => ({ name, sql: await readFile(path.resolve("migrations", name), "utf8") })));
const pool = new pg.Pool({ connectionString, max: 1, connectionTimeoutMillis: 10_000 });
try {
  for (const migration of migrations) await pool.query(migration.sql);
  const result = await pool.query(
    `SELECT
       to_regclass('p42_portal_state') AS state_table,
       to_regclass('p42_rate_limit_bucket') AS rate_table,
       to_regclass('p42_indexer_checkpoint_high_water') AS high_water_table,
       (SELECT name FROM p42_schema_migration WHERE version = 1) AS migration_1_name,
       (SELECT name FROM p42_schema_migration WHERE version = 2) AS migration_2_name,
       (SELECT count(*)::integer FROM p42_indexer_checkpoint_high_water WHERE singleton = true) AS high_water_rows`,
  );
  const row = result.rows[0];
  if (!row?.state_table || !row?.rate_table || !row?.high_water_table
    || row.migration_1_name !== "portal_store"
    || row.migration_2_name !== "indexer_checkpoint_high_water"
    || row.high_water_rows !== 1) {
    throw new Error("portal database migration did not create and record the required schema");
  }
  process.stdout.write("portal database schema is ready\n");
} finally {
  await pool.end();
}
