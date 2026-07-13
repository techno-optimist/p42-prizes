import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const connectionString = process.env.P42_PORTAL_DATABASE_URL?.trim();
if (!connectionString) throw new Error("P42_PORTAL_DATABASE_URL is required for portal database migration");

const sql = await readFile(path.resolve("migrations/001_portal_store.sql"), "utf8");
const pool = new pg.Pool({ connectionString, max: 1, connectionTimeoutMillis: 10_000 });
try {
  await pool.query(sql);
  const result = await pool.query(
    `SELECT
       to_regclass('p42_portal_state') AS state_table,
       to_regclass('p42_rate_limit_bucket') AS rate_table,
       (SELECT name FROM p42_schema_migration WHERE version = 1) AS migration_name`,
  );
  if (!result.rows[0]?.state_table || !result.rows[0]?.rate_table || result.rows[0]?.migration_name !== "portal_store") {
    throw new Error("portal database migration did not create and record the required schema");
  }
  process.stdout.write("portal database schema is ready\n");
} finally {
  await pool.end();
}
