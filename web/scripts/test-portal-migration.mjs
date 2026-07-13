import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const connectionString = process.env.P42_PORTAL_DATABASE_URL?.trim();
if (!connectionString) throw new Error("P42_PORTAL_DATABASE_URL is required for migration integration tests");
const migrationSql = await readFile(path.resolve("migrations/001_portal_store.sql"), "utf8");
const admin = new pg.Client({ connectionString, connectionTimeoutMillis: 10_000 });
await admin.connect();

const passed = [];
try {
  await inTemporarySchema("fresh-idempotent", async (client) => {
    await client.query(migrationSql);
    await client.query(migrationSql);
  });

  await inTemporarySchema("missing-primary-key", async (client) => {
    await client.query(migrationSql);
    await client.query("ALTER TABLE p42_portal_state DROP CONSTRAINT p42_portal_state_pkey");
    await expectMigrationFailure(client);
  });

  await inTemporarySchema("unexpected-unique", async (client) => {
    await client.query(migrationSql);
    await client.query("ALTER TABLE p42_portal_state ADD CONSTRAINT unexpected_revision_unique UNIQUE (revision)");
    await expectMigrationFailure(client);
  });

  await inTemporarySchema("wrong-expiry-index", async (client) => {
    await client.query(migrationSql);
    await client.query("DROP INDEX p42_rate_limit_bucket_expiry_idx");
    await client.query("CREATE INDEX p42_rate_limit_bucket_expiry_idx ON p42_rate_limit_bucket (count)");
    await expectMigrationFailure(client);
  });

  await inTemporarySchema("fresh-failure-rolls-back", async (client) => {
    await client.query(`CREATE TABLE p42_rate_limit_bucket (
      policy_id text NOT NULL,
      subject text NOT NULL,
      count integer NOT NULL CHECK (count > 0),
      expires_at timestamptz NOT NULL,
      PRIMARY KEY (policy_id, subject)
    )`);
    await client.query("CREATE INDEX p42_rate_limit_bucket_expiry_idx ON p42_rate_limit_bucket (count)");
    await expectMigrationFailure(client);
    const result = await client.query(
      "SELECT to_regclass('p42_portal_state') AS state_table, to_regclass('p42_schema_migration') AS migration_table",
    );
    if (result.rows[0].state_table || result.rows[0].migration_table) {
      throw new Error("failed fresh migration left partial tables behind");
    }
  });

  process.stdout.write(`${JSON.stringify({
    schemaVersion: "p42-portal-migration-integration/v1",
    status: "passed",
    postgresVersion: (await admin.query("SHOW server_version")).rows[0].server_version,
    cases: passed,
  })}\n`);
} finally {
  await admin.end();
}

async function inTemporarySchema(label, operation) {
  const schema = `p42_migration_test_${randomUUID().replaceAll("-", "")}`;
  const identifier = quoteIdentifier(schema);
  await admin.query(`CREATE SCHEMA ${identifier}`);
  const client = new pg.Client({ connectionString, connectionTimeoutMillis: 10_000 });
  try {
    await client.connect();
    await client.query(`SET search_path TO ${identifier}`);
    await operation(client);
    passed.push(label);
  } finally {
    await client.end().catch(() => {});
    await admin.query(`DROP SCHEMA IF EXISTS ${identifier} CASCADE`);
  }
}

async function expectMigrationFailure(client) {
  try {
    await client.query(migrationSql);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    if (error instanceof Error && error.message.includes("do not match migration 1")) return;
    throw error;
  }
  throw new Error("malformed portal schema unexpectedly passed migration validation");
}

function quoteIdentifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}
