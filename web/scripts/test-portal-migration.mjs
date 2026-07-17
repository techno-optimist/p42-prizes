import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const connectionString = process.env.P42_PORTAL_DATABASE_URL?.trim();
if (!connectionString) throw new Error("P42_PORTAL_DATABASE_URL is required for migration integration tests");
const migration1Sql = await readFile(path.resolve("migrations/001_portal_store.sql"), "utf8");
const migration2Sql = await readFile(path.resolve("migrations/002_indexer_checkpoint_high_water.sql"), "utf8");
const admin = new pg.Client({ connectionString, connectionTimeoutMillis: 10_000 });
await admin.connect();

const passed = [];
try {
  await inTemporarySchema("fresh-idempotent", async (client) => {
    await applyMigrations(client);
    await applyMigrations(client);
    const highWater = await client.query(
      `SELECT count(*)::integer AS rows,
              count(finalized_block_number)::integer AS initialized
         FROM p42_indexer_checkpoint_high_water
        WHERE singleton = true`,
    );
    if (highWater.rows[0].rows !== 1 || highWater.rows[0].initialized !== 0) {
      throw new Error("fresh high-water singleton was not preseeded in the uninitialized state");
    }
  });

  await inTemporarySchema("missing-primary-key", async (client) => {
    await applyMigrations(client);
    await client.query("ALTER TABLE p42_portal_state DROP CONSTRAINT p42_portal_state_pkey");
    await expectMigrationFailure(client, migration1Sql, "do not match migration 1");
  });

  await inTemporarySchema("unexpected-unique", async (client) => {
    await applyMigrations(client);
    await client.query("ALTER TABLE p42_portal_state ADD CONSTRAINT unexpected_revision_unique UNIQUE (revision)");
    await expectMigrationFailure(client, migration1Sql, "do not match migration 1");
  });

  await inTemporarySchema("wrong-expiry-index", async (client) => {
    await applyMigrations(client);
    await client.query("DROP INDEX p42_rate_limit_bucket_expiry_idx");
    await client.query("CREATE INDEX p42_rate_limit_bucket_expiry_idx ON p42_rate_limit_bucket (count)");
    await expectMigrationFailure(client, migration1Sql, "do not match migration 1");
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
    await expectMigrationFailure(client, migration1Sql, "do not match migration 1");
    const result = await client.query(
      "SELECT to_regclass('p42_portal_state') AS state_table, to_regclass('p42_schema_migration') AS migration_table",
    );
    if (result.rows[0].state_table || result.rows[0].migration_table) {
      throw new Error("failed fresh migration left partial tables behind");
    }
  });

  await inTemporarySchema("high-water-missing-completeness-constraint", async (client) => {
    await applyMigrations(client);
    await client.query(
      "ALTER TABLE p42_indexer_checkpoint_high_water DROP CONSTRAINT p42_indexer_checkpoint_high_water_complete",
    );
    await expectMigrationFailure(client, migration2Sql, "does not match migration 2");
  });

  await inTemporarySchema("high-water-weakened-hash-constraint", async (client) => {
    await applyMigrations(client);
    await client.query(
      `ALTER TABLE p42_indexer_checkpoint_high_water
         DROP CONSTRAINT p42_indexer_checkpoint_high_water_finalized_block_hash_check,
         ADD CONSTRAINT p42_indexer_checkpoint_high_water_finalized_block_hash_check
           CHECK (finalized_block_hash IS NULL OR length(finalized_block_hash) > 0)`,
    );
    await expectMigrationFailure(client, migration2Sql, "does not match migration 2");
  });

  await inTemporarySchema("high-water-wrong-migration-name", async (client) => {
    await client.query(migration1Sql);
    await client.query("INSERT INTO p42_schema_migration (version, name) VALUES (2, 'wrong_name')");
    await expectMigrationFailure(client, migration2Sql, "version 2 is bound to another name");
  });

  await inTemporarySchema("high-water-failure-rolls-back", async (client) => {
    await client.query(migration1Sql);
    await client.query("CREATE TABLE p42_indexer_checkpoint_high_water (singleton boolean PRIMARY KEY)");
    await expectMigrationFailure(client, migration2Sql, "does not match migration 2");
    const result = await client.query(
      `SELECT count(*)::integer AS columns,
              (SELECT count(*)::integer FROM p42_schema_migration WHERE version = 2) AS migration_rows
         FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'p42_indexer_checkpoint_high_water'`,
    );
    if (result.rows[0].columns !== 1 || result.rows[0].migration_rows !== 0) {
      throw new Error("failed high-water migration left partial schema behind");
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

async function applyMigrations(client) {
  await client.query(migration1Sql);
  await client.query(migration2Sql);
}

async function expectMigrationFailure(client, sql, expectedMessage) {
  try {
    await client.query(sql);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    if (error instanceof Error && error.message.includes(expectedMessage)) return;
    throw error;
  }
  throw new Error("malformed portal schema unexpectedly passed migration validation");
}

function quoteIdentifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}
