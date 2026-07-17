import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const migrationUrl = process.env.P42_PORTAL_MIGRATION_DATABASE_URL?.trim();
const runtimeUrl = process.env.P42_PORTAL_DATABASE_URL?.trim();
if (!migrationUrl) throw new Error("P42_PORTAL_MIGRATION_DATABASE_URL is required for portal database migration");
if (!runtimeUrl) throw new Error("P42_PORTAL_DATABASE_URL is required to provision and verify the runtime role");
if (migrationUrl === runtimeUrl) throw new Error("portal migration and runtime database URLs must be distinct");

const migrations = await Promise.all([
  "001_portal_store.sql", "002_indexer_checkpoint_high_water.sql",
].map(async (name) => ({ name, sql: await readFile(path.resolve("migrations", name), "utf8") })));
const owner = new pg.Pool({ connectionString: migrationUrl, max: 1, connectionTimeoutMillis: 10_000 });
const runtime = new pg.Pool({ connectionString: runtimeUrl, max: 1, connectionTimeoutMillis: 10_000 });
try {
  for (const migration of migrations) await owner.query(migration.sql);
  const ownerIdentity = (await owner.query("SELECT current_user AS role, current_schema() AS schema")).rows[0];
  const runtimeIdentity = (await runtime.query("SELECT current_user AS role")).rows[0];
  if (!ownerIdentity?.role || !runtimeIdentity?.role || ownerIdentity.role === runtimeIdentity.role) {
    throw new Error("portal migration and runtime connections must authenticate as different roles");
  }
  const ownership = await owner.query(`SELECT count(*)::integer AS owned
    FROM pg_class WHERE oid IN (
      'p42_portal_state'::regclass, 'p42_rate_limit_bucket'::regclass,
      'p42_schema_migration'::regclass, 'p42_indexer_checkpoint_control'::regclass,
      'p42_indexer_checkpoint_epoch'::regclass, 'p42_indexer_checkpoint_acceptance'::regclass
    ) AND pg_get_userbyid(relowner) = current_user`);
  if (ownership.rows[0]?.owned !== 6) throw new Error("migration role must own every portal table");

  const runtimeRole = quoteIdentifier(runtimeIdentity.role);
  const schema = quoteIdentifier(ownerIdentity.schema);
  await owner.query(`GRANT USAGE ON SCHEMA ${schema} TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT, INSERT, UPDATE ON p42_portal_state TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON p42_rate_limit_bucket TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT ON p42_schema_migration TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT, UPDATE ON p42_indexer_checkpoint_control TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT, INSERT ON p42_indexer_checkpoint_epoch TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT, INSERT ON p42_indexer_checkpoint_acceptance TO ${runtimeRole}`);

  const verification = await runtime.query(`SELECT
    to_regclass('p42_portal_state') IS NOT NULL AS state_table,
    to_regclass('p42_rate_limit_bucket') IS NOT NULL AS rate_table,
    to_regclass('p42_indexer_checkpoint_control') IS NOT NULL AS control_table,
    to_regclass('p42_indexer_checkpoint_epoch') IS NOT NULL AS epoch_table,
    to_regclass('p42_indexer_checkpoint_acceptance') IS NOT NULL AS acceptance_table,
    (SELECT name FROM p42_schema_migration WHERE version=1) AS migration_1_name,
    (SELECT name FROM p42_schema_migration WHERE version=2) AS migration_2_name,
    (SELECT count(*)::integer FROM p42_indexer_checkpoint_control WHERE singleton=true) AS control_rows,
    has_schema_privilege(current_user, current_schema(), 'CREATE') AS can_create,
    has_table_privilege(current_user, 'p42_indexer_checkpoint_control', 'TRIGGER') AS can_trigger_control,
    has_table_privilege(current_user, 'p42_indexer_checkpoint_epoch', 'TRIGGER') AS can_trigger_epoch,
    has_table_privilege(current_user, 'p42_indexer_checkpoint_acceptance', 'TRIGGER') AS can_trigger_acceptance,
    has_table_privilege(current_user, 'p42_indexer_checkpoint_epoch', 'UPDATE') AS can_update_epoch,
    has_table_privilege(current_user, 'p42_indexer_checkpoint_acceptance', 'UPDATE') AS can_update_acceptance,
    has_table_privilege(current_user, 'p42_indexer_checkpoint_control', 'INSERT') AS can_insert_control,
    has_table_privilege(current_user, 'p42_indexer_checkpoint_control', 'DELETE') AS can_delete_control,
    has_table_privilege(current_user, 'p42_indexer_checkpoint_epoch', 'DELETE') AS can_delete_epoch,
    has_table_privilege(current_user, 'p42_indexer_checkpoint_acceptance', 'DELETE') AS can_delete_acceptance,
    EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid IN (
      'p42_indexer_checkpoint_control'::regclass, 'p42_indexer_checkpoint_epoch'::regclass,
      'p42_indexer_checkpoint_acceptance'::regclass
    ) AND NOT tgisinternal) AS external_triggers,
    EXISTS (SELECT 1 FROM pg_class WHERE oid IN (
      'p42_indexer_checkpoint_control'::regclass, 'p42_indexer_checkpoint_epoch'::regclass,
      'p42_indexer_checkpoint_acceptance'::regclass
    ) AND pg_get_userbyid(relowner)=current_user) AS owns_high_water`);
  const row = verification.rows[0];
  if (!row?.state_table || !row?.rate_table || !row?.control_table || !row?.epoch_table || !row?.acceptance_table
    || row.migration_1_name !== "portal_store" || row.migration_2_name !== "indexer_checkpoint_epoch_high_water"
    || row.control_rows !== 1 || row.can_create || row.can_trigger_control || row.can_trigger_epoch
    || row.can_trigger_acceptance || row.can_update_epoch || row.can_update_acceptance
    || row.can_insert_control || row.can_delete_control || row.can_delete_epoch || row.can_delete_acceptance
    || row.external_triggers || row.owns_high_water) {
    throw new Error("portal runtime role failed least-privilege schema verification");
  }
  process.stdout.write("portal database schema and least-privilege runtime grants are ready\n");
} finally {
  await runtime.end(); await owner.end();
}

function quoteIdentifier(value) { return `"${value.replaceAll('"', '""')}"`; }
