import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const migrationUrl = process.env.P42_PORTAL_MIGRATION_DATABASE_URL?.trim();
const runtimeUrl = process.env.P42_PORTAL_DATABASE_URL?.trim();
const targetSchema = process.env.P42_PORTAL_DATABASE_SCHEMA?.trim();
if (!migrationUrl) throw new Error("P42_PORTAL_MIGRATION_DATABASE_URL is required for portal database migration");
if (!runtimeUrl) throw new Error("P42_PORTAL_DATABASE_URL is required to provision and verify the runtime role");
if (!targetSchema || !/^[a-z][a-z0-9_]{0,62}$/.test(targetSchema)) {
  throw new Error("P42_PORTAL_DATABASE_SCHEMA must name the preprovisioned production schema");
}
if (migrationUrl === runtimeUrl) throw new Error("portal migration and runtime database URLs must be distinct");

const migrations = await Promise.all([
  "001_portal_store.sql", "002_indexer_checkpoint_high_water.sql",
].map(async (name) => ({ name, sql: await readFile(path.resolve("migrations", name), "utf8") })));
const ownerPool = new pg.Pool({ connectionString: migrationUrl, max: 1, connectionTimeoutMillis: 10_000 });
const runtimePool = new pg.Pool({ connectionString: runtimeUrl, max: 1, connectionTimeoutMillis: 10_000 });
const owner = await ownerPool.connect();
const runtime = await runtimePool.connect();
const schema = quoteIdentifier(targetSchema);
const relation = (name) => `${schema}.${name}`;
const functionIdentity = `${schema}.p42_transition_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)`;
const exactFunctionIdentity = `${schema}.p42_read_exact_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)`;

try {
  const ownerIdentity = (await owner.query(`SELECT current_user AS role, current_user::regrole::oid AS role_oid,
    current_database() AS database, (SELECT datdba FROM pg_catalog.pg_database WHERE datname=current_database()) AS database_owner_oid`)).rows[0];
  const runtimeIdentity = (await runtime.query("SELECT current_user AS role, current_user::regrole::oid AS role_oid, current_database() AS database")).rows[0];
  if (!ownerIdentity?.role || !runtimeIdentity?.role || ownerIdentity.role === runtimeIdentity.role) {
    throw new Error("portal migration and runtime connections must authenticate as different roles");
  }
  if (ownerIdentity.database !== runtimeIdentity.database) throw new Error("portal migration and runtime roles must use the same database");
  if (ownerIdentity.database_owner_oid !== ownerIdentity.role_oid) throw new Error("migration role must own the pinned portal database");

  const schemaIdentity = await owner.query(`SELECT n.oid, n.nspowner FROM pg_catalog.pg_namespace AS n WHERE n.nspname=$1`, [targetSchema]);
  if (schemaIdentity.rowCount !== 1 || schemaIdentity.rows[0].nspowner !== ownerIdentity.role_oid) {
    throw new Error("migration role must own the preprovisioned portal schema");
  }
  await owner.query("SELECT set_config('search_path',$1,false)", [schema]);
  for (const migration of migrations) await owner.query(migration.sql);

  const ownedObjects = await owner.query(`SELECT count(*)::integer AS owned FROM pg_catalog.pg_class AS c
    WHERE c.oid IN (${[
      "p42_portal_state", "p42_rate_limit_bucket", "p42_schema_migration",
      "p42_indexer_checkpoint_authority", "p42_indexer_checkpoint_control",
      "p42_indexer_checkpoint_epoch", "p42_indexer_checkpoint_acceptance",
    ].map((name) => `'${targetSchema}.${name}'::regclass`).join(",")}) AND c.relowner=$1`, [ownerIdentity.role_oid]);
  if (ownedObjects.rows[0]?.owned !== 7) throw new Error("migration role must own every pinned portal table");

  const runtimeRole = quoteIdentifier(runtimeIdentity.role);
  const highWaterRelations = [
    relation("p42_indexer_checkpoint_authority"), relation("p42_indexer_checkpoint_control"),
    relation("p42_indexer_checkpoint_epoch"), relation("p42_indexer_checkpoint_acceptance"),
  ].join(", ");
  await owner.query(`REVOKE ALL ON ${highWaterRelations} FROM PUBLIC`);
  await owner.query(`REVOKE ALL ON ${highWaterRelations} FROM ${runtimeRole}`);
  await owner.query(`REVOKE ALL ON FUNCTION ${functionIdentity} FROM PUBLIC`);
  await owner.query(`REVOKE ALL ON FUNCTION ${functionIdentity} FROM ${runtimeRole}`);
  await owner.query(`REVOKE ALL ON FUNCTION ${exactFunctionIdentity} FROM PUBLIC`);
  await owner.query(`REVOKE ALL ON FUNCTION ${exactFunctionIdentity} FROM ${runtimeRole}`);
  await owner.query(`GRANT USAGE ON SCHEMA ${schema} TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT, INSERT, UPDATE ON ${relation("p42_portal_state")} TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ${relation("p42_rate_limit_bucket")} TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT ON ${relation("p42_schema_migration")} TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT ON ${highWaterRelations} TO ${runtimeRole}`);
  await owner.query(`GRANT EXECUTE ON FUNCTION ${functionIdentity} TO ${runtimeRole}`);
  await owner.query(`GRANT EXECUTE ON FUNCTION ${exactFunctionIdentity} TO ${runtimeRole}`);

  await runtime.query("SELECT set_config('search_path','pg_catalog',false)");
  const verification = await runtime.query(runtimeVerificationSql(targetSchema), [targetSchema]);
  const row = verification.rows[0];
  if (verification.rowCount !== 1 || !row.identity_matches || !row.function_matches || !row.acl_matches
    || !row.safe_role || !row.no_direct_writes || !row.no_dangerous_set_role || !row.no_external_triggers
    || row.control_rows !== 1 || row.migration_1_name !== "portal_store"
    || row.migration_2_name !== "indexer_checkpoint_epoch_high_water") {
    throw new Error("portal runtime role failed pinned least-privilege authority verification");
  }
  process.stdout.write("portal database schema and pinned least-privilege transition authority are ready\n");
} finally {
  owner.release(); runtime.release();
  await runtimePool.end(); await ownerPool.end();
}

function runtimeVerificationSql(schemaName) {
  const q = quoteIdentifier(schemaName);
  const named = (name) => `${schemaName}.${name}`;
  return `WITH pinned AS (SELECT * FROM ${q}.p42_indexer_checkpoint_authority WHERE singleton=true),
  objects AS (
    SELECT p.*, n.oid AS actual_schema_oid, n.nspname AS actual_schema_name,
      f.proowner AS function_owner, f.prosecdef, f.provolatile, f.prokind, f.proconfig, f.prosrc,
      l.lanname, f.proisstrict, f.proleakproof, f.proparallel, f.proretset,
      pg_catalog.pg_get_function_result(f.oid) AS function_result, f.oid AS actual_function_oid,
      x.proowner AS exact_owner, x.prosecdef AS exact_secdef, x.provolatile AS exact_volatile,
      x.prokind AS exact_kind, x.proconfig AS exact_config, x.prosrc AS actual_exact_source,
      xl.lanname AS exact_language, x.proisstrict AS exact_strict, x.proleakproof AS exact_leakproof,
      x.proparallel AS exact_parallel, x.proretset AS exact_retset,
      pg_catalog.pg_get_function_result(x.oid) AS exact_result, x.oid AS actual_exact_oid
    FROM pinned AS p JOIN pg_catalog.pg_namespace AS n ON n.oid=p.schema_oid
    JOIN pg_catalog.pg_proc AS f ON f.oid=p.transition_function_oid
    JOIN pg_catalog.pg_language AS l ON l.oid=f.prolang
    JOIN pg_catalog.pg_proc AS x ON x.oid=p.exact_read_function_oid
    JOIN pg_catalog.pg_language AS xl ON xl.oid=x.prolang
  ), runtime AS (SELECT r.* FROM pg_catalog.pg_roles AS r WHERE r.rolname=CURRENT_USER)
  SELECT
    CURRENT_USER=SESSION_USER
      AND o.database_oid=(SELECT d.oid FROM pg_catalog.pg_database AS d WHERE d.datname=current_database())
      AND o.database_name::text=current_database() AND o.schema_oid=o.actual_schema_oid
      AND o.schema_name::text=$1 AND o.actual_schema_name=$1
      AND o.migration_owner_oid=(SELECT d.datdba FROM pg_catalog.pg_database AS d WHERE d.oid=o.database_oid)
      AND o.migration_owner_oid=(SELECT n.nspowner FROM pg_catalog.pg_namespace AS n WHERE n.oid=o.schema_oid)
      AND o.migration_owner_oid=(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.authority_oid)
      AND o.migration_owner_oid=(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.control_oid)
      AND o.migration_owner_oid=(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.epoch_oid)
      AND o.migration_owner_oid=(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.acceptance_oid)
      AND o.authority_oid='${named("p42_indexer_checkpoint_authority")}'::regclass::oid
      AND o.control_oid='${named("p42_indexer_checkpoint_control")}'::regclass::oid
      AND o.epoch_oid='${named("p42_indexer_checkpoint_epoch")}'::regclass::oid
      AND o.acceptance_oid='${named("p42_indexer_checkpoint_acceptance")}'::regclass::oid
      AND o.exact_read_function_oid=o.actual_exact_oid AS identity_matches,
    o.actual_function_oid='${named("p42_transition_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)")}'::regprocedure::oid
      AND o.function_owner=o.migration_owner_oid
      AND o.migration_owner_name::text=pg_catalog.pg_get_userbyid(o.function_owner)
      AND o.prosecdef AND o.provolatile='v' AND o.prokind='f'
      AND o.lanname='plpgsql' AND NOT o.proisstrict AND NOT o.proleakproof
      AND o.proparallel='u' AND o.proretset AND o.function_result='TABLE(transition_kind text, epoch_id bigint, release_binding_digest text, authorization_digest text, chain_id bigint, chain_name text, deployment_commit text, deployment_config_hash text, epoch_accepted_at timestamp with time zone, acceptance_id bigint, finalized_block_number bigint, finalized_block_hash text, checkpoint_digest text, checkpoint_timestamp bigint, acceptance_accepted_at timestamp with time zone, current_epoch bigint, current_acceptance bigint, next_epoch bigint, next_acceptance bigint, control_updated_at timestamp with time zone)'
      AND o.proconfig=ARRAY['search_path=pg_catalog']::text[] AND o.prosrc=o.transition_function_source
      AND o.actual_exact_oid='${named("p42_read_exact_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)")}'::regprocedure::oid
      AND o.exact_owner=o.migration_owner_oid AND o.exact_secdef AND o.exact_volatile='v' AND o.exact_kind='f'
      AND o.exact_language='plpgsql' AND NOT o.exact_strict AND NOT o.exact_leakproof
      AND o.exact_parallel='u' AND o.exact_retset AND o.exact_result=o.function_result
      AND o.exact_config=ARRAY['search_path=pg_catalog']::text[]
      AND o.actual_exact_source=o.exact_read_function_source AS function_matches,
    pg_catalog.has_function_privilege(CURRENT_USER,o.actual_function_oid,'EXECUTE')
      AND NOT pg_catalog.has_function_privilege('public',o.actual_function_oid,'EXECUTE')
      AND pg_catalog.has_function_privilege(CURRENT_USER,o.actual_exact_oid,'EXECUTE')
      AND NOT pg_catalog.has_function_privilege('public',o.actual_exact_oid,'EXECUTE')
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(
        (SELECT p.proacl FROM pg_catalog.pg_proc AS p WHERE p.oid=o.actual_function_oid),
        pg_catalog.acldefault('f',o.function_owner))) AS acl
        WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>ALL(ARRAY[o.function_owner,r.oid]))
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(
        (SELECT p.proacl FROM pg_catalog.pg_proc AS p WHERE p.oid=o.actual_exact_oid),
        pg_catalog.acldefault('f',o.exact_owner))) AS acl
        WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>ALL(ARRAY[o.exact_owner,r.oid])) AS acl_matches,
    NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolbypassrls
      AND (SELECT d.datdba<>r.oid FROM pg_catalog.pg_database AS d WHERE d.oid=o.database_oid)
      AND (SELECT n.nspowner<>r.oid FROM pg_catalog.pg_namespace AS n WHERE n.oid=o.schema_oid)
      AND r.oid<>ALL(ARRAY[(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.authority_oid),
        (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.control_oid),
        (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.epoch_oid),
        (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.acceptance_oid)])
      AND NOT pg_catalog.has_database_privilege(r.oid,o.database_oid,'CREATE')
      AND NOT pg_catalog.has_schema_privilege(r.oid,o.schema_oid,'CREATE') AS safe_role,
    NOT (${dangerousTablePrivileges("r.oid", "o")}) AS no_direct_writes,
    NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS candidate
      WHERE candidate.oid<>r.oid AND pg_catalog.pg_has_role(r.oid,candidate.oid,'SET')
        AND (candidate.oid=o.migration_owner_oid OR candidate.rolsuper OR candidate.rolcreatedb
          OR candidate.rolcreaterole OR candidate.rolbypassrls
          OR pg_catalog.has_database_privilege(candidate.oid,o.database_oid,'CREATE')
          OR pg_catalog.has_schema_privilege(candidate.oid,o.schema_oid,'CREATE')
          OR candidate.oid=(SELECT d.datdba FROM pg_catalog.pg_database AS d WHERE d.oid=o.database_oid)
          OR candidate.oid=(SELECT n.nspowner FROM pg_catalog.pg_namespace AS n WHERE n.oid=o.schema_oid)
          OR ${dangerousTablePrivileges("candidate.oid", "o")})) AS no_dangerous_set_role,
    NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t
      WHERE t.tgrelid IN(o.authority_oid,o.control_oid,o.epoch_oid,o.acceptance_oid) AND NOT t.tgisinternal) AS no_external_triggers,
    (SELECT count(*)::integer FROM ${q}.p42_indexer_checkpoint_control WHERE singleton=true) AS control_rows,
    (SELECT name FROM ${q}.p42_schema_migration WHERE version=1) AS migration_1_name,
    (SELECT name FROM ${q}.p42_schema_migration WHERE version=2) AS migration_2_name
  FROM objects AS o CROSS JOIN runtime AS r`;
}

function dangerousTablePrivileges(role, objects) {
  return ["authority", "control", "epoch", "acceptance"].flatMap((table) =>
    ["INSERT", "UPDATE", "DELETE", "TRUNCATE", "TRIGGER"].map((privilege) =>
      `pg_catalog.has_table_privilege(${role},${objects}.${table}_oid,'${privilege}')`),
  ).join(" OR ");
}

function quoteIdentifier(value) { return `"${value.replaceAll('"', '""')}"`; }
