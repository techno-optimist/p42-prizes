import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const migrationUrl = process.env.P42_PORTAL_MIGRATION_DATABASE_URL?.trim();
const runtimeUrl = process.env.P42_PORTAL_DATABASE_URL?.trim();
const targetSchema = process.env.P42_PORTAL_DATABASE_SCHEMA?.trim();
const expectedRuntimeRole = process.env.P42_PORTAL_RUNTIME_ROLE?.trim();
const expectedDatabase = process.env.P42_PORTAL_DATABASE_NAME?.trim();
if (!migrationUrl) throw new Error("P42_PORTAL_MIGRATION_DATABASE_URL is required for portal database migration");
if (!runtimeUrl) throw new Error("P42_PORTAL_DATABASE_URL is required to provision and verify the runtime role");
if (!targetSchema || !/^[a-z][a-z0-9_]{0,62}$/.test(targetSchema)) {
  throw new Error("P42_PORTAL_DATABASE_SCHEMA must name the preprovisioned production schema");
}
if (!expectedRuntimeRole || !/^[a-z][a-z0-9_]{0,62}$/.test(expectedRuntimeRole)) {
  throw new Error("P42_PORTAL_RUNTIME_ROLE must name the exact provisioned runtime role");
}
if (!expectedDatabase || !/^[a-z][a-z0-9_]{0,62}$/.test(expectedDatabase)) {
  throw new Error("P42_PORTAL_DATABASE_NAME must name the exact provisioned database");
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
  if (ownerIdentity.database !== expectedDatabase) throw new Error("portal migration and runtime roles must use the exact configured database");
  if (runtimeIdentity.role !== expectedRuntimeRole) throw new Error("portal runtime connection must authenticate as the exact configured role");
  if (ownerIdentity.database_owner_oid !== ownerIdentity.role_oid) throw new Error("migration role must own the pinned portal database");

  const schemaIdentity = await owner.query(`SELECT n.oid, n.nspowner FROM pg_catalog.pg_namespace AS n WHERE n.nspname=$1`, [targetSchema]);
  if (schemaIdentity.rowCount !== 1 || schemaIdentity.rows[0].nspowner !== ownerIdentity.role_oid) {
    throw new Error("migration role must own the preprovisioned portal schema");
  }
  await owner.query("SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1,0))", [
    `${expectedDatabase}:${expectedRuntimeRole}:${targetSchema}`,
  ]);
  const preflight = (await runtime.query(runtimePreflightSql(), [
    expectedRuntimeRole, expectedDatabase, `${targetSchema}, pg_catalog`, ownerIdentity.role_oid,
  ])).rows[0];
  if (!preflight?.identity_matches || !preflight.safe_role || !preflight.membership_matches
    || !preflight.database_settings_match || !preflight.search_path_matches) {
    const failed = Object.entries(preflight ?? {}).filter(([, passed]) => !passed).map(([name]) => name).join(",");
    throw new Error(`portal runtime identity, membership, settings, or search_path preflight failed before migration: ${failed || "missing_result"}`);
  }
  await closeOwnerDefaultPrivileges(owner, ownerIdentity.role, ownerIdentity.role_oid, targetSchema);
  await closeCreationPrivileges(owner, ownerIdentity, targetSchema);
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
  await owner.query(`REVOKE ALL ON ${highWaterRelations} FROM ${runtimeRole}`);
  await closePortalObjectPrivileges(owner, ownerIdentity.role_oid, targetSchema);
  await owner.query(`GRANT USAGE ON SCHEMA ${schema} TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT, INSERT, UPDATE ON ${relation("p42_portal_state")} TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ${relation("p42_rate_limit_bucket")} TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT ON ${relation("p42_schema_migration")} TO ${runtimeRole}`);
  await owner.query(`GRANT SELECT ON ${highWaterRelations} TO ${runtimeRole}`);
  await owner.query(`GRANT EXECUTE ON FUNCTION ${functionIdentity} TO ${runtimeRole}`);
  await owner.query(`GRANT EXECUTE ON FUNCTION ${exactFunctionIdentity} TO ${runtimeRole}`);

  const aclClosure = (await owner.query(aclClosureSql(targetSchema), [ownerIdentity.role_oid, runtimeIdentity.role_oid])).rows[0];
  if (!aclClosure?.default_acl_closed || !aclClosure.schema_acl_exact || !aclClosure.database_create_closed
    || !aclClosure.relation_acl_exact || !aclClosure.column_acl_closed || !aclClosure.function_acl_exact) {
    const failed = Object.entries(aclClosure ?? {}).filter(([, passed]) => !passed).map(([name]) => name).join(",");
    throw new Error(`portal database ACL closure verification failed: ${failed || "missing_result"}`);
  }

  await runtime.query("SELECT set_config('search_path','pg_catalog',false)");
  const verification = await runtime.query(runtimeVerificationSql(targetSchema), [targetSchema]);
  const row = verification.rows[0];
  if (verification.rowCount !== 1 || !row.identity_matches || !row.function_matches || !row.acl_matches
    || !row.safe_role || !row.membership_matches || !row.database_settings_match || !row.no_direct_writes
    || !row.no_dangerous_set_role || !row.no_external_triggers
    || row.control_rows !== 1 || row.migration_1_name !== "portal_store"
    || row.migration_2_name !== "indexer_checkpoint_epoch_high_water") {
    const failed = Object.entries(row ?? {}).filter(([name, value]) =>
      (typeof value === "boolean" && !value) || (name === "control_rows" && value !== 1),
    ).map(([name]) => name).join(",");
    throw new Error(`portal runtime role failed pinned least-privilege authority verification: ${failed || "identity_or_migration"}`);
  }
  process.stdout.write("portal database schema and pinned least-privilege transition authority are ready\n");
} finally {
  owner.release(); runtime.release();
  await runtimePool.end(); await ownerPool.end();
}

function runtimePreflightSql() {
  return `WITH runtime AS (SELECT r.* FROM pg_catalog.pg_roles AS r WHERE r.rolname=CURRENT_USER)
  SELECT CURRENT_USER=SESSION_USER AND CURRENT_USER=$1 AND current_database()=$2 AS identity_matches,
    r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole
      AND NOT r.rolinherit AND NOT r.rolreplication AND NOT r.rolbypassrls AS safe_role,
    NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS outbound WHERE outbound.member=r.oid)
      AND (SELECT count(*) FROM pg_catalog.pg_auth_members AS inbound WHERE inbound.roleid=r.oid)=1
      AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS inbound
        JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=inbound.grantor
        WHERE inbound.roleid=r.oid AND inbound.member=$4
          AND inbound.grantor=10 AND grantor.rolsuper AND inbound.admin_option
          AND NOT inbound.inherit_option AND NOT inbound.set_option) AS membership_matches,
    (SELECT count(*) FROM pg_catalog.pg_db_role_setting AS s WHERE s.setrole=r.oid)=1
      AND EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting AS s
        WHERE s.setrole=r.oid
          AND s.setdatabase=(SELECT d.oid FROM pg_catalog.pg_database AS d WHERE d.datname=current_database())
          AND s.setconfig=ARRAY['search_path=' || $3]::text[]) AS database_settings_match,
    current_setting('search_path')=$3 AS search_path_matches
  FROM runtime AS r`;
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
    r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole
      AND NOT r.rolinherit AND NOT r.rolreplication AND NOT r.rolbypassrls
      AND (SELECT d.datdba<>r.oid FROM pg_catalog.pg_database AS d WHERE d.oid=o.database_oid)
      AND (SELECT n.nspowner<>r.oid FROM pg_catalog.pg_namespace AS n WHERE n.oid=o.schema_oid)
      AND r.oid<>ALL(ARRAY[(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.authority_oid),
        (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.control_oid),
        (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.epoch_oid),
        (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.acceptance_oid)])
      AND NOT pg_catalog.has_database_privilege(r.oid,o.database_oid,'CREATE')
      AND NOT pg_catalog.has_schema_privilege(r.oid,o.schema_oid,'CREATE') AS safe_role,
    NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS outbound WHERE outbound.member=r.oid)
      AND (SELECT count(*) FROM pg_catalog.pg_auth_members AS inbound WHERE inbound.roleid=r.oid)=1
      AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS inbound
        JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=inbound.grantor
        WHERE inbound.roleid=r.oid AND inbound.member=o.migration_owner_oid
          AND inbound.grantor=10 AND grantor.rolsuper AND inbound.admin_option
          AND NOT inbound.inherit_option AND NOT inbound.set_option) AS membership_matches,
    (SELECT count(*) FROM pg_catalog.pg_db_role_setting AS s WHERE s.setrole=r.oid)=1
      AND EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting AS s
        WHERE s.setrole=r.oid AND s.setdatabase=o.database_oid
          AND s.setconfig=ARRAY['search_path=' || $1 || ', pg_catalog']::text[]) AS database_settings_match,
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

async function closeOwnerDefaultPrivileges(client, ownerName, ownerOid, schemaName) {
  const rows = await client.query(`SELECT d.defaclnamespace::text AS namespace_oid,
    d.defaclobjtype AS object_type, acl.grantee::text AS grantee_oid,
    CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee
    FROM pg_catalog.pg_default_acl AS d
    CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) AS acl
    WHERE d.defaclrole=$1 AND d.defaclnamespace IN (0,
      (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname=$2))
      AND acl.grantee<>$1`, [ownerOid, schemaName]);
  const kinds = { r: "TABLES", S: "SEQUENCES", f: "FUNCTIONS", T: "TYPES", n: "SCHEMAS" };
  const seen = new Set();
  for (const row of rows.rows) {
    const kind = kinds[row.object_type];
    if (!kind || !row.grantee) throw new Error("unsupported owner default privilege drift");
    const key = `${row.namespace_oid}:${row.object_type}:${row.grantee_oid}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const inSchema = row.namespace_oid === "0" ? "" : ` IN SCHEMA ${quoteIdentifier(schemaName)}`;
    await client.query(`ALTER DEFAULT PRIVILEGES FOR ROLE ${quoteIdentifier(ownerName)}${inSchema}
      REVOKE ALL PRIVILEGES ON ${kind} FROM ${grantee(row.grantee)}`);
  }
  // Close PostgreSQL's implicit PUBLIC EXECUTE default even when no pg_default_acl row exists yet.
  await client.query(`ALTER DEFAULT PRIVILEGES FOR ROLE ${quoteIdentifier(ownerName)}
    REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC`);
  await client.query(`ALTER DEFAULT PRIVILEGES FOR ROLE ${quoteIdentifier(ownerName)} IN SCHEMA ${quoteIdentifier(schemaName)}
    REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC`);
}

async function closeCreationPrivileges(client, ownerIdentity, schemaName) {
  const database = quoteIdentifier(ownerIdentity.database);
  const schema = quoteIdentifier(schemaName);
  const databaseGrantees = await client.query(`SELECT DISTINCT CASE WHEN acl.grantee=0 THEN 'PUBLIC'
      ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee
    FROM pg_catalog.pg_database AS d
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))) AS acl
    WHERE d.datname=current_database() AND acl.privilege_type='CREATE' AND acl.grantee<>$1`, [ownerIdentity.role_oid]);
  for (const row of databaseGrantees.rows) await client.query(`REVOKE CREATE ON DATABASE ${database} FROM ${grantee(row.grantee)}`);
  const targetSchemaGrantees = await client.query(`SELECT DISTINCT CASE WHEN acl.grantee=0 THEN 'PUBLIC'
      ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee
    FROM pg_catalog.pg_namespace AS n
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) AS acl
    WHERE n.nspname=$1 AND acl.grantee<>$2`, [schemaName, ownerIdentity.role_oid]);
  for (const row of targetSchemaGrantees.rows) await client.query(`REVOKE ALL PRIVILEGES ON SCHEMA ${schema} FROM ${grantee(row.grantee)}`);
  const publicCreateGrantees = await client.query(`SELECT DISTINCT CASE WHEN acl.grantee=0 THEN 'PUBLIC'
      ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee
    FROM pg_catalog.pg_namespace AS n
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) AS acl
    WHERE n.nspname='public' AND acl.privilege_type='CREATE' AND acl.grantee<>n.nspowner`);
  for (const row of publicCreateGrantees.rows) await client.query(`REVOKE CREATE ON SCHEMA public FROM ${grantee(row.grantee)}`);
}

async function closePortalObjectPrivileges(client, ownerOid, schemaName) {
  const tableNames = portalTableNames();
  const tableList = tableNames.map((name) => `${quoteIdentifier(schemaName)}.${quoteIdentifier(name)}`).join(", ");
  const relationGrantees = await client.query(`SELECT DISTINCT CASE WHEN acl.grantee=0 THEN 'PUBLIC'
      ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee
    FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) AS acl
    WHERE n.nspname=$1 AND c.relname=ANY($2::text[]) AND acl.grantee<>$3`, [schemaName, tableNames, ownerOid]);
  for (const row of relationGrantees.rows) await client.query(`REVOKE ALL PRIVILEGES ON TABLE ${tableList} FROM ${grantee(row.grantee)}`);

  const columnGrants = await client.query(`SELECT c.relname, a.attname,
      CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee
    FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
    JOIN pg_catalog.pg_attribute AS a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
    CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) AS acl
    WHERE n.nspname=$1 AND c.relname=ANY($2::text[])`, [schemaName, tableNames]);
  const columnsByRelationAndGrantee = new Map();
  for (const row of columnGrants.rows) {
    const key = `${row.relname}\0${row.grantee}`;
    if (!columnsByRelationAndGrantee.has(key)) columnsByRelationAndGrantee.set(key, new Set());
    columnsByRelationAndGrantee.get(key).add(row.attname);
  }
  for (const [key, columns] of columnsByRelationAndGrantee) {
    const [relationName, granteeName] = key.split("\0");
    const columnList = [...columns].map(quoteIdentifier).join(", ");
    await client.query(`REVOKE ALL PRIVILEGES (${columnList}) ON TABLE
      ${quoteIdentifier(schemaName)}.${quoteIdentifier(relationName)} FROM ${grantee(granteeName)}`);
  }

  const functionIdentities = [functionIdentityFor(schemaName, "p42_transition_indexer_checkpoint"),
    functionIdentityFor(schemaName, "p42_read_exact_indexer_checkpoint")];
  const functionGrantees = await client.query(`SELECT DISTINCT CASE WHEN acl.grantee=0 THEN 'PUBLIC'
      ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee
    FROM pg_catalog.pg_proc AS p
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) AS acl
    WHERE p.oid IN ($1::regprocedure::oid,$2::regprocedure::oid) AND acl.grantee<>$3`,
  [...functionIdentities, ownerOid]);
  const functionList = functionIdentities.map((identity) => {
    const separator = identity.indexOf(".");
    return `${quoteIdentifier(identity.slice(0, separator))}.${identity.slice(separator + 1)}`;
  }).join(", ");
  for (const row of functionGrantees.rows) await client.query(`REVOKE ALL PRIVILEGES ON FUNCTION ${functionList} FROM ${grantee(row.grantee)}`);
}

function aclClosureSql(schemaName) {
  const tables = portalTableNames();
  const expected = [
    ["p42_portal_state", "SELECT"], ["p42_portal_state", "INSERT"], ["p42_portal_state", "UPDATE"],
    ["p42_rate_limit_bucket", "SELECT"], ["p42_rate_limit_bucket", "INSERT"],
    ["p42_rate_limit_bucket", "UPDATE"], ["p42_rate_limit_bucket", "DELETE"],
    ["p42_schema_migration", "SELECT"],
    ...["p42_indexer_checkpoint_authority", "p42_indexer_checkpoint_control",
      "p42_indexer_checkpoint_epoch", "p42_indexer_checkpoint_acceptance"].map((name) => [name, "SELECT"]),
  ];
  const expectedValues = expected.map(([name, privilege]) => `('${name}','${privilege}')`).join(",");
  return `WITH expected_runtime(relation_name,privilege_type) AS (VALUES ${expectedValues}),
  relations AS (SELECT c.oid,c.relname,c.relowner,c.relacl FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='${schemaName}' AND c.relname=ANY(ARRAY[${tables.map((name) => `'${name}'`).join(",")}])) ,
  relation_acl AS (SELECT r.relname,r.relowner,acl.* FROM relations r
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(r.relacl,pg_catalog.acldefault('r',r.relowner))) acl),
  function_acl AS (SELECT p.oid,p.proowner,acl.* FROM pg_catalog.pg_proc p
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
    WHERE p.oid IN ('${schemaName}.p42_transition_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)'::regprocedure,
      '${schemaName}.p42_read_exact_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)'::regprocedure))
   SELECT (SELECT count(*) FROM pg_catalog.pg_default_acl d WHERE d.defaclrole=$1
        AND d.defaclobjtype='f' AND d.defaclnamespace=0)=1
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl d
        CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) acl
        WHERE d.defaclrole=$1 AND d.defaclnamespace IN (0,(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='${schemaName}'))
          AND acl.grantee<>$1) AS default_acl_closed,
    NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
      CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) acl
      WHERE n.nspname='${schemaName}' AND NOT (
        (acl.grantee=$1 AND acl.privilege_type IN ('USAGE','CREATE'))
        OR (acl.grantee=$2 AND acl.privilege_type='USAGE' AND NOT acl.is_grantable)))
      AND pg_catalog.has_schema_privilege($2,'${schemaName}','USAGE')
      AND NOT pg_catalog.has_schema_privilege($2,'${schemaName}','CREATE')
      AND NOT pg_catalog.has_schema_privilege('public','${schemaName}','USAGE')
      AND NOT pg_catalog.has_schema_privilege('public','${schemaName}','CREATE') AS schema_acl_exact,
    NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database d
      CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))) acl
      WHERE d.datname=current_database() AND acl.privilege_type='CREATE' AND acl.grantee<>$1)
      AND NOT pg_catalog.has_database_privilege($2,current_database(),'CREATE')
       AND NOT pg_catalog.has_database_privilege('public',current_database(),'CREATE')
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
         CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) acl
         WHERE n.nspname='public' AND acl.privilege_type='CREATE' AND acl.grantee<>n.nspowner)
       AND NOT pg_catalog.has_schema_privilege($2,'public','CREATE')
      AND NOT pg_catalog.has_schema_privilege('public','public','CREATE') AS database_create_closed,
    NOT EXISTS (SELECT 1 FROM relation_acl acl WHERE NOT (
      (acl.grantee=$1 AND acl.privilege_type IN ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN'))
      OR (acl.grantee=$2 AND NOT acl.is_grantable AND EXISTS (SELECT 1 FROM expected_runtime e
        WHERE e.relation_name=acl.relname AND e.privilege_type=acl.privilege_type))))
      AND NOT EXISTS (SELECT 1 FROM expected_runtime e WHERE NOT EXISTS (SELECT 1 FROM relation_acl acl
        WHERE acl.relname=e.relation_name AND acl.grantee=$2 AND acl.privilege_type=e.privilege_type AND NOT acl.is_grantable)) AS relation_acl_exact,
    NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a JOIN relations r ON r.oid=a.attrelid
      CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl WHERE a.attnum>0 AND NOT a.attisdropped) AS column_acl_closed,
    NOT EXISTS (SELECT 1 FROM function_acl acl WHERE NOT (
      (acl.grantee=$1 AND acl.privilege_type='EXECUTE')
      OR (acl.grantee=$2 AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)))
      AND (SELECT count(*) FROM function_acl WHERE grantee=$2 AND privilege_type='EXECUTE' AND NOT is_grantable)=2 AS function_acl_exact`;
}

function portalTableNames() {
  return ["p42_portal_state", "p42_rate_limit_bucket", "p42_schema_migration",
    "p42_indexer_checkpoint_authority", "p42_indexer_checkpoint_control",
    "p42_indexer_checkpoint_epoch", "p42_indexer_checkpoint_acceptance"];
}

function functionIdentityFor(schemaName, name) {
  return `${schemaName}.${name}(bigint,text,text,bigint,text,text,bigint,text,text,text)`;
}

function grantee(name) { return name === "PUBLIC" ? "PUBLIC" : quoteIdentifier(name); }

function quoteIdentifier(value) { return `"${value.replaceAll('"', '""')}"`; }
