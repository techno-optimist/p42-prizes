import { createHash } from "node:crypto";
import process from "node:process";
import pg from "pg";

const VERSION = "p42-portal-db-provisioning/v1";
const NAME = /^[a-z][a-z0-9_]{0,62}$/;
const connectionString = process.env.P42_PORTAL_MIGRATION_DATABASE_URL?.trim();
const runtimeRoleName = process.env.P42_PORTAL_RUNTIME_ROLE?.trim();
const targetSchemaName = process.env.P42_PORTAL_DATABASE_SCHEMA?.trim();
const runtimePassword = process.env.P42_PORTAL_RUNTIME_PASSWORD;

let client;
try {
  const mode = parseMode(process.argv.slice(2));
  requireValue(connectionString, "P42_PORTAL_MIGRATION_DATABASE_URL");
  requireName(runtimeRoleName, "P42_PORTAL_RUNTIME_ROLE");
  requireName(targetSchemaName, "P42_PORTAL_DATABASE_SCHEMA");
  if (mode === "apply" && !runtimePassword) {
    throw ceremonyError("missing_runtime_password", "P42_PORTAL_RUNTIME_PASSWORD is required for apply mode");
  }

  client = new pg.Client({
    connectionString,
    application_name: "p42-portal-db-provisioning",
    connectionTimeoutMillis: 10_000,
  });
  client.on("error", () => undefined);
  await client.connect();
  const result = await provision(client, { mode, runtimeRoleName, targetSchemaName, runtimePassword });
  process.stdout.write(`${canonicalJson(withDigest(result))}\n`);
} catch (error) {
  const safe = publicError(error, [connectionString, runtimePassword]);
  process.stderr.write(`${canonicalJson(safe)}\n`);
  process.exitCode = 1;
} finally {
  if (client) await client.end().catch(() => undefined);
}

async function provision(db, options) {
  const { mode: requestedMode, runtimeRoleName: runtimeName, targetSchemaName: schemaName, runtimePassword: password } = options;
  await db.query(requestedMode === "plan"
    ? "BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY"
    : "BEGIN ISOLATION LEVEL SERIALIZABLE");
  try {
    await db.query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(current_database() || ':' || $1 || ':' || $2, 0))", [runtimeName, schemaName]);
    const before = await inspect(db, runtimeName, schemaName);
    assertSafeState(before, runtimeName, schemaName);

    if (requestedMode === "apply") {
      await applyProvisioning(db, before, runtimeName, schemaName, password);
      const after = await inspect(db, runtimeName, schemaName);
      assertExactResult(after, runtimeName, schemaName);
      await db.query("COMMIT");
      return receipt("apply", "applied_and_verified", after, before);
    }

    await db.query("ROLLBACK");
    return receipt("plan", "ready", before, before);
  } catch (error) {
    await db.query("ROLLBACK").catch(() => undefined);
    throw error;
  }
}

async function inspect(db, runtimeName, schemaName) {
  const identity = (await db.query(`SELECT current_user AS migration_owner,
    session_user AS session_owner, current_database() AS database_name,
    d.oid::text AS database_oid, d.datdba::text AS database_owner_oid,
    current_user::regrole::oid::text AS migration_owner_oid,
    r.rolcreaterole AS owner_can_create_role
    FROM pg_catalog.pg_database AS d
    JOIN pg_catalog.pg_roles AS r ON r.rolname=current_user
    WHERE d.datname=current_database()`)).rows[0];
  const runtimeResult = await db.query(`SELECT r.oid::text AS oid, r.rolcanlogin, r.rolsuper,
    r.rolcreatedb, r.rolcreaterole, r.rolinherit, r.rolreplication, r.rolbypassrls,
    r.rolconnlimit, r.rolvaliduntil IS NULL AS no_expiry,
    (SELECT count(*)::integer FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid) AS memberships,
    (SELECT count(*)::integer FROM pg_catalog.pg_shdepend s
      WHERE s.refclassid='pg_catalog.pg_authid'::regclass AND s.refobjid=r.oid
        AND s.deptype='o') AS owned_objects,
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))) a
      WHERE a.grantee=r.oid AND a.privilege_type='CREATE') AS direct_database_create,
    coalesce((SELECT array_agg(s.setdatabase::text || ':' || setting ORDER BY s.setdatabase,setting)
      FROM pg_catalog.pg_db_role_setting s, LATERAL unnest(s.setconfig) setting
      WHERE s.setrole=r.oid), ARRAY[]::text[]) AS settings
    FROM pg_catalog.pg_roles r CROSS JOIN pg_catalog.pg_database d
    WHERE r.rolname=$1 AND d.datname=current_database()`, [runtimeName]);
  const schemaResult = await db.query(`SELECT n.oid::text AS oid, n.nspowner::text AS owner_oid,
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
      JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE r.rolname=$2 AND a.privilege_type='CREATE') AS runtime_direct_create,
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
      WHERE a.grantee=0 AND a.privilege_type='CREATE') AS public_create,
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
      JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE r.rolname=$2 AND a.privilege_type='USAGE') AS runtime_usage,
    (SELECT count(*)::integer FROM (
      SELECT c.relowner AS owner FROM pg_catalog.pg_class c WHERE c.relnamespace=n.oid
      UNION ALL SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.pronamespace=n.oid
      UNION ALL SELECT t.typowner FROM pg_catalog.pg_type t WHERE t.typnamespace=n.oid AND t.typrelid=0
      UNION ALL SELECT o.oprowner FROM pg_catalog.pg_operator o WHERE o.oprnamespace=n.oid
      UNION ALL SELECT c.collowner FROM pg_catalog.pg_collation c WHERE c.collnamespace=n.oid
      UNION ALL SELECT c.conowner FROM pg_catalog.pg_conversion c WHERE c.connamespace=n.oid
    ) owned WHERE owned.owner<>$3::oid) AS foreign_owned_objects
    FROM pg_catalog.pg_namespace n WHERE n.nspname=$1`, [schemaName, runtimeName, identity.migration_owner_oid]);
  const publicSchema = (await db.query(`SELECT n.oid::text AS oid,
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
      WHERE a.grantee=0 AND a.privilege_type='CREATE') AS public_create,
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
      JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE r.rolname=$1 AND a.privilege_type='CREATE') AS runtime_direct_create
    FROM pg_catalog.pg_namespace n WHERE n.nspname='public'`, [runtimeName])).rows[0];
  const publicDatabaseCreate = (await db.query(`SELECT EXISTS (
    SELECT 1 FROM pg_catalog.pg_database d,
    LATERAL pg_catalog.aclexplode(coalesce(d.datacl,pg_catalog.acldefault('d',d.datdba))) a
    WHERE d.datname=current_database() AND a.grantee=0 AND a.privilege_type='CREATE') AS allowed`)).rows[0].allowed;
  return {
    identity,
    runtime: runtimeResult.rows[0] ?? null,
    schema: schemaResult.rows[0] ?? null,
    publicSchema: publicSchema ?? null,
    hazards: { publicDatabaseCreate },
  };
}

function assertSafeState(state, runtimeName, schemaName) {
  const { identity, runtime, schema, publicSchema } = state;
  if (!identity || identity.migration_owner !== identity.session_owner
    || identity.database_owner_oid !== identity.migration_owner_oid) {
    throw ceremonyError("migration_owner_drift", "authenticated migration role must be the exact database owner");
  }
  if (!identity.owner_can_create_role) throw ceremonyError("owner_cannot_create_role", "database owner lacks CREATEROLE");
  if (identity.migration_owner === runtimeName) throw ceremonyError("identity_overlap", "runtime role must differ from migration owner");
  if (!publicSchema) throw ceremonyError("public_schema_missing", "public schema is required for explicit hazard revocation");
  if (runtime && !exactRuntimeAttributes(runtime, schemaName, identity.database_oid)) {
    throw ceremonyError("runtime_role_drift", `preexisting runtime role drifted: ${runtimeDriftReasons(runtime, schemaName, identity.database_oid).join(",")}`);
  }
  if (schema && (schema.owner_oid !== identity.migration_owner_oid || schema.foreign_owned_objects !== 0)) {
    throw ceremonyError("schema_ownership_drift", `preexisting ${schemaName} schema or contained object ownership drifted`);
  }
  if (schema?.runtime_direct_create || publicSchema.runtime_direct_create || runtime?.direct_database_create) {
    throw ceremonyError("runtime_create_drift", "preexisting runtime role has a direct CREATE grant");
  }
}

function exactRuntimeAttributes(runtime, schemaName, databaseOid) {
  const settings = runtime.settings ?? [];
  const settingsSafe = settings.length === 0
    || (settings.length === 1 && settings[0] === `${databaseOid}:search_path=${schemaName}, pg_catalog`);
  return runtime.rolcanlogin && !runtime.rolsuper && !runtime.rolcreatedb && !runtime.rolcreaterole
    && !runtime.rolinherit && !runtime.rolreplication && !runtime.rolbypassrls
    && runtime.rolconnlimit === -1 && runtime.no_expiry && runtime.memberships === 0
    && runtime.owned_objects === 0 && !runtime.direct_database_create && settingsSafe;
}

function runtimeDriftReasons(runtime, schemaName, databaseOid) {
  const checks = {
    login: runtime.rolcanlogin, nosuperuser: !runtime.rolsuper, nocreatedb: !runtime.rolcreatedb,
    nocreaterole: !runtime.rolcreaterole, noinherit: !runtime.rolinherit,
    noreplication: !runtime.rolreplication, nobypassrls: !runtime.rolbypassrls,
    connection_limit: runtime.rolconnlimit === -1, no_expiry: runtime.no_expiry,
    no_memberships: runtime.memberships === 0, owns_nothing: runtime.owned_objects === 0,
    no_direct_database_create: !runtime.direct_database_create,
    settings: (runtime.settings ?? []).length === 0
      || ((runtime.settings ?? []).length === 1 && runtime.settings[0] === `${databaseOid}:search_path=${schemaName}, pg_catalog`),
  };
  return Object.entries(checks).filter(([, passed]) => !passed).map(([name]) => name);
}

async function applyProvisioning(db, before, runtimeName, schemaName, password) {
  const role = quoteIdentifier(runtimeName);
  const schema = quoteIdentifier(schemaName);
  const database = quoteIdentifier(before.identity.database_name);
  const owner = quoteIdentifier(before.identity.migration_owner);
  if (!before.runtime) {
    await db.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1`);
  }
  await db.query("SELECT pg_catalog.set_config('p42.provision_runtime_password',$1,true)", [password]);
  await db.query(`DO $provision$ BEGIN EXECUTE pg_catalog.format('ALTER ROLE %I PASSWORD %L', ${quoteLiteral(runtimeName)},
    pg_catalog.current_setting('p42.provision_runtime_password')); END $provision$`);
  await db.query("SELECT pg_catalog.set_config('p42.provision_runtime_password','',true)");
  if (!before.schema) await db.query(`CREATE SCHEMA ${schema} AUTHORIZATION ${owner}`);

  await db.query(`REVOKE CREATE ON DATABASE ${database} FROM PUBLIC`);
  await db.query("REVOKE CREATE ON SCHEMA public FROM PUBLIC");
  await db.query(`REVOKE ALL ON SCHEMA ${schema} FROM PUBLIC`);
  await db.query(`REVOKE ALL ON SCHEMA ${schema} FROM ${role}`);
  await db.query(`REVOKE CREATE ON DATABASE ${database} FROM ${role}`);
  await db.query(`REVOKE CREATE ON SCHEMA public FROM ${role}`);
  await db.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role}`);
  for (const kind of ["TABLES", "SEQUENCES", "FUNCTIONS", "TYPES"]) {
    await db.query(`ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE ALL ON ${kind} FROM PUBLIC`);
    await db.query(`ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE ALL ON ${kind} FROM ${role}`);
  }
  await db.query(`ALTER ROLE ${role} IN DATABASE ${database} SET search_path TO ${schema}, pg_catalog`);
}

function assertExactResult(state, runtimeName, schemaName) {
  assertSafeState(state, runtimeName, schemaName);
  if (!state.runtime || !state.schema || !state.schema.runtime_usage
    || state.hazards.publicDatabaseCreate || state.publicSchema.public_create
    || state.schema.public_create || state.schema.runtime_direct_create
    || state.publicSchema.runtime_direct_create || state.runtime.direct_database_create
    || state.runtime.settings.length !== 1
    || state.runtime.settings[0] !== `${state.identity.database_oid}:search_path=${schemaName}, pg_catalog`) {
    throw ceremonyError("postcondition_failed", "provisioning postconditions did not hold");
  }
}

function receipt(receiptMode, status, state, before) {
  return {
    schemaVersion: VERSION,
    mode: receiptMode,
    status,
    productionComplete: false,
    database: { name: state.identity.database_name, oid: state.identity.database_oid },
    migrationOwner: { name: state.identity.migration_owner, oid: state.identity.migration_owner_oid, exactDatabaseOwner: true },
    runtimeRole: {
      name: runtimeRoleName,
      oid: state.runtime?.oid ?? null,
      existedBefore: Boolean(before.runtime),
      willCreate: !before.runtime,
      requiredAttributes: ["LOGIN", "NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOBYPASSRLS", "NOINHERIT", "NOREPLICATION"],
      ownsNothing: state.runtime ? state.runtime.owned_objects === 0 : true,
      memberships: state.runtime?.memberships ?? 0,
    },
    targetSchema: {
      name: targetSchemaName,
      oid: state.schema?.oid ?? null,
      existedBefore: Boolean(before.schema),
      willCreate: !before.schema,
      exactOwner: state.schema ? state.schema.owner_oid === state.identity.migration_owner_oid : true,
    },
    publicHazards: {
      databaseCreate: state.hazards.publicDatabaseCreate,
      publicSchemaCreate: state.publicSchema.public_create,
      targetSchemaCreate: state.schema?.public_create ?? false,
      willRevoke: receiptMode === "plan" && Boolean(state.hazards.publicDatabaseCreate || state.publicSchema.public_create || state.schema?.public_create),
    },
    nextRequiredActions: ["run_migrations_separately", "run_import_separately", "run_live_rehearsal_and_retain_redacted_evidence"],
  };
}

function withDigest(value) {
  return { ...value, resultSha256: `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}` };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function parseMode(args) {
  if (args.length === 0 || (args.length === 1 && args[0] === "--plan")) return "plan";
  if (args.length === 1 && args[0] === "--apply") return "apply";
  throw ceremonyError("invalid_arguments", "usage: provision-portal-db.mjs [--plan|--apply]");
}

function requireValue(value, name) {
  if (!value) throw ceremonyError("missing_configuration", `${name} is required`);
}

function requireName(value, name) {
  requireValue(value, name);
  if (!NAME.test(value)) throw ceremonyError("unsafe_identifier", `${name} must be a pinned lowercase PostgreSQL identifier`);
}

function quoteIdentifier(value) { return `"${value.replaceAll('"', '""')}"`; }
function quoteLiteral(value) { return `'${value.replaceAll("'", "''")}'`; }

function ceremonyError(code, message) {
  const error = new Error(message);
  error.ceremonyCode = code;
  return error;
}

function publicError(error, secrets) {
  let message = error instanceof Error ? error.message : "unknown provisioning failure";
  for (const secret of secrets.filter(Boolean)) message = message.replaceAll(secret, "[redacted]");
  message = message.replaceAll(/postgres(?:ql)?:\/\/[^\s"']+/gi, "[redacted-database-url]");
  return {
    schemaVersion: `${VERSION}/error`,
    status: "failed_closed",
    code: error?.ceremonyCode ?? (error?.code ? `postgres_${String(error.code).toLowerCase()}` : "provisioning_failed"),
    message,
    productionComplete: false,
  };
}
