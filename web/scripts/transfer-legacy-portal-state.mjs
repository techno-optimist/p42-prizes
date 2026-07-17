import { createHash } from "node:crypto";
import process from "node:process";
import pg from "pg";

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[a-z][a-z0-9_]{0,62}$/;
const TABLE = "p42_portal_state";
const EXPECTED_SCHEMA_VERSION = 1;

class TransferError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

main().catch((error) => {
  const code = error instanceof TransferError ? error.code : "database-operation-failed";
  process.stderr.write(`${canonicalJson({ error: code, schemaVersion: "p42-legacy-portal-state-transfer-error/v1", status: "failed" })}\n`);
  process.exitCode = 1;
});

async function main() {
  const connectionString = requiredEnv("P42_PORTAL_MIGRATION_DATABASE_URL");
  const targetSchema = schemaEnv("P42_PORTAL_DATABASE_SCHEMA");
  const legacySchema = optionalSchemaEnv("P42_PORTAL_LEGACY_DATABASE_SCHEMA", "public");
  const expectedStateSha256 = digestEnv("P42_PORTAL_EXPECTED_STATE_SHA256");
  const expectedImportSha256 = digestEnv("P42_PORTAL_EXPECTED_IMPORT_SHA256");
  const expectedRevision = revisionEnv("P42_PORTAL_EXPECTED_REVISION");
  if (targetSchema === legacySchema) fail("source-destination-alias");

  const client = new pg.Client({ connectionString, connectionTimeoutMillis: 10_000 });
  let transactionOpen = false;
  try {
    await client.connect();
    await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
    transactionOpen = true;
    await client.query("SET LOCAL search_path = pg_catalog");
    await client.query("SET LOCAL lock_timeout = '30s'");
    await client.query("SET LOCAL statement_timeout = '60s'");

    const identity = await databaseIdentity(client);
    if (identity.roleOid !== identity.databaseOwnerOid) fail("database-owner-mismatch");

    const initial = await resolveRelations(client, targetSchema, legacySchema);
    if (initial.target.oid === initial.legacy.oid) fail("source-destination-alias");
    for (const relation of [initial.target, initial.legacy].sort((a, b) => a.oid - b.oid)) {
      await client.query(`LOCK TABLE ${qualified(relation.schema, TABLE)} IN ACCESS EXCLUSIVE MODE`);
    }

    const locked = await resolveRelations(client, targetSchema, legacySchema);
    if (locked.target.oid !== initial.target.oid || locked.legacy.oid !== initial.legacy.oid) {
      fail("relation-identity-changed");
    }
    if (locked.target.oid === locked.legacy.oid) fail("source-destination-alias");
    if (locked.target.schemaOwnerOid !== identity.roleOid) fail("target-schema-owner-mismatch");
    for (const relation of [locked.target, locked.legacy]) {
      if (relation.ownerOid !== identity.roleOid) fail(`${relation.kind}-table-owner-mismatch`);
      await verifyPortalTableShape(client, relation);
    }

    const destinationCount = await client.query(
      `SELECT count(*)::integer AS count FROM ${qualified(targetSchema, TABLE)}`,
    );
    if (destinationCount.rows[0]?.count !== 0) fail("destination-not-empty");

    const source = await client.query(
      `SELECT singleton, schema_version, revision::text AS revision, state::text AS state_text,
              import_sha256, imported_at::text AS imported_at, updated_at::text AS updated_at
         FROM ${qualified(legacySchema, TABLE)}`,
    );
    if (source.rowCount !== 1 || source.rows[0]?.singleton !== true) fail("source-not-singleton");
    const sourceRow = source.rows[0];
    if (sourceRow.schema_version !== EXPECTED_SCHEMA_VERSION) fail("source-schema-version-mismatch");
    if (sourceRow.revision !== expectedRevision) fail("source-revision-mismatch");
    if (sourceRow.import_sha256 !== expectedImportSha256) fail("source-import-digest-mismatch");
    if (sha256(sourceRow.state_text) !== expectedStateSha256) fail("source-state-digest-mismatch");

    const inserted = await client.query(
      `INSERT INTO ${qualified(targetSchema, TABLE)}
         (singleton, schema_version, revision, state, import_sha256, imported_at, updated_at)
       SELECT singleton, schema_version, revision, state, import_sha256, imported_at, updated_at
         FROM ${qualified(legacySchema, TABLE)}`,
    );
    if (inserted.rowCount !== 1) fail("insert-count-mismatch");

    const readback = await client.query(
      `SELECT singleton, schema_version, revision::text AS revision, state::text AS state_text,
              import_sha256, imported_at::text AS imported_at, updated_at::text AS updated_at
         FROM ${qualified(targetSchema, TABLE)}`,
    );
    if (readback.rowCount !== 1) fail("destination-readback-count-mismatch");
    const destinationRow = readback.rows[0];
    if (destinationRow.singleton !== true
      || destinationRow.schema_version !== sourceRow.schema_version
      || destinationRow.revision !== sourceRow.revision
      || destinationRow.import_sha256 !== sourceRow.import_sha256
      || destinationRow.imported_at !== sourceRow.imported_at
      || destinationRow.updated_at !== sourceRow.updated_at) {
      fail("destination-metadata-mismatch");
    }
    if (destinationRow.state_text !== sourceRow.state_text
      || sha256(destinationRow.state_text) !== expectedStateSha256) {
      fail("destination-state-digest-mismatch");
    }

    await client.query("COMMIT");
    transactionOpen = false;
    const result = {
      databaseOid: identity.databaseOid,
      importSha256: expectedImportSha256,
      legacyRelationOid: locked.legacy.oid,
      legacySchemaOid: locked.legacy.schemaOid,
      portalSchemaVersion: EXPECTED_SCHEMA_VERSION,
      revision: expectedRevision,
      schemaVersion: "p42-legacy-portal-state-transfer/v1",
      stateSha256: expectedStateSha256,
      status: "transferred",
      targetRelationOid: locked.target.oid,
      targetSchemaOid: locked.target.schemaOid,
    };
    result.transferHash = sha256(canonicalJson(result));
    process.stdout.write(`${canonicalJson(result)}\n`);
  } catch (error) {
    if (transactionOpen) await client.query("ROLLBACK").catch(() => {});
    if (error instanceof TransferError) throw error;
    throw new TransferError("database-operation-failed");
  } finally {
    await client.end().catch(() => {});
  }
}

async function databaseIdentity(client) {
  const result = await client.query(`SELECT current_user::regrole::oid::integer AS role_oid,
    d.oid::integer AS database_oid, d.datdba::integer AS database_owner_oid
    FROM pg_catalog.pg_database AS d WHERE d.datname = current_database()`);
  if (result.rowCount !== 1) fail("database-identity-mismatch");
  return {
    roleOid: result.rows[0].role_oid,
    databaseOid: result.rows[0].database_oid,
    databaseOwnerOid: result.rows[0].database_owner_oid,
  };
}

async function resolveRelations(client, targetSchema, legacySchema) {
  const result = await client.query(`SELECT requested.kind, n.oid::integer AS schema_oid,
      n.nspowner::integer AS schema_owner_oid, c.oid::integer AS relation_oid,
      c.relowner::integer AS relation_owner_oid
    FROM (VALUES ('target'::text, $1::text), ('legacy'::text, $2::text)) AS requested(kind, schema_name)
    LEFT JOIN pg_catalog.pg_namespace AS n ON n.nspname = requested.schema_name
    LEFT JOIN pg_catalog.pg_class AS c ON c.relnamespace = n.oid AND c.relname = $3
    ORDER BY requested.kind`, [targetSchema, legacySchema, TABLE]);
  if (result.rowCount !== 2) fail("relation-identity-mismatch");
  const values = Object.fromEntries(result.rows.map((row) => [row.kind, {
    kind: row.kind,
    schema: row.kind === "target" ? targetSchema : legacySchema,
    schemaOid: row.schema_oid,
    schemaOwnerOid: row.schema_owner_oid,
    oid: row.relation_oid,
    ownerOid: row.relation_owner_oid,
  }]));
  if (!values.target?.schemaOid || !values.target?.oid) fail("target-relation-missing");
  if (!values.legacy?.schemaOid || !values.legacy?.oid) fail("legacy-relation-missing");
  return values;
}

async function verifyPortalTableShape(client, relation) {
  const result = await client.query(`SELECT c.relkind, c.relpersistence, c.relispartition,
      c.relrowsecurity, c.relforcerowsecurity,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits AS i
        WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) AS no_inheritance,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t
        WHERE t.tgrelid=c.oid AND NOT t.tgisinternal) AS no_external_triggers,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite AS r WHERE r.ev_class=c.oid) AS no_rules,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy AS p WHERE p.polrelid=c.oid) AS no_policies,
      (SELECT pg_catalog.json_agg(pg_catalog.json_build_array(
          a.attname, pg_catalog.format_type(a.atttypid,a.atttypmod), a.attnotnull,
          pg_catalog.pg_get_expr(d.adbin,d.adrelid), a.attidentity, a.attgenerated
        ) ORDER BY a.attnum)
       FROM pg_catalog.pg_attribute AS a
       LEFT JOIN pg_catalog.pg_attrdef AS d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
       WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns,
      (SELECT pg_catalog.json_agg(pg_catalog.json_build_array(
          x.contype, pg_catalog.pg_get_constraintdef(x.oid,true)
        ) ORDER BY x.contype, pg_catalog.pg_get_constraintdef(x.oid,true))
       FROM pg_catalog.pg_constraint AS x WHERE x.conrelid=c.oid AND x.contype<>'n') AS constraints
    FROM pg_catalog.pg_class AS c WHERE c.oid=$1::oid`, [relation.oid]);
  if (result.rowCount !== 1) fail(`${relation.kind}-shape-mismatch`);
  const row = result.rows[0];
  const expectedColumns = [
    ["singleton", "boolean", true, "true", "", ""],
    ["schema_version", "integer", true, null, "", ""],
    ["revision", "bigint", true, "0", "", ""],
    ["state", "jsonb", true, null, "", ""],
    ["import_sha256", "text", true, null, "", ""],
    ["imported_at", "timestamp with time zone", true, "clock_timestamp()", "", ""],
    ["updated_at", "timestamp with time zone", true, "clock_timestamp()", "", ""],
  ];
  const expectedConstraints = [
    ["c", "CHECK (import_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)"],
    ["c", "CHECK (revision >= 0)"],
    ["c", "CHECK (schema_version = 1)"],
    ["c", "CHECK (singleton)"],
    ["p", "PRIMARY KEY (singleton)"],
  ];
  if (row.relkind !== "r" || row.relpersistence !== "p" || row.relispartition
    || row.relrowsecurity || row.relforcerowsecurity || !row.no_inheritance
    || !row.no_external_triggers || !row.no_rules || !row.no_policies
    || canonicalJson(row.columns) !== canonicalJson(expectedColumns)
    || canonicalJson(row.constraints) !== canonicalJson(expectedConstraints)) {
    fail(`${relation.kind}-shape-mismatch`);
  }
}

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) fail(`missing-${name.toLowerCase().replaceAll("_", "-")}`);
  return value;
}

function schemaEnv(name) {
  const value = requiredEnv(name);
  if (!IDENTIFIER.test(value)) fail(`invalid-${name.toLowerCase().replaceAll("_", "-")}`);
  return value;
}

function optionalSchemaEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const value = raw.trim();
  if (!IDENTIFIER.test(value)) fail(`invalid-${name.toLowerCase().replaceAll("_", "-")}`);
  return value;
}

function digestEnv(name) {
  const value = requiredEnv(name);
  if (!DIGEST.test(value)) fail(`invalid-${name.toLowerCase().replaceAll("_", "-")}`);
  return value;
}

function revisionEnv(name) {
  const value = requiredEnv(name);
  if (!/^(0|[1-9][0-9]{0,18})$/.test(value) || BigInt(value) > 9223372036854775807n) {
    fail(`invalid-${name.toLowerCase().replaceAll("_", "-")}`);
  }
  return value;
}

function qualified(schema, table) {
  return `${quoteIdentifier(schema)}.${quoteIdentifier(table)}`;
}

function quoteIdentifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function fail(code) {
  throw new TransferError(code);
}
