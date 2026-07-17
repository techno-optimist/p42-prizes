import { createHash } from "node:crypto";
import process from "node:process";
import pg from "pg";

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[a-z][a-z0-9_]{0,62}$/;
const TABLE = "p42_portal_state";
const PROVENANCE_TABLE = "p42_portal_state_transfer_provenance";
const EXPECTED_SCHEMA_VERSION = 1;

class TransferError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

main().catch((error) => {
  const code = error instanceof TransferError ? error.code : "database-operation-failed";
  process.stderr.write(`${canonicalJson({ error: code, schemaVersion: "p42-legacy-portal-state-transfer-error/v3", status: "failed" })}\n`);
  process.exitCode = 1;
});

async function main() {
  const connectionString = requiredEnv("P42_PORTAL_MIGRATION_DATABASE_URL");
  const targetSchema = schemaEnv("P42_PORTAL_DATABASE_SCHEMA");
  const legacySchema = optionalSchemaEnv("P42_PORTAL_LEGACY_DATABASE_SCHEMA", "public");
  const expectedStateSha256 = digestEnv("P42_PORTAL_EXPECTED_STATE_SHA256");
  const expectedImportSha256 = digestEnv("P42_PORTAL_EXPECTED_IMPORT_SHA256");
  const expectedRevision = revisionEnv("P42_PORTAL_EXPECTED_REVISION");
  const runtimeRoleName = roleEnv("P42_PORTAL_RUNTIME_DATABASE_ROLE");
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
    const runtimeRole = await resolveRuntimeRole(client, runtimeRoleName, identity.roleOid);

    const initial = await resolveRelations(client, targetSchema, legacySchema);
    if (initial.target.oid === initial.legacy.oid) fail("source-destination-alias");
    for (const relation of [initial.target, initial.legacy].sort(compareOid)) {
      await client.query(`LOCK TABLE ${qualified(relation.schema, TABLE)} IN ACCESS EXCLUSIVE MODE`);
    }
    await verifyAccessExclusiveLocks(client, [initial.target.oid, initial.legacy.oid]);

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

    await testPause("P42_PORTAL_TEST_PAUSE_AFTER_RELATION_LOCK_MS");
    await createOidBoundPortalView(client, "p42_locked_legacy", locked.legacy);
    await createOidBoundPortalView(client, "p42_locked_target", locked.target);
    await ensureProvenanceTable(client, locked.target, identity.roleOid, runtimeRole);
    const sourceRow = await readSingleton(client, "p42_locked_legacy", "source");
    verifyExpectedSource(sourceRow, { expectedImportSha256, expectedRevision, expectedStateSha256 });

    const binding = {
      databaseOid: identity.databaseOid,
      databaseOwnerRoleOid: identity.roleOid,
      importSha256: expectedImportSha256,
      legacyRelationOid: locked.legacy.oid,
      legacySchemaOid: locked.legacy.schemaOid,
      portalSchemaVersion: EXPECTED_SCHEMA_VERSION,
      revision: expectedRevision,
      runtimeRoleOid: runtimeRole.oid,
      sourceImportedAt: sourceRow.imported_at,
      sourceUpdatedAt: sourceRow.updated_at,
      stateSha256: expectedStateSha256,
      targetRelationOid: locked.target.oid,
      targetSchemaOid: locked.target.schemaOid,
    };
    const bindingJson = canonicalJson(binding);
    const transferId = sha256(bindingJson);
    let status;
    let committedAt;
    const existingMarker = await client.query(`SELECT binding_json, committed_at::text AS committed_at
      FROM pg_temp.p42_locked_provenance WHERE transfer_id=$1`, [transferId]);

    if (existingMarker.rowCount === 1 && existingMarker.rows[0].binding_json === bindingJson) {
      committedAt = existingMarker.rows[0].committed_at;
      status = "reconciled";
    } else {
      if (existingMarker.rowCount !== 0) fail("destination-not-reconcilable");
      const destination = await client.query("SELECT count(*)::integer AS count FROM pg_temp.p42_locked_target");
      if (destination.rows[0]?.count !== 0) fail("destination-not-reconcilable");
      const inserted = await client.query(`INSERT INTO pg_temp.p42_locked_target
          (singleton, schema_version, revision, state, import_sha256, imported_at, updated_at)
        SELECT singleton, schema_version, revision, state, import_sha256, imported_at, updated_at
          FROM pg_temp.p42_locked_legacy`);
      if (inserted.rowCount !== 1) fail("insert-count-mismatch");
      await verifyDestination(client, sourceRow, expectedStateSha256);
      const marker = await client.query(`INSERT INTO pg_temp.p42_locked_provenance
          (transfer_id, binding_json, committed_at)
        VALUES ($1, $2, clock_timestamp()) RETURNING committed_at::text AS committed_at`, [transferId, bindingJson]);
      if (marker.rowCount !== 1) fail("provenance-insert-count-mismatch");
      committedAt = marker.rows[0].committed_at;
      status = "transferred";
    }

    await testPause("P42_PORTAL_TEST_PAUSE_BEFORE_COMMIT_MS");
    await client.query("COMMIT");
    transactionOpen = false;
    if (process.env.P42_PORTAL_TEST_FAULT_AFTER_COMMIT === "ambiguous-ack") {
      throw new TransferError("commit-acknowledgment-ambiguous");
    }
    await testPause("P42_PORTAL_TEST_PAUSE_AFTER_COMMIT_MS");

    const result = {
      ...binding,
      committedAt,
      databaseOwnerRemainsAuthority: true,
      destinationCurrentStateAttested: false,
      externalEvidenceRequirement: "external-signed-receipt-capture-required",
      provenanceAuthority: "database-owner-controlled-not-external-evidence",
      receiptChecksumPurpose: "accidental-corruption-check-only-not-authentication-or-evidence",
      receiptScope: "historical-committed-transfer-event-and-owner-controlled-provenance-row",
      schemaVersion: "p42-legacy-portal-state-transfer/v3",
      status,
      transferId,
    };
    result.receiptChecksum = sha256(canonicalJson(result));
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
  const result = await client.query(`SELECT current_user::regrole::oid::text AS role_oid,
    d.oid::text AS database_oid, d.datdba::text AS database_owner_oid
    FROM pg_catalog.pg_database AS d WHERE d.datname = current_database()`);
  if (result.rowCount !== 1) fail("database-identity-mismatch");
  return {
    roleOid: result.rows[0].role_oid,
    databaseOid: result.rows[0].database_oid,
    databaseOwnerOid: result.rows[0].database_owner_oid,
  };
}

async function resolveRuntimeRole(client, roleName, ownerOid) {
  const result = await client.query(`SELECT oid::text AS oid, rolsuper, rolbypassrls,
      pg_catalog.pg_has_role(oid, $2::oid, 'MEMBER') AS inherits_owner
    FROM pg_catalog.pg_roles WHERE rolname=$1`, [roleName, ownerOid]);
  if (result.rowCount !== 1) fail("runtime-role-missing");
  const role = result.rows[0];
  if (role.oid === ownerOid || role.rolsuper || role.rolbypassrls || role.inherits_owner) {
    fail("runtime-role-not-separable-from-owner");
  }
  return { name: roleName, oid: role.oid };
}

async function resolveRelations(client, targetSchema, legacySchema) {
  const result = await client.query(`SELECT requested.kind, n.oid::text AS schema_oid,
      n.nspowner::text AS schema_owner_oid, c.oid::text AS relation_oid,
      c.relowner::text AS relation_owner_oid
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

async function createOidBoundPortalView(client, viewName, relation) {
  const current = await relationNameByOid(client, relation.oid);
  try {
    await client.query(`CREATE TEMP VIEW ${quoteIdentifier(viewName)} AS
      SELECT singleton, schema_version, revision, state, import_sha256, imported_at, updated_at
      FROM ${qualified(current.schema, current.table)}`);
  } catch {
    fail(`${relation.kind}-oid-binding-mismatch`);
  }
  const dependency = await client.query(`SELECT DISTINCT d.refobjid::text AS oid
    FROM pg_catalog.pg_class AS v
    JOIN pg_catalog.pg_rewrite AS r ON r.ev_class=v.oid
    JOIN pg_catalog.pg_depend AS d ON d.classid='pg_rewrite'::regclass AND d.objid=r.oid
      AND d.refclassid='pg_class'::regclass AND d.deptype='n'
    WHERE v.relnamespace=pg_my_temp_schema() AND v.relname=$1 AND d.refobjid<>v.oid`, [viewName]);
  if (dependency.rowCount !== 1 || dependency.rows[0].oid !== relation.oid) {
    fail(`${relation.kind}-oid-binding-mismatch`);
  }
}

async function relationNameByOid(client, oid) {
  const result = await client.query(`SELECT n.nspname AS schema_name, c.relname AS table_name
    FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
    WHERE c.oid=$1::oid`, [oid]);
  if (result.rowCount !== 1) fail("relation-identity-changed");
  return { schema: result.rows[0].schema_name, table: result.rows[0].table_name };
}

async function ensureProvenanceTable(client, target, roleOid, runtimeRole) {
  const namespace = await client.query(`SELECT nspname, nspowner::text AS owner_oid
    FROM pg_catalog.pg_namespace WHERE oid=$1::oid`, [target.schemaOid]);
  if (namespace.rowCount !== 1 || namespace.rows[0].owner_oid !== roleOid) fail("target-schema-identity-changed");
  const schema = namespace.rows[0].nspname;
  await client.query(`CREATE TABLE IF NOT EXISTS ${qualified(schema, PROVENANCE_TABLE)} (
    transfer_id text PRIMARY KEY CHECK (transfer_id ~ '^sha256:[0-9a-f]{64}$'),
    binding_json text NOT NULL,
    committed_at timestamp with time zone NOT NULL DEFAULT clock_timestamp()
  )`);
  const resolved = await client.query(`SELECT c.oid::text AS oid, c.relnamespace::text AS schema_oid,
      c.relowner::text AS owner_oid
    FROM pg_catalog.pg_class AS c WHERE c.relnamespace=$1::oid AND c.relname=$2`, [target.schemaOid, PROVENANCE_TABLE]);
  if (resolved.rowCount !== 1 || resolved.rows[0].schema_oid !== target.schemaOid
    || resolved.rows[0].owner_oid !== roleOid) fail("provenance-identity-mismatch");
  const relation = { kind: "provenance", oid: resolved.rows[0].oid };
  await client.query(`LOCK TABLE ${qualified(schema, PROVENANCE_TABLE)} IN ACCESS EXCLUSIVE MODE`);
  await verifyAccessExclusiveLocks(client, [relation.oid], "provenance-lock-mismatch");
  await verifyProvenanceTableShape(client, relation);
  const current = await relationNameByOid(client, relation.oid);
  await revokeProvenancePrivileges(client, current, runtimeRole.name);
  await verifyProvenanceAclClosure(client, relation, roleOid, runtimeRole.oid);
  await client.query(`CREATE TEMP VIEW p42_locked_provenance AS
    SELECT transfer_id, binding_json, committed_at FROM ${qualified(current.schema, current.table)}`);
  const dependency = await client.query(`SELECT DISTINCT d.refobjid::text AS oid
    FROM pg_catalog.pg_class AS v JOIN pg_catalog.pg_rewrite AS r ON r.ev_class=v.oid
    JOIN pg_catalog.pg_depend AS d ON d.classid='pg_rewrite'::regclass AND d.objid=r.oid
      AND d.refclassid='pg_class'::regclass AND d.deptype='n'
    WHERE v.relnamespace=pg_my_temp_schema() AND v.relname='p42_locked_provenance' AND d.refobjid<>v.oid`);
  if (dependency.rowCount !== 1 || dependency.rows[0].oid !== relation.oid) fail("provenance-oid-binding-mismatch");
  return relation;
}

async function revokeProvenancePrivileges(client, relation, runtimeRoleName) {
  const table = qualified(relation.schema, relation.table);
  const grantees = `PUBLIC, ${quoteIdentifier(runtimeRoleName)}`;
  await client.query(`REVOKE ALL PRIVILEGES ON TABLE ${table} FROM ${grantees}`);
  await client.query(`REVOKE ALL PRIVILEGES
    (transfer_id, binding_json, committed_at) ON TABLE ${table} FROM ${grantees}`);
}

async function verifyProvenanceAclClosure(client, relation, ownerOid, runtimeRoleOid) {
  const result = await client.query(`SELECT
      NOT EXISTS (
        SELECT 1 FROM pg_catalog.aclexplode(
          COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) AS acl
        WHERE acl.grantee<>c.relowner
      ) AS table_acl_closed,
      NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute AS a
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) AS acl
        WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
          AND a.attacl IS NOT NULL AND acl.grantee<>c.relowner
      ) AS column_acl_closed,
      NOT pg_catalog.has_table_privilege($2::oid, c.oid,
        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS runtime_table_closed,
      NOT pg_catalog.has_any_column_privilege($2::oid, c.oid,
        'SELECT,INSERT,UPDATE,REFERENCES') AS runtime_column_closed
    FROM pg_catalog.pg_class AS c WHERE c.oid=$1::oid AND c.relowner=$3::oid`,
  [relation.oid, runtimeRoleOid, ownerOid]);
  const row = result.rows[0];
  if (result.rowCount !== 1 || !row.table_acl_closed || !row.column_acl_closed
    || !row.runtime_table_closed || !row.runtime_column_closed) fail("provenance-acl-not-closed");
}

async function verifyAccessExclusiveLocks(client, relationOids, code = "relation-lock-mismatch") {
  const result = await client.query(`SELECT relation::text AS oid FROM pg_catalog.pg_locks
    WHERE locktype='relation' AND pid=pg_backend_pid() AND granted
      AND mode='AccessExclusiveLock' AND relation=ANY($1::oid[])`, [relationOids]);
  const held = new Set(result.rows.map((row) => row.oid));
  if (relationOids.some((oid) => !held.has(oid))) fail(code);
}

async function verifyProvenanceTableShape(client, relation) {
  const result = await client.query(`SELECT c.relkind, c.relpersistence, c.relispartition,
      c.relrowsecurity, c.relforcerowsecurity,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) AS no_inheritance,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal) AS no_external_triggers,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class=c.oid) AS no_rules,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid=c.oid) AS no_policies,
      (SELECT pg_catalog.json_agg(pg_catalog.json_build_array(a.attname,
        pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,
        pg_catalog.pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated) ORDER BY a.attnum)
       FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d
         ON d.adrelid=a.attrelid AND d.adnum=a.attnum
       WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns,
      (SELECT pg_catalog.json_agg(pg_catalog.json_build_array(x.contype,
        pg_catalog.pg_get_constraintdef(x.oid,true)) ORDER BY x.contype,pg_catalog.pg_get_constraintdef(x.oid,true))
       FROM pg_catalog.pg_constraint x WHERE x.conrelid=c.oid AND x.contype<>'n') AS constraints
    FROM pg_catalog.pg_class c WHERE c.oid=$1::oid`, [relation.oid]);
  const row = result.rows[0];
  const expectedColumns = [
    ["transfer_id", "text", true, null, "", ""],
    ["binding_json", "text", true, null, "", ""],
    ["committed_at", "timestamp with time zone", true, "clock_timestamp()", "", ""],
  ];
  const expectedConstraints = [
    ["c", "CHECK (transfer_id ~ '^sha256:[0-9a-f]{64}$'::text)"],
    ["p", "PRIMARY KEY (transfer_id)"],
  ];
  if (result.rowCount !== 1 || row.relkind !== "r" || row.relpersistence !== "p" || row.relispartition
    || row.relrowsecurity || row.relforcerowsecurity || !row.no_inheritance || !row.no_external_triggers
    || !row.no_rules || !row.no_policies || canonicalJson(row.columns) !== canonicalJson(expectedColumns)
    || canonicalJson(row.constraints) !== canonicalJson(expectedConstraints)) fail("provenance-shape-mismatch");
}

async function readSingleton(client, viewName, prefix) {
  const result = await client.query(`SELECT singleton, schema_version, revision::text AS revision,
      state::text AS state_text, import_sha256, imported_at::text AS imported_at, updated_at::text AS updated_at
    FROM pg_temp.${quoteIdentifier(viewName)}`);
  if (result.rowCount !== 1 || result.rows[0]?.singleton !== true) fail(`${prefix}-not-singleton`);
  return result.rows[0];
}

function verifyExpectedSource(sourceRow, expected) {
  if (sourceRow.schema_version !== EXPECTED_SCHEMA_VERSION) fail("source-schema-version-mismatch");
  if (sourceRow.revision !== expected.expectedRevision) fail("source-revision-mismatch");
  if (sourceRow.import_sha256 !== expected.expectedImportSha256) fail("source-import-digest-mismatch");
  if (sha256(sourceRow.state_text) !== expected.expectedStateSha256) fail("source-state-digest-mismatch");
}

async function verifyDestination(client, sourceRow, expectedStateSha256) {
  const destinationRow = await readSingleton(client, "p42_locked_target", "destination-readback");
  if (destinationRow.schema_version !== sourceRow.schema_version || destinationRow.revision !== sourceRow.revision
    || destinationRow.import_sha256 !== sourceRow.import_sha256 || destinationRow.imported_at !== sourceRow.imported_at
    || destinationRow.updated_at !== sourceRow.updated_at) fail("destination-metadata-mismatch");
  if (destinationRow.state_text !== sourceRow.state_text || sha256(destinationRow.state_text) !== expectedStateSha256) {
    fail("destination-state-digest-mismatch");
  }
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

function roleEnv(name) {
  const value = requiredEnv(name);
  if (value.includes("\0") || Buffer.byteLength(value, "utf8") > 63) {
    fail(`invalid-${name.toLowerCase().replaceAll("_", "-")}`);
  }
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

function compareOid(a, b) {
  return BigInt(a.oid) < BigInt(b.oid) ? -1 : BigInt(a.oid) > BigInt(b.oid) ? 1 : 0;
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

async function testPause(name) {
  const raw = process.env[name];
  if (raw === undefined) return;
  if (!/^[1-9][0-9]{0,4}$/.test(raw)) fail(`invalid-${name.toLowerCase().replaceAll("_", "-")}`);
  await new Promise((resolve) => setTimeout(resolve, Number(raw)));
}

function fail(code) {
  throw new TransferError(code);
}
