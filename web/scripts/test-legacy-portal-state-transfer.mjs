import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import pg from "pg";

const connectionString = process.env.P42_PORTAL_MIGRATION_DATABASE_URL?.trim();
if (!connectionString) throw new Error("P42_PORTAL_MIGRATION_DATABASE_URL is required for transfer integration tests");
const migrationSql = await readFile(path.resolve("migrations/001_portal_store.sql"), "utf8");
const transferScript = path.resolve("scripts/transfer-legacy-portal-state.mjs");
const admin = new pg.Client({ connectionString, connectionTimeoutMillis: 10_000 });
await admin.connect();
const runtimeRole = `p42_runtime_${randomUUID().replaceAll("-", "")}`;
await admin.query(`CREATE ROLE ${quoteIdentifier(runtimeRole)} NOLOGIN NOSUPERUSER NOINHERIT
  NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);

const passed = [];
const state = { marker: "sensitive-state-marker" };
const importSha256 = `sha256:${"7".repeat(64)}`;

try {
  await transferCase("success", async ({ legacy, target }) => {
    const result = await runTransfer({ legacy, target });
    const receipt = assertSuccessResult(result);
    if (receipt.status !== "transferred") throw new Error("initial transfer was not labeled transferred");
    const rows = await admin.query(`SELECT revision::text AS revision, state::text AS state_text, import_sha256,
      imported_at::text AS imported_at, updated_at::text AS updated_at FROM ${qualified(target, "p42_portal_state")}`);
    if (rows.rowCount !== 1 || rows.rows[0].revision !== "0" || rows.rows[0].import_sha256 !== importSha256
      || digest(rows.rows[0].state_text) !== stateDigest()) throw new Error("successful transfer readback mismatch");
  });

  await transferCase("source-destination-alias", async ({ legacy }) => {
    await expectFailure({ legacy, target: legacy }, "source-destination-alias");
  });

  await transferCase("nonempty-destination", async ({ legacy, target }) => {
    await seed(target);
    await expectFailure({ legacy, target }, "destination-not-reconcilable");
  });

  await transferCase("ambiguous-commit-reconciliation", async ({ legacy, target }) => {
    await expectFailure({
      legacy, target, extraEnv: { P42_PORTAL_TEST_FAULT_AFTER_COMMIT: "ambiguous-ack" },
    }, "commit-acknowledgment-ambiguous");
    const reconciled = assertSuccessResult(await runTransfer({ legacy, target }));
    if (reconciled.status !== "reconciled") throw new Error("retry did not emit a reconciled receipt");
    const markers = await admin.query(`SELECT transfer_id, binding_json FROM
      ${qualified(target, "p42_portal_state_transfer_provenance")}`);
    if (markers.rowCount !== 1 || markers.rows[0].transfer_id !== reconciled.transferId) {
      throw new Error("reconciled receipt was not bound to the durable provenance row");
    }
  });

  await transferCase("ambiguous-commit-reconciliation-after-destination-advance", async ({ legacy, target }) => {
    await expectFailure({
      legacy, target, extraEnv: { P42_PORTAL_TEST_FAULT_AFTER_COMMIT: "ambiguous-ack" },
    }, "commit-acknowledgment-ambiguous");
    await admin.query(`UPDATE ${qualified(target, "p42_portal_state")}
      SET revision=1, state='{"marker":"legitimate-advance"}'::jsonb, updated_at='2026-07-17T02:00:00Z'
      WHERE singleton=true`);
    const reconciled = assertSuccessResult(await runTransfer({ legacy, target }));
    if (reconciled.status !== "reconciled" || reconciled.revision !== "0") {
      throw new Error("advanced retry did not attest the historical transfer event");
    }
    const current = await admin.query(`SELECT revision::text AS revision, state::text AS state_text
      FROM ${qualified(target, "p42_portal_state")}`);
    if (current.rows[0]?.revision !== "1" || current.rows[0]?.state_text !== '{"marker": "legitimate-advance"}') {
      throw new Error("reconciliation modified legitimately advanced destination state");
    }
  });

  await transferCase("permissive-default-privileges-revoked", async ({ legacy, target }) => {
    await admin.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA ${quoteIdentifier(target)}
      GRANT ALL PRIVILEGES ON TABLES TO PUBLIC, ${quoteIdentifier(runtimeRole)}`);
    const receipt = assertSuccessResult(await runTransfer({ legacy, target }));
    if (receipt.status !== "transferred") throw new Error("default-ACL transfer did not complete");
    await assertProvenanceAclClosed(target);
  });

  await transferCase("preexisting-provenance-runtime-dml-revoked", async ({ legacy, target }) => {
    await createProvenanceTable(target);
    await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
      ${qualified(target, "p42_portal_state_transfer_provenance")} TO ${quoteIdentifier(runtimeRole)}`);
    await admin.query(`GRANT SELECT (transfer_id), UPDATE (binding_json) ON TABLE
      ${qualified(target, "p42_portal_state_transfer_provenance")} TO ${quoteIdentifier(runtimeRole)}`);
    const receipt = assertSuccessResult(await runTransfer({ legacy, target }));
    if (receipt.status !== "transferred") throw new Error("preexisting provenance transfer did not complete");
    await assertProvenanceAclClosed(target);
  });

  await transferCase("safe-benign-set-role-memberships", async ({ legacy, target }) => {
    const first = `p42_benign_first_${randomUUID().replaceAll("-", "")}`;
    const second = `p42_benign_second_${randomUUID().replaceAll("-", "")}`;
    await createRestrictedRole(first);
    await createRestrictedRole(second);
    try {
      await admin.query(`GRANT ${quoteIdentifier(second)} TO ${quoteIdentifier(first)}
        WITH INHERIT FALSE, SET TRUE`);
      await admin.query(`GRANT ${quoteIdentifier(first)} TO ${quoteIdentifier(runtimeRole)}
        WITH INHERIT FALSE, SET TRUE`);
      await admin.query(`GRANT SELECT, INSERT, UPDATE ON TABLE ${qualified(target, "p42_portal_state")}
        TO ${quoteIdentifier(runtimeRole)}`);
      const receipt = assertSuccessResult(await runTransfer({ legacy, target }));
      if (receipt.status !== "transferred") throw new Error("benign SET-role closure was rejected");
    } finally {
      await admin.query(`REVOKE ${quoteIdentifier(first)} FROM ${quoteIdentifier(runtimeRole)}`).catch(() => {});
      await admin.query(`REVOKE ${quoteIdentifier(second)} FROM ${quoteIdentifier(first)}`).catch(() => {});
      await admin.query(`DROP ROLE IF EXISTS ${quoteIdentifier(first)}, ${quoteIdentifier(second)}`).catch(() => {});
    }
  });

  await transferCase("noinherit-set-role-superuser-escalation-rejected", async ({ legacy, target }) => {
    const intermediary = `p42_intermediary_${randomUUID().replaceAll("-", "")}`;
    const elevated = `p42_elevated_${randomUUID().replaceAll("-", "")}`;
    await createRestrictedRole(intermediary);
    await admin.query(`CREATE ROLE ${quoteIdentifier(elevated)} NOLOGIN SUPERUSER`);
    try {
      await admin.query(`GRANT ${quoteIdentifier(elevated)} TO ${quoteIdentifier(intermediary)}
        WITH INHERIT FALSE, SET TRUE`);
      await admin.query(`GRANT ${quoteIdentifier(intermediary)} TO ${quoteIdentifier(runtimeRole)}
        WITH INHERIT FALSE, SET TRUE`);
      await assertSetRoleEscalation(intermediary, elevated);
      await expectFailure({ legacy, target }, "runtime-role-dangerous-set-closure");
      await assertEmpty(target);
    } finally {
      await admin.query(`REVOKE ${quoteIdentifier(intermediary)} FROM ${quoteIdentifier(runtimeRole)}`).catch(() => {});
      await admin.query(`REVOKE ${quoteIdentifier(elevated)} FROM ${quoteIdentifier(intermediary)}`).catch(() => {});
      await admin.query(`DROP ROLE IF EXISTS ${quoteIdentifier(intermediary)}, ${quoteIdentifier(elevated)}`).catch(() => {});
    }
  });

  await transferCase("timezone-datestyle-stable-reconciliation", async ({ legacy, target }) => {
    await expectFailure({
      legacy,
      target,
      extraEnv: {
        PGOPTIONS: "-c TimeZone=America/Denver -c DateStyle=SQL,DMY",
        P42_PORTAL_TEST_FAULT_AFTER_COMMIT: "ambiguous-ack",
      },
    }, "commit-acknowledgment-ambiguous");
    const marker = await admin.query(`SELECT transfer_id, binding_json FROM
      ${qualified(target, "p42_portal_state_transfer_provenance")}`);
    if (marker.rowCount !== 1) throw new Error("timezone transfer marker missing");
    const binding = JSON.parse(marker.rows[0].binding_json);
    if (binding.sourceImportedAt !== "2026-07-17T00:00:00.000000Z"
      || binding.sourceUpdatedAt !== "2026-07-17T01:00:00.000000Z") {
      throw new Error("bound timestamps were not canonical UTC microsecond text");
    }
    const receipt = assertSuccessResult(await runTransfer({
      legacy,
      target,
      extraEnv: { PGOPTIONS: "-c TimeZone=Asia/Tokyo -c DateStyle=German,DMY" },
    }));
    if (receipt.status !== "reconciled" || receipt.transferId !== marker.rows[0].transfer_id) {
      throw new Error("timezone change altered the transfer binding");
    }
  });

  await transferCase("empty-source", async ({ legacy, target }) => {
    await admin.query(`DELETE FROM ${qualified(legacy, "p42_portal_state")}`);
    await expectFailure({ legacy, target }, "source-not-singleton");
    await assertEmpty(target);
  });

  for (const [label, overrides, code] of [
    ["state-digest-mismatch", { stateSha256: `sha256:${"1".repeat(64)}` }, "source-state-digest-mismatch"],
    ["revision-mismatch", { revision: "1" }, "source-revision-mismatch"],
    ["import-digest-mismatch", { importSha256: `sha256:${"2".repeat(64)}` }, "source-import-digest-mismatch"],
  ]) {
    await transferCase(label, async ({ legacy, target }) => {
      await expectFailure({ legacy, target, ...overrides }, code);
      await assertEmpty(target);
    });
  }

  await transferCase("hostile-search-path", async ({ legacy, target, decoy }) => {
    await createMigratedSchema(decoy);
    await seed(decoy, { importDigest: `sha256:${"9".repeat(64)}` });
    const result = await runTransfer({ legacy, target, extraEnv: { PGOPTIONS: `-c search_path=${decoy}` } });
    assertSuccessResult(result);
  });

  await hostileCase("hostile-view", async ({ legacy }) => {
    await admin.query(`DROP TABLE ${qualified(legacy, "p42_portal_state")}`);
    await admin.query(`CREATE VIEW ${qualified(legacy, "p42_portal_state")} AS SELECT true AS singleton,
      1::integer AS schema_version, 0::bigint AS revision, '{}'::jsonb AS state,
      '${importSha256}'::text AS import_sha256, clock_timestamp() AS imported_at, clock_timestamp() AS updated_at`);
  }, "legacy-shape-mismatch");

  await hostileCase("hostile-schema-owner", async ({ target, hostileRole }) => {
    await admin.query(`ALTER SCHEMA ${quoteIdentifier(target)} OWNER TO ${quoteIdentifier(hostileRole)}`);
  }, "target-schema-owner-mismatch");

  await hostileCase("hostile-target-table-owner", async ({ target, hostileRole }) => {
    await admin.query(`ALTER TABLE ${qualified(target, "p42_portal_state")} OWNER TO ${quoteIdentifier(hostileRole)}`);
  }, "target-table-owner-mismatch");

  await hostileCase("hostile-table-owner", async ({ legacy, hostileRole }) => {
    await admin.query(`ALTER TABLE ${qualified(legacy, "p42_portal_state")} OWNER TO ${quoteIdentifier(hostileRole)}`);
  }, "legacy-table-owner-mismatch");

  await hostileCase("hostile-shape", async ({ legacy }) => {
    await admin.query(`ALTER TABLE ${qualified(legacy, "p42_portal_state")} ADD COLUMN planted text`);
  }, "legacy-shape-mismatch");

  await transferCase("hostile-database-owner", async ({ legacy, target }) => {
    const hostileRole = `p42_hostile_${randomUUID().replaceAll("-", "")}`;
    const role = quoteIdentifier(hostileRole);
    await admin.query(`CREATE ROLE ${role} NOLOGIN`);
    try {
      await admin.query(`GRANT ${role} TO CURRENT_USER`);
      await expectFailure({ legacy, target, extraEnv: { PGOPTIONS: `-c role=${hostileRole}` } }, "database-owner-mismatch");
      await assertEmpty(target);
    } finally {
      await admin.query(`REVOKE ${role} FROM CURRENT_USER`).catch(() => {});
      await admin.query(`DROP ROLE IF EXISTS ${role}`).catch(() => {});
    }
  });

  await transferCase("concurrent-writer-lock", async ({ legacy, target }) => {
    const holder = new pg.Client({ connectionString });
    await holder.connect();
    let child;
    try {
      await holder.query("BEGIN");
      await holder.query(`UPDATE ${qualified(legacy, "p42_portal_state")} SET state=state WHERE singleton=true`);
      const holderPid = (await holder.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      child = runTransferProcess({ legacy, target });
      let transferPid;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const activity = await admin.query(`SELECT pid FROM pg_catalog.pg_stat_activity
          WHERE application_name='p42-legacy-portal-state-transfer' AND pid<>pg_backend_pid()`);
        transferPid = activity.rows[0]?.pid;
        if (transferPid) {
          const blocking = await admin.query("SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked", [holderPid, transferPid]);
          if (blocking.rows[0]?.blocked) break;
        }
        await delay(20);
      }
      if (!transferPid) throw new Error("transfer connection was not observed");
      const blocking = await admin.query("SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked", [holderPid, transferPid]);
      if (!blocking.rows[0]?.blocked) throw new Error("transfer did not block behind the concurrent writer");
      await holder.query("COMMIT");
      const completed = await child;
      if (completed.code !== 0) throw new Error(`blocked transfer failed: ${completed.stderr}`);
      assertSuccessResult(completed);
    } finally {
      await holder.query("ROLLBACK").catch(() => {});
      await holder.end().catch(() => {});
      if (child) await child.catch(() => {});
    }
  });

  await transferCase("schema-rename-and-replace-fails-closed", async ({ legacy, target }) => {
    const moved = `${legacy}_moved`;
    const child = runTransferProcess({
      legacy, target, extraEnv: { P42_PORTAL_TEST_PAUSE_AFTER_RELATION_LOCK_MS: "1500" },
    });
    try {
      await waitForTransferPid();
      await delay(100);
      await admin.query(`ALTER SCHEMA ${quoteIdentifier(legacy)} RENAME TO ${quoteIdentifier(moved)}`);
      await createMigratedSchema(legacy);
      await seed(legacy, { importDigest: `sha256:${"8".repeat(64)}` });
      const completed = await child;
      if (completed.code === 0 || completed.stdout !== "") throw new Error("namespace replacement did not fail closed");
      const failure = JSON.parse(completed.stderr);
      if (failure.error !== "legacy-oid-binding-mismatch") {
        throw new Error(`namespace replacement failed with ${failure.error}`);
      }
      await assertEmpty(target);
      const marker = await admin.query(`SELECT to_regclass($1) IS NULL AS missing`,
        [`${target}.p42_portal_state_transfer_provenance`]);
      if (!marker.rows[0]?.missing) throw new Error("failed namespace race left provenance behind");
    } finally {
      await child.catch(() => {});
      await admin.query(`DROP SCHEMA IF EXISTS ${quoteIdentifier(moved)} CASCADE`).catch(() => {});
    }
  });

  await transferCase("target-schema-rename-and-replace-fails-closed", async ({ legacy, target }) => {
    const moved = `${target}_moved`;
    const child = runTransferProcess({
      legacy, target, extraEnv: { P42_PORTAL_TEST_PAUSE_AFTER_RELATION_LOCK_MS: "1500" },
    });
    try {
      await waitForTransferPid();
      await delay(100);
      await admin.query(`ALTER SCHEMA ${quoteIdentifier(target)} RENAME TO ${quoteIdentifier(moved)}`);
      await createMigratedSchema(target);
      const completed = await child;
      if (completed.code === 0 || completed.stdout !== "") throw new Error("target namespace replacement did not fail closed");
      const failure = JSON.parse(completed.stderr);
      if (failure.error !== "target-oid-binding-mismatch") {
        throw new Error(`target namespace replacement failed with ${failure.error}`);
      }
      await assertEmpty(target);
      await assertEmpty(moved);
      const marker = await admin.query(`SELECT to_regclass($1) IS NULL AS missing`,
        [`${moved}.p42_portal_state_transfer_provenance`]);
      if (!marker.rows[0]?.missing) throw new Error("failed target namespace race left provenance behind");
    } finally {
      await child.catch(() => {});
      await admin.query(`DROP SCHEMA IF EXISTS ${quoteIdentifier(moved)} CASCADE`).catch(() => {});
    }
  });

  await transferCase("queued-target-writer-after-commit", async ({ legacy, target }) => {
    const writer = new pg.Client({ connectionString, application_name: "p42-queued-target-writer" });
    await writer.connect();
    const child = runTransferProcess({
      legacy,
      target,
      extraEnv: {
        P42_PORTAL_TEST_PAUSE_AFTER_COMMIT_MS: "1000",
        P42_PORTAL_TEST_PAUSE_BEFORE_COMMIT_MS: "1500",
      },
    });
    try {
      const transferPid = await waitForTransferPid();
      await delay(200);
      const writerPid = (await writer.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      const write = writer.query(`UPDATE ${qualified(target, "p42_portal_state")}
        SET revision=1, state='{"marker":"post-transfer-writer"}'::jsonb, updated_at=clock_timestamp()
        WHERE singleton=true`);
      let blocked = false;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const check = await admin.query("SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked", [transferPid, writerPid]);
        if (check.rows[0]?.blocked) { blocked = true; break; }
        await delay(20);
      }
      if (!blocked) throw new Error("target writer was not queued across transfer commit");
      await write;
      const completed = await child;
      const receipt = assertSuccessResult(completed);
      const current = await admin.query(`SELECT revision::text AS revision, state::text AS state_text
        FROM ${qualified(target, "p42_portal_state")}`);
      if (current.rows[0]?.revision !== "1" || current.rows[0]?.state_text !== '{"marker": "post-transfer-writer"}') {
        throw new Error("queued target writer did not commit before receipt emission");
      }
      if (receipt.destinationCurrentStateAttested !== false
        || receipt.receiptScope !== "historical-committed-transfer-event-and-owner-controlled-provenance-row") {
        throw new Error("receipt falsely claims current destination state");
      }
    } finally {
      await writer.end().catch(() => {});
      await child.catch(() => {});
    }
  });

  await transferCase("rollback-and-secret-redaction", async ({ legacy, target }) => {
    const secret = `secret-${randomUUID()}`;
    const result = await runTransferProcess({
      legacy, target, importSha256: `sha256:${"3".repeat(64)}`,
      connectionString: withPassword(connectionString, secret),
    });
    if (result.code === 0 || !result.stderr.includes("source-import-digest-mismatch")) {
      throw new Error("redaction probe did not reach the expected failure");
    }
    const combined = `${result.stdout}\n${result.stderr}`;
    if (combined.includes(secret) || combined.includes(connectionString) || combined.includes(JSON.stringify(state))
      || combined.includes('{"marker": "sensitive-state-marker"}')) {
      throw new Error("transfer output exposed secret material");
    }
    if (result.stdout !== "") throw new Error("failed transfer emitted stdout");
    await assertEmpty(target);
  });

  const postgresVersion = (await admin.query("SHOW server_version")).rows[0].server_version;
  if (!/^18\.4(?:\s|$)/.test(postgresVersion)) {
    throw new Error(`integration harness requires PostgreSQL 18.4, received ${postgresVersion}`);
  }
  process.stdout.write(`${JSON.stringify({
    cases: passed,
    postgresVersion,
    schemaVersion: "p42-legacy-portal-state-transfer-test/v4",
    status: "passed",
  })}\n`);
} finally {
  await admin.query(`DROP ROLE IF EXISTS ${quoteIdentifier(runtimeRole)}`).catch(() => {});
  await admin.end();
}

async function transferCase(label, operation) {
  const suffix = randomUUID().replaceAll("-", "");
  const legacy = `p42_legacy_${suffix}`;
  const target = `p42_target_${suffix}`;
  const decoy = `p42_decoy_${suffix}`;
  try {
    await createMigratedSchema(legacy);
    await createMigratedSchema(target);
    await seed(legacy);
    await operation({ legacy, target, decoy });
    passed.push(label);
  } finally {
    for (const schema of [decoy, target, legacy]) {
      await admin.query(`DROP SCHEMA IF EXISTS ${quoteIdentifier(schema)} CASCADE`).catch(() => {});
    }
  }
}

async function hostileCase(label, mutation, expectedCode) {
  await transferCase(label, async ({ legacy, target }) => {
    const hostileRole = `p42_hostile_${randomUUID().replaceAll("-", "")}`;
    await admin.query(`CREATE ROLE ${quoteIdentifier(hostileRole)} NOLOGIN`);
    try {
      await mutation({ legacy, target, hostileRole });
      await expectFailure({ legacy, target }, expectedCode);
      await assertEmpty(target);
    } finally {
      await admin.query(`REASSIGN OWNED BY ${quoteIdentifier(hostileRole)} TO CURRENT_USER`).catch(() => {});
      await admin.query(`DROP OWNED BY ${quoteIdentifier(hostileRole)}`).catch(() => {});
      await admin.query(`DROP ROLE IF EXISTS ${quoteIdentifier(hostileRole)}`).catch(() => {});
    }
  });
}

async function createMigratedSchema(schema) {
  await admin.query(`CREATE SCHEMA ${quoteIdentifier(schema)}`);
  try {
    await admin.query("SELECT set_config('search_path',$1,false)", [quoteIdentifier(schema)]);
    await admin.query(migrationSql);
  } catch (error) {
    await admin.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    await admin.query("SELECT set_config('search_path','pg_catalog',false)").catch(() => {});
  }
}

async function createProvenanceTable(schema) {
  await admin.query(`CREATE TABLE ${qualified(schema, "p42_portal_state_transfer_provenance")} (
    transfer_id text PRIMARY KEY CHECK (transfer_id ~ '^sha256:[0-9a-f]{64}$'),
    binding_json text NOT NULL,
    committed_at timestamp with time zone NOT NULL DEFAULT clock_timestamp()
  )`);
}

async function createRestrictedRole(role) {
  await admin.query(`CREATE ROLE ${quoteIdentifier(role)} NOLOGIN NOSUPERUSER NOINHERIT
    NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
}

async function assertSetRoleEscalation(intermediary, elevated) {
  const probe = new pg.Client({ connectionString });
  await probe.connect();
  try {
    await probe.query(`SET SESSION AUTHORIZATION ${quoteIdentifier(runtimeRole)}`);
    await probe.query(`SET ROLE ${quoteIdentifier(intermediary)}`);
    await probe.query(`SET ROLE ${quoteIdentifier(elevated)}`);
    const identity = await probe.query(`SELECT current_user=$1 AS role_matches,
      (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user) AS is_superuser`, [elevated]);
    if (!identity.rows[0]?.role_matches || !identity.rows[0]?.is_superuser) {
      throw new Error("SET ROLE escalation reproduction did not reach the superuser role");
    }
  } finally {
    await probe.end().catch(() => {});
  }
}

async function assertProvenanceAclClosed(schema) {
  const relation = `${schema}.p42_portal_state_transfer_provenance`;
  const result = await admin.query(`SELECT
      NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c,
          LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) acl
        WHERE c.oid=$1::regclass AND acl.grantee<>c.relowner
      ) AS table_acl_closed,
      NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute a
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped
          AND a.attacl IS NOT NULL AND acl.grantee<>(SELECT relowner FROM pg_catalog.pg_class WHERE oid=$1::regclass)
      ) AS column_acl_closed,
      NOT pg_catalog.has_table_privilege($2, $1, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
        AS runtime_table_closed,
      NOT pg_catalog.has_any_column_privilege($2, $1, 'SELECT,INSERT,UPDATE,REFERENCES')
        AS runtime_column_closed`, [relation, runtimeRole]);
  const row = result.rows[0];
  if (!row?.table_acl_closed || !row.column_acl_closed || !row.runtime_table_closed || !row.runtime_column_closed) {
    throw new Error("provenance ACL closure verification failed");
  }
}

async function seed(schema, { importDigest = importSha256 } = {}) {
  await admin.query(`INSERT INTO ${qualified(schema, "p42_portal_state")}
    (singleton,schema_version,revision,state,import_sha256,imported_at,updated_at)
    VALUES(true,1,0,$1::jsonb,$2,'2026-07-17T00:00:00Z','2026-07-17T01:00:00Z')`, [JSON.stringify(state), importDigest]);
}

async function expectFailure(options, expectedCode) {
  const result = await runTransferProcess(options);
  if (result.code === 0) throw new Error(`transfer unexpectedly succeeded; expected ${expectedCode}`);
  if (result.stdout !== "") throw new Error("failed transfer emitted stdout");
  const failure = JSON.parse(result.stderr);
  if (failure.error !== expectedCode || failure.status !== "failed") {
    throw new Error(`expected ${expectedCode}, received ${failure.error}`);
  }
  return result;
}

async function runTransfer(options) {
  const result = await runTransferProcess(options);
  if (result.code !== 0) throw new Error(`transfer failed: ${result.stderr}`);
  return result;
}

function runTransferProcess({
  legacy, target, revision = "0", stateSha256 = stateDigest(), importSha256: expectedImport = importSha256,
  extraEnv = {}, connectionString: url = connectionString,
}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [transferScript], {
      cwd: path.resolve("."),
      env: {
        ...process.env,
        ...extraEnv,
        P42_PORTAL_MIGRATION_DATABASE_URL: url,
        P42_PORTAL_DATABASE_SCHEMA: target,
        P42_PORTAL_LEGACY_DATABASE_SCHEMA: legacy,
        P42_PORTAL_EXPECTED_STATE_SHA256: stateSha256,
        P42_PORTAL_EXPECTED_IMPORT_SHA256: expectedImport,
        P42_PORTAL_EXPECTED_REVISION: revision,
        P42_PORTAL_RUNTIME_DATABASE_ROLE: runtimeRole,
        PGAPPNAME: "p42-legacy-portal-state-transfer",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr, stdout }));
  });
}

function assertSuccessResult(result) {
  if (result.code !== 0 || result.stderr !== "" || result.stdout === "") {
    throw new Error(`transfer did not emit a success receipt: ${result.stderr || "empty stdout"}`);
  }
  const value = JSON.parse(result.stdout);
  const { receiptChecksum, ...checksummed } = value;
  if (!["transferred", "reconciled"].includes(value.status)
    || receiptChecksum !== digest(canonicalJson(checksummed))) throw new Error("receipt checksum mismatch");
  if (value.receiptChecksumPurpose !== "accidental-corruption-check-only-not-authentication-or-evidence") {
    throw new Error("receipt checksum was not labeled non-authenticating");
  }
  if (value.provenanceAuthority !== "database-owner-controlled-not-external-evidence"
    || value.externalEvidenceRequirement !== "external-signed-receipt-capture-required"
    || value.databaseOwnerRemainsAuthority !== true
    || value.timestampEncoding !== "utc-iso8601-microseconds") {
    throw new Error("receipt did not disclose its owner authority and external evidence boundary");
  }
  for (const key of ["databaseOid", "databaseOwnerRoleOid", "legacySchemaOid", "legacyRelationOid",
    "targetSchemaOid", "targetRelationOid"]) {
    if (!/^[1-9][0-9]*$/.test(value[key])) throw new Error(`transfer result has invalid ${key}`);
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(value.committedAt)
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(value.sourceImportedAt)
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(value.sourceUpdatedAt)) {
    throw new Error("receipt timestamps were not canonical UTC microsecond text");
  }
  return value;
}

async function waitForTransferPid() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const activity = await admin.query(`SELECT pid FROM pg_catalog.pg_stat_activity
      WHERE application_name='p42-legacy-portal-state-transfer' AND pid<>pg_backend_pid()
      ORDER BY backend_start DESC LIMIT 1`);
    if (activity.rows[0]?.pid) return activity.rows[0].pid;
    await delay(20);
  }
  throw new Error("transfer connection was not observed");
}

async function assertEmpty(schema) {
  const result = await admin.query(`SELECT count(*)::integer AS count FROM ${qualified(schema, "p42_portal_state")}`);
  if (result.rows[0]?.count !== 0) throw new Error("failed transfer did not roll back destination");
}

function stateDigest() {
  return digest('{"marker": "sensitive-state-marker"}');
}

function withPassword(value, password) {
  const encoded = encodeURIComponent(password);
  const updated = value.replace(/^(postgres(?:ql)?:\/\/)([^:@/?#]+)(?::[^@/?#]*)?@/, `$1$2:${encoded}@`);
  if (updated === value) throw new Error("test database URL must contain a username for credential redaction");
  return updated;
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function qualified(schema, table) {
  return `${quoteIdentifier(schema)}.${quoteIdentifier(table)}`;
}

function quoteIdentifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
