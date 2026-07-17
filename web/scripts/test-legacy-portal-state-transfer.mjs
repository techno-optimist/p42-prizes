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

const passed = [];
const state = { marker: "sensitive-state-marker" };
const importSha256 = `sha256:${"7".repeat(64)}`;

try {
  await transferCase("success", async ({ legacy, target }) => {
    const result = await runTransfer({ legacy, target });
    assertSuccessResult(result);
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
    await expectFailure({ legacy, target }, "destination-not-empty");
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

  process.stdout.write(`${JSON.stringify({
    cases: passed,
    postgresVersion: (await admin.query("SHOW server_version")).rows[0].server_version,
    schemaVersion: "p42-legacy-portal-state-transfer-test/v1",
    status: "passed",
  })}\n`);
} finally {
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
  const value = JSON.parse(result.stdout);
  const { transferHash, ...unsigned } = value;
  if (result.stderr !== "" || result.code !== 0 || value.status !== "transferred"
    || transferHash !== digest(canonicalJson(unsigned))) throw new Error("transfer result self-hash mismatch");
  for (const key of ["databaseOid", "legacySchemaOid", "legacyRelationOid", "targetSchemaOid", "targetRelationOid"]) {
    if (!Number.isInteger(value[key]) || value[key] <= 0) throw new Error(`transfer result has invalid ${key}`);
  }
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
