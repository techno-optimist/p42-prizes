import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const connectionString = process.env.P42_PORTAL_MIGRATION_DATABASE_URL?.trim();
if (!connectionString) throw new Error("P42_PORTAL_MIGRATION_DATABASE_URL is required for migration integration tests");
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
      `SELECT (SELECT count(*)::integer FROM p42_indexer_checkpoint_control WHERE singleton=true) AS controls,
              (SELECT count(*)::integer FROM p42_indexer_checkpoint_epoch) AS epochs`,
    );
    if (highWater.rows[0].controls !== 1 || highWater.rows[0].epochs !== 0) {
      throw new Error("fresh epoch control was not preseeded with empty history");
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

  await inTemporarySchema("epoch-control-missing-completeness-constraint", async (client) => {
    await applyMigrations(client);
    await client.query(
      "ALTER TABLE p42_indexer_checkpoint_control DROP CONSTRAINT p42_indexer_checkpoint_control_state_complete",
    );
    await expectMigrationFailure(client, migration2Sql, "does not match migration 2");
  });

  await inTemporarySchema("acceptance-history-same-name-check-true", async (client) => {
    await applyMigrations(client);
    await client.query(
      `ALTER TABLE p42_indexer_checkpoint_acceptance
         DROP CONSTRAINT p42_indexer_checkpoint_acceptance_block_hash_format,
         ADD CONSTRAINT p42_indexer_checkpoint_acceptance_block_hash_format CHECK (true)`,
    );
    await expectMigrationFailure(client, migration2Sql, "does not match migration 2");
  });

  await inTemporarySchema("epoch-control-same-name-check-true", async (client) => {
    await applyMigrations(client);
    await client.query(
      `ALTER TABLE p42_indexer_checkpoint_control
         DROP CONSTRAINT p42_indexer_checkpoint_control_state_complete,
         ADD CONSTRAINT p42_indexer_checkpoint_control_state_complete CHECK (true)`,
    );
    await expectMigrationFailure(client, migration2Sql, "does not match migration 2");
  });

  await inTemporarySchema("authority-same-name-check-true", async (client) => {
    await applyMigrations(client);
    await client.query(
      `ALTER TABLE p42_indexer_checkpoint_authority
         DROP CONSTRAINT p42_indexer_checkpoint_authority_oids_positive,
         ADD CONSTRAINT p42_indexer_checkpoint_authority_oids_positive CHECK (true)`,
    );
    await expectMigrationFailure(client, migration2Sql, "authority schema does not match migration 2");
  });

  await inTemporarySchema("security-definer-definition-restored", async (client) => {
    await applyMigrations(client);
    await client.query(`ALTER FUNCTION p42_transition_indexer_checkpoint(
      bigint,text,text,bigint,text,text,bigint,text,text,text) SET search_path=public`);
    await client.query(`ALTER FUNCTION p42_read_exact_indexer_checkpoint(
      bigint,text,text,bigint,text,text,bigint,text,text,text) SET search_path=public`);
    await applyMigrations(client);
    const functionRow = await client.query(`SELECT prosecdef, proconfig,
      pg_get_userbyid(proowner)=current_user AS exact_owner,
      prosrc=(SELECT transition_function_source FROM p42_indexer_checkpoint_authority WHERE singleton=true) AS exact_source
      FROM pg_proc WHERE oid='p42_transition_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)'::regprocedure`);
    const row = functionRow.rows[0];
    if (!row?.prosecdef || !row.exact_owner || !row.exact_source
      || JSON.stringify(row.proconfig) !== JSON.stringify(["search_path=pg_catalog"])) {
      throw new Error("migration did not restore the exact transition function authority");
    }
    const exactRow = (await client.query(`SELECT prosecdef,proconfig,
      pg_get_userbyid(proowner)=current_user AS exact_owner,
      prosrc=(SELECT exact_read_function_source FROM p42_indexer_checkpoint_authority WHERE singleton=true) AS exact_source
      FROM pg_proc WHERE oid='p42_read_exact_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)'::regprocedure`)).rows[0];
    if(!exactRow?.prosecdef||!exactRow.exact_owner||!exactRow.exact_source
      ||JSON.stringify(exactRow.proconfig)!==JSON.stringify(["search_path=pg_catalog"])) {
      throw new Error("migration did not restore the exact read function authority");
    }
  });

  await inTemporarySchema("forged-high-history-rejected", async (client) => {
    await applyMigrations(client);
    await callTransition(client, checkpoint("100", "1", "2", "1000"));
    await client.query(`INSERT INTO p42_indexer_checkpoint_epoch VALUES(
      99,$1,$2,84532,'baseSepolia',$3,$4,clock_timestamp())`,
    [`sha256:${"6".repeat(64)}`, `sha256:${"7".repeat(64)}`, "b".repeat(40), `0x${"8".repeat(64)}`]);
    await client.query(`INSERT INTO p42_indexer_checkpoint_acceptance VALUES(
      99,99,999,$1,$2,1999,clock_timestamp())`, [`0x${"9".repeat(64)}`, `sha256:${"a".repeat(64)}`]);
    await expectQueryFailure(() => callTransition(client, checkpoint("101", "b", "c", "1001")), "not contiguous and complete");
  });

  await inTemporarySchema("regressed-contiguous-upgrade-rejected", async (client) => {
    await applyMigrations(client);
    await callTransition(client, checkpoint("100", "1", "2", "1000"));
    await client.query(`INSERT INTO p42_indexer_checkpoint_acceptance(
      acceptance_id,epoch_id,finalized_block_number,finalized_block_hash,
      checkpoint_digest,checkpoint_timestamp,accepted_at)
      VALUES(2,1,50,$1,$2,900,clock_timestamp())`,
    [`0x${"6".repeat(64)}`, `sha256:${"7".repeat(64)}`]);
    await client.query(`UPDATE p42_indexer_checkpoint_control SET
      current_acceptance=2,next_acceptance=3,updated_at=clock_timestamp() WHERE singleton=true`);
    await expectMigrationFailure(client, migration2Sql, "semantic history regresses at acceptance 2");
  });

  await inTemporarySchema("nonadjacent-full-identity-replay-upgrade-rejected", async (client) => {
    await applyMigrations(client);
    const identityA = checkpoint("100", "1", "2", "1000");
    await callTransition(client, identityA);
    const identityB = checkpoint("101", "3", "6", "1001");
    identityB[4]=`sha256:${"7".repeat(64)}`; identityB[5]=`sha256:${"8".repeat(64)}`;
    identityB[8]="b".repeat(40); identityB[9]=`0x${"9".repeat(64)}`;
    await callTransition(client, identityB);
    await client.query("ALTER TABLE p42_indexer_checkpoint_epoch DROP CONSTRAINT p42_indexer_checkpoint_epoch_identity_key");
    await client.query(`INSERT INTO p42_indexer_checkpoint_epoch VALUES(
      3,$1,$2,84532,'baseSepolia',$3,$4,clock_timestamp())`,
    [identityA[4],identityA[5],identityA[8],identityA[9]]);
    await client.query(`INSERT INTO p42_indexer_checkpoint_acceptance VALUES(
      3,3,102,$1,$2,1002,clock_timestamp())`,[`0x${"a".repeat(64)}`,`sha256:${"b".repeat(64)}`]);
    await client.query(`UPDATE p42_indexer_checkpoint_control SET current_epoch=3,current_acceptance=3,
      next_epoch=4,next_acceptance=4,updated_at=clock_timestamp() WHERE singleton=true`);
    await expectMigrationFailure(client,migration2Sql,"historical full identity replay");
  });

  await inTemporarySchema("runtime-direct-rollback-denied", async (client, schema) => {
    await applyMigrations(client);
    const runtimeRole = `p42_runtime_${randomUUID().replaceAll("-", "")}`;
    const role = quoteIdentifier(runtimeRole);
    try {
      await admin.query(`CREATE ROLE ${role} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`);
      await client.query(`GRANT USAGE ON SCHEMA ${quoteIdentifier(schema)} TO ${role}`);
      await client.query(`GRANT SELECT ON p42_indexer_checkpoint_authority,p42_indexer_checkpoint_control,
        p42_indexer_checkpoint_epoch,p42_indexer_checkpoint_acceptance TO ${role}`);
      await client.query(`GRANT EXECUTE ON FUNCTION p42_transition_indexer_checkpoint(
        bigint,text,text,bigint,text,text,bigint,text,text,text) TO ${role}`);
      await client.query(`GRANT EXECUTE ON FUNCTION p42_read_exact_indexer_checkpoint(
        bigint,text,text,bigint,text,text,bigint,text,text,text) TO ${role}`);
      await client.query(`SET ROLE ${role}`);
      await callTransition(client, checkpoint("100", "1", "2", "1000"));
      await expectQueryFailure(() => client.query("UPDATE p42_indexer_checkpoint_control SET current_epoch=NULL"), "permission denied");
      await expectQueryFailure(() => client.query(`INSERT INTO p42_indexer_checkpoint_epoch VALUES(
        99,$1,$2,84532,'baseSepolia',$3,$4,clock_timestamp())`,
      [`sha256:${"6".repeat(64)}`, `sha256:${"7".repeat(64)}`, "b".repeat(40), `0x${"8".repeat(64)}`]), "permission denied");
      await expectQueryFailure(() => client.query("TRUNCATE p42_indexer_checkpoint_acceptance"), "permission denied");
      await client.query("RESET ROLE");
    } finally {
      await client.query("RESET ROLE").catch(() => {});
      await admin.query(`DROP OWNED BY ${role}`).catch(() => {});
      await admin.query(`DROP ROLE IF EXISTS ${role}`);
    }
  });

  await inTemporarySchema("noinherit-set-role-path-detected", async (client) => {
    await applyMigrations(client);
    const suffix = randomUUID().replaceAll("-", "");
    const runtimeName = `p42_runtime_${suffix}`; const dangerousName = `p42_danger_${suffix}`;
    const runtimeRole = quoteIdentifier(runtimeName); const dangerousRole = quoteIdentifier(dangerousName);
    try {
      await admin.query(`CREATE ROLE ${dangerousRole} NOLOGIN`);
      await admin.query(`CREATE ROLE ${runtimeRole} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`);
      await client.query(`GRANT UPDATE ON p42_indexer_checkpoint_control TO ${dangerousRole}`);
      await admin.query(`GRANT ${dangerousRole} TO ${runtimeRole} WITH INHERIT FALSE, SET TRUE`);
      const detected = await client.query(`SELECT pg_has_role($1,$2,'SET')
        AND has_table_privilege($2,'p42_indexer_checkpoint_control','UPDATE') AS dangerous`, [runtimeName, dangerousName]);
      if (!detected.rows[0]?.dangerous) throw new Error("NOINHERIT SET ROLE authority path was not detected");
    } finally {
      await admin.query(`REVOKE ${dangerousRole} FROM ${runtimeRole}`).catch(() => {});
      await admin.query(`DROP OWNED BY ${dangerousRole}`).catch(() => {});
      await admin.query(`DROP OWNED BY ${runtimeRole}`).catch(() => {});
      await admin.query(`DROP ROLE IF EXISTS ${runtimeRole}`).catch(() => {});
      await admin.query(`DROP ROLE IF EXISTS ${dangerousRole}`).catch(() => {});
    }
  });

  await inTemporarySchema("alternate-search-path-cannot-reset-authority", async (client, schema) => {
    await applyMigrations(client);
    await callTransition(client, checkpoint("100", "1", "2", "1000"));
    const alternate = `p42_parallel_${randomUUID().replaceAll("-", "")}`;
    try {
      await admin.query(`CREATE SCHEMA ${quoteIdentifier(alternate)}`);
      await client.query(`SET search_path TO ${quoteIdentifier(alternate)}`);
      await applyMigrations(client);
      await client.query(`SET search_path TO ${quoteIdentifier(alternate)},pg_catalog`);
      const original = await callTransition(client, checkpoint("101", "3", "4", "1001"), schema);
      if (original.rows[0]?.transition_kind !== "advance") {
        throw new Error("alternate search_path reset the pinned authority to epoch 1");
      }
    } finally {
      await client.query(`SET search_path TO ${quoteIdentifier(schema)}`);
      await admin.query(`DROP SCHEMA IF EXISTS ${quoteIdentifier(alternate)} CASCADE`);
    }
  });

  await inTemporarySchema("high-water-wrong-migration-name", async (client) => {
    await client.query(migration1Sql);
    await client.query("INSERT INTO p42_schema_migration (version, name) VALUES (2, 'wrong_name')");
    await expectMigrationFailure(client, migration2Sql, "version 2 is bound to another name");
  });

  await inTemporarySchema("high-water-failure-rolls-back", async (client) => {
    await client.query(migration1Sql);
    await client.query("CREATE TABLE p42_indexer_checkpoint_epoch (epoch_id bigint PRIMARY KEY)");
    await expectMigrationFailure(client, migration2Sql, "does not match migration 2");
    const result = await client.query(
      `SELECT count(*)::integer AS columns,
              (SELECT count(*)::integer FROM p42_schema_migration WHERE version = 2) AS migration_rows
         FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'p42_indexer_checkpoint_epoch'`,
    );
    if (result.rows[0].columns !== 1 || result.rows[0].migration_rows !== 0) {
      throw new Error("failed epoch migration left partial schema behind");
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
    await operation(client, schema);
    passed.push(label);
  } finally {
    await client.end().catch(() => {});
    await admin.query(`DROP SCHEMA IF EXISTS ${identifier} CASCADE`);
  }
}

function checkpoint(block, hashDigit, digestDigit, timestamp) {
  return [block, `0x${hashDigit.repeat(64)}`, `sha256:${digestDigit.repeat(64)}`, timestamp,
    `sha256:${"3".repeat(64)}`, `sha256:${"4".repeat(64)}`, "84532", "baseSepolia",
    "a".repeat(40), `0x${"5".repeat(64)}`];
}

async function callTransition(client, values, schema) {
  const prefix = schema ? `${quoteIdentifier(schema)}.` : "";
  return client.query(`SELECT * FROM ${prefix}p42_transition_indexer_checkpoint(
    $1::bigint,$2::text,$3::text,$4::bigint,$5::text,$6::text,$7::bigint,$8::text,$9::text,$10::text)`, values);
}

async function expectQueryFailure(operation, expectedMessage) {
  try { await operation(); } catch (error) {
    if (error instanceof Error && error.message.includes(expectedMessage)) return;
    throw error;
  }
  throw new Error(`query unexpectedly succeeded; expected ${expectedMessage}`);
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
