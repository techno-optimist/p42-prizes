import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const runtimeUrl = process.env.P42_PORTAL_DATABASE_URL?.trim();
const migrationUrl = process.env.P42_PORTAL_MIGRATION_DATABASE_URL?.trim();
if (!runtimeUrl || !migrationUrl) throw new Error("separate runtime and migration database URLs are required for rehearsal");
if (runtimeUrl === migrationUrl) throw new Error("runtime and migration database URLs must be distinct");

const runtimePool = new pg.Pool({ connectionString: runtimeUrl, max: 10, connectionTimeoutMillis: 10_000 });
const ownerPool = new pg.Pool({ connectionString: migrationUrl, max: 3, connectionTimeoutMillis: 10_000 });
const policyId = `p42-db-rehearsal-${randomUUID()}`;
const subject = "concurrent-probe";
const startedAt = new Date().toISOString();
let cleanupComplete = false;
const migration1Sql = await readFile(path.resolve("migrations/001_portal_store.sql"), "utf8");
const migration2Sql = await readFile(path.resolve("migrations/002_indexer_checkpoint_high_water.sql"), "utf8");

try {
  const version = await runtimePool.query("SELECT current_setting('server_version') AS server_version");
  const stateSnapshot = await rehearseStateLock();
  const highWater = await rehearseHighWaterLock();

  const increments = 8;
  await Promise.all(Array.from({ length: increments }, () => runtimePool.query(
    `INSERT INTO p42_rate_limit_bucket (policy_id, subject, count, expires_at)
     VALUES ($1, $2, 1, clock_timestamp() + interval '5 minutes')
     ON CONFLICT (policy_id, subject) DO UPDATE
       SET count = p42_rate_limit_bucket.count + 1,
           expires_at = EXCLUDED.expires_at`,
    [policyId, subject],
  )));
  const bucket = await runtimePool.query(
    "SELECT count FROM p42_rate_limit_bucket WHERE policy_id = $1 AND subject = $2",
    [policyId, subject],
  );
  if (bucket.rowCount !== 1 || bucket.rows[0].count !== increments) {
    throw new Error("atomic rate-limit upsert lost a concurrent increment");
  }

  const cleanup = await runtimePool.query(
    "DELETE FROM p42_rate_limit_bucket WHERE policy_id = $1 AND subject = $2",
    [policyId, subject],
  );
  if (cleanup.rowCount !== 1) {
    throw new Error("rate-limit rehearsal row cleanup was not confirmed");
  }
  cleanupComplete = true;

  process.stdout.write(`${JSON.stringify({
    schemaVersion: "p42-portal-db-rehearsal/v1",
    status: "passed",
    startedAt,
    completedAt: new Date().toISOString(),
    postgresVersion: version.rows[0].server_version,
    stateRevision: String(stateSnapshot.revision),
    stateSha256: `sha256:${createHash("sha256").update(stateSnapshot.stateText).digest("hex")}`,
    concurrentStateConnections: 2,
    blockingVerified: true,
    concurrentCheckpointConnections: 2,
    migrationRuntimeRolesDistinct: highWater.ownerRole !== highWater.runtimeRole,
    runtimeHistoryMutationDenied: true,
    acceptedCheckpointBlock: highWater.acceptedBlock,
    staleCheckpointBlock: highWater.staleBlock,
    staleCheckpointRejectedAfterLock: true,
    concurrentRateIncrements: increments,
  })}\n`);
} finally {
  if (!cleanupComplete) {
    await runtimePool.query(
      "DELETE FROM p42_rate_limit_bucket WHERE policy_id = $1 AND subject = $2",
      [policyId, subject],
    ).catch(() => {});
  }
  await runtimePool.end();
  await ownerPool.end();
}

async function rehearseHighWaterLock() {
  const schema = `p42_high_water_rehearsal_${randomUUID().replaceAll("-", "")}`;
  const identifier = quoteIdentifier(schema);
  const migrator = await ownerPool.connect();
  const holder = await runtimePool.connect();
  const waiter = await runtimePool.connect();
  let waiterLock;
  try {
    await ownerPool.query(`CREATE SCHEMA ${identifier}`);
    await migrator.query(`SET search_path TO ${identifier}`);
    await migrator.query(migration1Sql);
    await migrator.query(migration2Sql);
    const runtimeRole = (await holder.query("SELECT current_user AS role")).rows[0].role;
    const ownerRole = (await migrator.query("SELECT current_user AS role")).rows[0].role;
    if (runtimeRole === ownerRole) throw new Error("rehearsal runtime role is the schema owner");
    await migrator.query(`GRANT USAGE ON SCHEMA ${identifier} TO ${quoteIdentifier(runtimeRole)}`);
    await migrator.query(`GRANT SELECT, UPDATE ON p42_indexer_checkpoint_control TO ${quoteIdentifier(runtimeRole)}`);
    await migrator.query(`GRANT SELECT, INSERT ON p42_indexer_checkpoint_epoch TO ${quoteIdentifier(runtimeRole)}`);
    await migrator.query(`GRANT SELECT, INSERT ON p42_indexer_checkpoint_acceptance TO ${quoteIdentifier(runtimeRole)}`);
    await holder.query(`SET search_path TO ${identifier}`);
    await waiter.query(`SET search_path TO ${identifier}`);
    await holder.query("BEGIN");
    await holder.query("SET LOCAL lock_timeout = '5s'");
    await holder.query("SET LOCAL statement_timeout = '15s'");
    await waiter.query("BEGIN");
    await waiter.query("SET LOCAL lock_timeout = '5s'");
    await waiter.query("SET LOCAL statement_timeout = '15s'");

    const holderPid = (await holder.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
    const waiterPid = (await waiter.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
    const authority = await holder.query(`SELECT
      EXISTS (SELECT 1 FROM pg_class WHERE oid IN ('p42_indexer_checkpoint_control'::regclass,
        'p42_indexer_checkpoint_epoch'::regclass,'p42_indexer_checkpoint_acceptance'::regclass) AND pg_get_userbyid(relowner)=current_user) AS owns,
      has_schema_privilege(current_user, current_schema(), 'CREATE') AS can_create,
      (has_table_privilege(current_user, 'p42_indexer_checkpoint_control', 'TRIGGER') OR
       has_table_privilege(current_user, 'p42_indexer_checkpoint_epoch', 'TRIGGER') OR
       has_table_privilege(current_user, 'p42_indexer_checkpoint_acceptance', 'TRIGGER')) AS can_trigger,
      (has_table_privilege(current_user, 'p42_indexer_checkpoint_epoch', 'UPDATE') OR
       has_table_privilege(current_user, 'p42_indexer_checkpoint_epoch', 'DELETE') OR
       has_table_privilege(current_user, 'p42_indexer_checkpoint_acceptance', 'UPDATE') OR
       has_table_privilege(current_user, 'p42_indexer_checkpoint_acceptance', 'DELETE')) AS can_mutate_history,
      (has_table_privilege(current_user, 'p42_indexer_checkpoint_control', 'INSERT') OR
       has_table_privilege(current_user, 'p42_indexer_checkpoint_control', 'DELETE')) AS can_replace_control,
      EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid IN ('p42_indexer_checkpoint_control'::regclass,
        'p42_indexer_checkpoint_epoch'::regclass,'p42_indexer_checkpoint_acceptance'::regclass) AND NOT tgisinternal) AS external_triggers`);
    if (authority.rows[0].owns || authority.rows[0].can_create || authority.rows[0].can_trigger
      || authority.rows[0].can_mutate_history || authority.rows[0].can_replace_control
      || authority.rows[0].external_triggers) throw new Error("rehearsal runtime role is not least-privilege");
    const first = await holder.query(`SELECT current_epoch,current_acceptance,next_epoch,next_acceptance
      FROM p42_indexer_checkpoint_control WHERE singleton=true FOR UPDATE`);
    if (first.rowCount !== 1 || first.rows[0].current_epoch !== null || first.rows[0].current_acceptance!==null
      || String(first.rows[0].next_epoch)!=="1" || String(first.rows[0].next_acceptance)!=="1") {
      throw new Error("isolated epoch control was not fresh and lockable");
    }

    const acceptedBlock = "101";
    const staleBlock = "100";
    const insertedEpoch=await holder.query(`INSERT INTO p42_indexer_checkpoint_epoch(epoch_id,
      release_binding_digest,authorization_digest,chain_id,chain_name,deployment_commit,deployment_config_hash,accepted_at)
      VALUES(1,$1,$2,$3,$4,$5,$6,clock_timestamp()) RETURNING epoch_id`,[
      `sha256:${"3".repeat(64)}`,`sha256:${"4".repeat(64)}`,"84532","baseSepolia","a".repeat(40),`0x${"5".repeat(64)}`]);
    if(insertedEpoch.rowCount!==1||String(insertedEpoch.rows[0].epoch_id)!=="1") throw new Error("first identity epoch insert mismatch");
    const inserted = await holder.query(
      `INSERT INTO p42_indexer_checkpoint_acceptance(acceptance_id,epoch_id,finalized_block_number,
        finalized_block_hash,checkpoint_digest,checkpoint_timestamp,accepted_at)
       VALUES(1,1,$1,$2,$3,$4,clock_timestamp()) RETURNING acceptance_id,finalized_block_number`,
      [
        acceptedBlock,`0x${"1".repeat(64)}`,`sha256:${"2".repeat(64)}`,"1001",
      ],
    );
    if (inserted.rowCount !== 1 || String(inserted.rows[0].acceptance_id) !== "1"
      || String(inserted.rows[0].finalized_block_number) !== acceptedBlock) throw new Error("first epoch insert mismatch");
    const advanced = await holder.query(`UPDATE p42_indexer_checkpoint_control
      SET current_epoch=1,current_acceptance=1,next_epoch=2,next_acceptance=2,updated_at=clock_timestamp()
      WHERE singleton=true RETURNING current_epoch,current_acceptance,next_epoch,next_acceptance`);
    if (advanced.rowCount !== 1 || String(advanced.rows[0].current_epoch) !== "1"
      ||String(advanced.rows[0].current_acceptance)!=="1"||String(advanced.rows[0].next_epoch)!=="2"
      ||String(advanced.rows[0].next_acceptance)!=="2") throw new Error("epoch control update mismatch");

    waiterLock = waiter.query(
      `SELECT current_epoch,current_acceptance,next_epoch,next_acceptance FROM p42_indexer_checkpoint_control
        WHERE singleton=true FOR UPDATE`,
    );
    waiterLock.catch(() => {});
    let blockingVerified = false;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const blocking = await runtimePool.query(
        "SELECT $1::integer = ANY(pg_blocking_pids($2::integer)) AS verified",
        [holderPid, waiterPid],
      );
      if (blocking.rows[0].verified) {
        blockingVerified = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    if (!blockingVerified) throw new Error("stale checkpoint contender did not block on the first acceptance lock");

    await holder.query("COMMIT");
    const locked = await waiterLock;
    waiterLock = undefined;
    if (locked.rowCount !== 1 || String(locked.rows[0].current_epoch) !== "1") {
      throw new Error("stale checkpoint contender did not observe the committed epoch control after locking");
    }
    const current = await waiter.query("SELECT finalized_block_number FROM p42_indexer_checkpoint_acceptance WHERE acceptance_id=1");
    if (current.rowCount !== 1 || BigInt(staleBlock) >= BigInt(current.rows[0].finalized_block_number)) {
      throw new Error("stale checkpoint contender was not rejected after lock acquisition");
    }
    await waiter.query("ROLLBACK");
    return {acceptedBlock,staleBlock,runtimeRole,ownerRole};
  } finally {
    await holder.query("ROLLBACK").catch(() => {});
    if (waiterLock) await waiterLock.catch(() => {});
    await waiter.query("ROLLBACK").catch(() => {});
    let resetError;
    for (const client of [migrator, holder, waiter]) {
      try {
        await client.query("RESET search_path");
      } catch (error) {
        resetError ??= error;
      }
    }
    migrator.release(resetError);
    holder.release(resetError);
    waiter.release(resetError);
    await ownerPool.query(`DROP SCHEMA IF EXISTS ${identifier} CASCADE`);
    if (resetError) throw resetError;
  }
}

async function rehearseStateLock() {
  const holder = await runtimePool.connect();
  const waiter = await runtimePool.connect();
  let waiterLock;
  try {
    await holder.query("BEGIN");
    await holder.query("SET LOCAL lock_timeout = '5s'");
    await holder.query("SET LOCAL statement_timeout = '15s'");
    await waiter.query("BEGIN");
    await waiter.query("SET LOCAL lock_timeout = '5s'");
    await waiter.query("SET LOCAL statement_timeout = '15s'");

    const holderPid = (await holder.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
    const waiterPid = (await waiter.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
    const row = await holder.query(
      "SELECT revision, state::text AS state_text FROM p42_portal_state WHERE singleton = true FOR UPDATE",
    );
    if (row.rowCount !== 1) throw new Error("portal database singleton is missing");

    waiterLock = waiter.query(
      "SELECT revision, state::text AS state_text FROM p42_portal_state WHERE singleton = true FOR UPDATE",
    );
    waiterLock.catch(() => {});
    let blockingVerified = false;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const blocking = await runtimePool.query(
        "SELECT $1::integer = ANY(pg_blocking_pids($2::integer)) AS verified",
        [holderPid, waiterPid],
      );
      if (blocking.rows[0].verified) {
        blockingVerified = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    if (!blockingVerified) throw new Error("PostgreSQL did not attribute the waiter lock to the holder");

    await holder.query("ROLLBACK");
    const waiterRow = await waiterLock;
    waiterLock = undefined;
    if (waiterRow.rowCount !== 1
      || waiterRow.rows[0].revision !== row.rows[0].revision
      || waiterRow.rows[0].state_text !== row.rows[0].state_text) {
      throw new Error("portal state changed during rollback-only lock rehearsal");
    }
    await waiter.query("ROLLBACK");
    return { revision: row.rows[0].revision, stateText: row.rows[0].state_text };
  } finally {
    await holder.query("ROLLBACK").catch(() => {});
    if (waiterLock) await waiterLock.catch(() => {});
    await waiter.query("ROLLBACK").catch(() => {});
    holder.release();
    waiter.release();
  }
}

function quoteIdentifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}
