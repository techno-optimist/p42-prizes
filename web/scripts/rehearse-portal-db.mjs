import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const connectionString = process.env.P42_PORTAL_DATABASE_URL?.trim();
if (!connectionString) throw new Error("P42_PORTAL_DATABASE_URL is required for portal database rehearsal");

const pool = new pg.Pool({ connectionString, max: 10, connectionTimeoutMillis: 10_000 });
const policyId = `p42-db-rehearsal-${randomUUID()}`;
const subject = "concurrent-probe";
const startedAt = new Date().toISOString();
let cleanupComplete = false;
const migration1Sql = await readFile(path.resolve("migrations/001_portal_store.sql"), "utf8");
const migration2Sql = await readFile(path.resolve("migrations/002_indexer_checkpoint_high_water.sql"), "utf8");

try {
  const version = await pool.query("SELECT current_setting('server_version') AS server_version");
  const stateSnapshot = await rehearseStateLock();
  const highWater = await rehearseHighWaterLock();

  const increments = 8;
  await Promise.all(Array.from({ length: increments }, () => pool.query(
    `INSERT INTO p42_rate_limit_bucket (policy_id, subject, count, expires_at)
     VALUES ($1, $2, 1, clock_timestamp() + interval '5 minutes')
     ON CONFLICT (policy_id, subject) DO UPDATE
       SET count = p42_rate_limit_bucket.count + 1,
           expires_at = EXCLUDED.expires_at`,
    [policyId, subject],
  )));
  const bucket = await pool.query(
    "SELECT count FROM p42_rate_limit_bucket WHERE policy_id = $1 AND subject = $2",
    [policyId, subject],
  );
  if (bucket.rowCount !== 1 || bucket.rows[0].count !== increments) {
    throw new Error("atomic rate-limit upsert lost a concurrent increment");
  }

  const cleanup = await pool.query(
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
    acceptedCheckpointBlock: highWater.acceptedBlock,
    staleCheckpointBlock: highWater.staleBlock,
    staleCheckpointRejectedAfterLock: true,
    concurrentRateIncrements: increments,
  })}\n`);
} finally {
  if (!cleanupComplete) {
    await pool.query(
      "DELETE FROM p42_rate_limit_bucket WHERE policy_id = $1 AND subject = $2",
      [policyId, subject],
    ).catch(() => {});
  }
  await pool.end();
}

async function rehearseHighWaterLock() {
  const schema = `p42_high_water_rehearsal_${randomUUID().replaceAll("-", "")}`;
  const identifier = quoteIdentifier(schema);
  const migrator = await pool.connect();
  const holder = await pool.connect();
  const waiter = await pool.connect();
  let waiterLock;
  try {
    await pool.query(`CREATE SCHEMA ${identifier}`);
    await migrator.query(`SET search_path TO ${identifier}`);
    await migrator.query(migration1Sql);
    await migrator.query(migration2Sql);
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
    const first = await holder.query(
      `SELECT finalized_block_number
         FROM p42_indexer_checkpoint_high_water
        WHERE singleton = true
        FOR UPDATE`,
    );
    if (first.rowCount !== 1 || first.rows[0].finalized_block_number !== null) {
      throw new Error("isolated high-water singleton was not fresh and lockable");
    }

    const acceptedBlock = "101";
    const staleBlock = "100";
    await holder.query(
      `UPDATE p42_indexer_checkpoint_high_water
          SET finalized_block_number = $1,
              finalized_block_hash = $2,
              checkpoint_digest = $3,
              checkpoint_timestamp = $4,
              release_binding_digest = $5,
              authorization_digest = $6,
              chain_id = $7,
              chain_name = $8,
              deployment_commit = $9,
              deployment_config_hash = $10,
              accepted_at = clock_timestamp(),
              updated_at = clock_timestamp()
        WHERE singleton = true`,
      [
        acceptedBlock, `0x${"1".repeat(64)}`, `sha256:${"2".repeat(64)}`, "1001",
        `sha256:${"3".repeat(64)}`, `sha256:${"4".repeat(64)}`, "84532", "baseSepolia",
        "a".repeat(40), `0x${"5".repeat(64)}`,
      ],
    );

    waiterLock = waiter.query(
      `SELECT finalized_block_number
         FROM p42_indexer_checkpoint_high_water
        WHERE singleton = true
        FOR UPDATE`,
    );
    waiterLock.catch(() => {});
    let blockingVerified = false;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const blocking = await pool.query(
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
    if (locked.rowCount !== 1 || String(locked.rows[0].finalized_block_number) !== acceptedBlock) {
      throw new Error("stale checkpoint contender did not observe the committed high-water row after locking");
    }
    if (BigInt(staleBlock) >= BigInt(locked.rows[0].finalized_block_number)) {
      throw new Error("stale checkpoint contender was not rejected after lock acquisition");
    }
    await waiter.query("ROLLBACK");
    return { acceptedBlock, staleBlock };
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
    await pool.query(`DROP SCHEMA IF EXISTS ${identifier} CASCADE`);
    if (resetError) throw resetError;
  }
}

async function rehearseStateLock() {
  const holder = await pool.connect();
  const waiter = await pool.connect();
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
      const blocking = await pool.query(
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
