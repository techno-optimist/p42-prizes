import { createHash, randomUUID } from "node:crypto";
import process from "node:process";
import pg from "pg";

const connectionString = process.env.P42_PORTAL_DATABASE_URL?.trim();
if (!connectionString) throw new Error("P42_PORTAL_DATABASE_URL is required for portal database rehearsal");

const pool = new pg.Pool({ connectionString, max: 10, connectionTimeoutMillis: 10_000 });
const policyId = `p42-db-rehearsal-${randomUUID()}`;
const subject = "concurrent-probe";
const startedAt = new Date().toISOString();
let cleanupComplete = false;

try {
  const version = await pool.query("SELECT current_setting('server_version') AS server_version");
  const stateSnapshot = await rehearseStateLock();

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
