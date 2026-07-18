import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import pg from "pg";

const runtimeUrl = process.env.P42_PORTAL_DATABASE_URL?.trim();
const migrationUrl = process.env.P42_PORTAL_MIGRATION_DATABASE_URL?.trim();
const targetSchema = process.env.P42_PORTAL_DATABASE_SCHEMA?.trim();
if (!runtimeUrl || !migrationUrl) throw new Error("separate runtime and migration database URLs are required for rehearsal");
if (!targetSchema || !/^[a-z][a-z0-9_]{0,62}$/.test(targetSchema)) throw new Error("pinned portal database schema is required for rehearsal");
if (runtimeUrl === migrationUrl) throw new Error("runtime and migration database URLs must be distinct");
const productionSchema = quoteIdentifier(targetSchema);

const runtimePool = new pg.Pool({ connectionString: runtimeUrl, max: 10, connectionTimeoutMillis: 10_000 });
const ownerPool = new pg.Pool({ connectionString: migrationUrl, max: 3, connectionTimeoutMillis: 10_000 });
const policyId = `p42-db-rehearsal-${randomUUID()}`;
const subject = "concurrent-probe";
const startedAt = new Date().toISOString();
const exactReadReleaseLatencyCeilingMilliseconds = 2_000;
let cleanupComplete = false;
const migration1Sql = await readFile(path.resolve("migrations/001_portal_store.sql"), "utf8");
const migration2Sql = await readFile(path.resolve("migrations/002_indexer_checkpoint_high_water.sql"), "utf8");

try {
  const version = await runtimePool.query("SELECT current_setting('server_version') AS server_version");
  const stateSnapshot = await rehearseStateLock();
  const highWater = await rehearseHighWaterLock();

  const increments = 8;
  await Promise.all(Array.from({ length: increments }, () => runtimePool.query(
    `INSERT INTO ${productionSchema}.p42_rate_limit_bucket AS bucket (policy_id, subject, count, expires_at)
     VALUES ($1, $2, 1, clock_timestamp() + interval '5 minutes')
     ON CONFLICT (policy_id, subject) DO UPDATE
       SET count = bucket.count + 1,
           expires_at = EXCLUDED.expires_at`,
    [policyId, subject],
  )));
  const bucket = await runtimePool.query(
    `SELECT count FROM ${productionSchema}.p42_rate_limit_bucket WHERE policy_id = $1 AND subject = $2`,
    [policyId, subject],
  );
  if (bucket.rowCount !== 1 || bucket.rows[0].count !== increments) {
    throw new Error("atomic rate-limit upsert lost a concurrent increment");
  }

  const cleanup = await runtimePool.query(
    `DELETE FROM ${productionSchema}.p42_rate_limit_bucket WHERE policy_id = $1 AND subject = $2`,
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
    runtimeHistoryTruncateDenied: true,
    acceptedCheckpointBlock: highWater.acceptedBlock,
    staleCheckpointBlock: highWater.staleBlock,
    staleCheckpointRejectedAfterLock: true,
    largeHistoryAcceptances: highWater.largeHistoryAcceptances,
    concurrentExactReaders: highWater.concurrentExactReaders,
    exactReadBlockingPids: highWater.exactReadBlockingPids,
    exactReadersObservedInFlight: highWater.exactReadersObservedInFlight,
    transitionBlockedByExactReaders: highWater.transitionBlockedByExactReaders,
    exactReadReleaseMilliseconds: highWater.exactReadReleaseMilliseconds,
    exactReadReleaseLatencyCeilingMilliseconds,
    concurrentRateIncrements: increments,
  })}\n`);
} finally {
  if (!cleanupComplete) {
    await runtimePool.query(
      `DELETE FROM ${productionSchema}.p42_rate_limit_bucket WHERE policy_id = $1 AND subject = $2`,
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
  let waiterCall;
  try {
    await ownerPool.query(`CREATE SCHEMA ${identifier}`);
    await migrator.query(`SET search_path TO ${identifier}`);
    await migrator.query(migration1Sql);
    await migrator.query(migration2Sql);
    const runtimeRole = (await holder.query("SELECT current_user AS role")).rows[0].role;
    const ownerRole = (await migrator.query("SELECT current_user AS role")).rows[0].role;
    if (runtimeRole === ownerRole) throw new Error("rehearsal runtime role is the schema owner");
    await migrator.query(`GRANT USAGE ON SCHEMA ${identifier} TO ${quoteIdentifier(runtimeRole)}`);
    await migrator.query(`REVOKE ALL ON p42_indexer_checkpoint_authority,p42_indexer_checkpoint_control,
      p42_indexer_checkpoint_epoch,p42_indexer_checkpoint_acceptance FROM ${quoteIdentifier(runtimeRole)}`);
    await migrator.query(`GRANT SELECT ON p42_indexer_checkpoint_authority,p42_indexer_checkpoint_control,
      p42_indexer_checkpoint_epoch,p42_indexer_checkpoint_acceptance TO ${quoteIdentifier(runtimeRole)}`);
    await migrator.query(`GRANT EXECUTE ON FUNCTION p42_transition_indexer_checkpoint(
      bigint,text,text,bigint,text,text,bigint,text,text,text) TO ${quoteIdentifier(runtimeRole)}`);
    await migrator.query(`GRANT EXECUTE ON FUNCTION p42_read_exact_indexer_checkpoint(
      bigint,text,text,bigint,text,text,bigint,text,text,text) TO ${quoteIdentifier(runtimeRole)}`);
    await holder.query("SET search_path TO pg_catalog");
    await waiter.query("SET search_path TO pg_catalog");

    await expectPermissionDenied(holder, `UPDATE ${identifier}.p42_indexer_checkpoint_control SET current_epoch=NULL`);
    await expectPermissionDenied(holder, `INSERT INTO ${identifier}.p42_indexer_checkpoint_epoch VALUES(
      99,'sha256:${"6".repeat(64)}','sha256:${"7".repeat(64)}',84532,'baseSepolia',
      '${"b".repeat(40)}','0x${"8".repeat(64)}',clock_timestamp())`);
    await expectPermissionDenied(holder, `TRUNCATE ${identifier}.p42_indexer_checkpoint_acceptance`);
    await holder.query("BEGIN");
    await holder.query("SET LOCAL lock_timeout = '5s'");
    await holder.query("SET LOCAL statement_timeout = '15s'");
    await waiter.query("BEGIN");
    await waiter.query("SET LOCAL lock_timeout = '5s'");
    await waiter.query("SET LOCAL statement_timeout = '15s'");

    const holderPid = (await holder.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
    const waiterPid = (await waiter.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
    const acceptedBlock = "101";
    const staleBlock = "100";
    const accepted = await callTransition(holder, identifier, acceptedBlock, "1", "2", "1001");
    if (accepted.rowCount !== 1 || accepted.rows[0].transition_kind !== "first"
      || String(accepted.rows[0].finalized_block_number) !== acceptedBlock) {
      throw new Error("owner transition function did not persist the first checkpoint");
    }

    waiterCall = callTransition(waiter, identifier, staleBlock, "3", "4", "1001");
    waiterCall.catch(() => {});
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
    if (!blockingVerified) throw new Error("stale checkpoint contender did not block inside the owner transition function");

    await holder.query("COMMIT");
    try { await waiterCall; throw new Error("stale checkpoint contender unexpectedly succeeded"); }
    catch (error) { if (!(error instanceof Error) || !error.message.includes("finalized block regression")) throw error; }
    waiterCall = undefined;
    await waiter.query("ROLLBACK");

    const largeHistoryAcceptances = 10_000;
    await migrator.query(`INSERT INTO ${identifier}.p42_indexer_checkpoint_acceptance (
      acceptance_id,epoch_id,finalized_block_number,finalized_block_hash,checkpoint_digest,
      checkpoint_timestamp,accepted_at)
      SELECT value,1,100+value,'0x'||lpad(to_hex(value),64,'0'),
        'sha256:'||lpad(to_hex(value),64,'0'),1000+value,clock_timestamp()
      FROM generate_series(2,$1::integer) AS value`, [largeHistoryAcceptances]);
    await migrator.query(`UPDATE ${identifier}.p42_indexer_checkpoint_control SET
      current_acceptance=$1::bigint,next_acceptance=$1::bigint+1,updated_at=clock_timestamp() WHERE singleton=true`,
    [largeHistoryAcceptances]);

    const concurrentExactReaders = 6;
    const readers = await Promise.all(Array.from({length:concurrentExactReaders},async()=>runtimePool.connect()));
    const barrier = await runtimePool.connect();
    const barrierKey = 42_002n;
    let exactReadBlockingPids = 0;
    let exactReadersObservedInFlight = 0;
    let transitionBlockedByExactReaders = 0;
    let exactReadReleaseMilliseconds = 0;
    let exactCalls;
    let blockedTransition;
    try {
      await barrier.query("SELECT pg_advisory_lock($1::bigint)",[barrierKey.toString()]);
      const barrierPid=(await barrier.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      await Promise.all(readers.map(async(reader)=>{
        await reader.query("BEGIN"); await reader.query("SET LOCAL lock_timeout='2s'");
        await reader.query("SET LOCAL statement_timeout='10s'"); await reader.query("SET LOCAL search_path=pg_catalog");
      }));
      const readerPids=await Promise.all(readers.map(async reader=>(await reader.query("SELECT pg_backend_pid() AS pid")).rows[0].pid));
      exactCalls=readers.map(reader=>callExactHeld(reader,identifier,largeHistoryAcceptances,barrierKey));
      exactCalls.forEach(call=>call.catch(()=>{}));
      let readerActivity=[];
      for(let attempt=0;attempt<100;attempt+=1) {
        const activity=await runtimePool.query(`SELECT pid,state,wait_event_type,wait_event,pg_blocking_pids(pid) AS blockers
          FROM pg_catalog.pg_stat_activity WHERE pid=ANY($1::integer[]) ORDER BY pid`,[readerPids]);
        readerActivity=activity.rows;
        if(readerActivity.length===concurrentExactReaders&&readerActivity.every(row=>row.state==="active"
          &&row.wait_event_type==="Lock"&&row.wait_event==="advisory"
          &&row.blockers.includes(barrierPid))) break;
        await new Promise(resolve=>setTimeout(resolve,20));
      }
      exactReadersObservedInFlight=readerActivity.filter(row=>row.state==="active"
        &&row.wait_event_type==="Lock"&&row.wait_event==="advisory"
        &&row.blockers.includes(barrierPid)).length;
      if(exactReadersObservedInFlight!==concurrentExactReaders) {
        throw new Error("not every exact checkpoint reader reached the held in-flight barrier");
      }
      exactReadBlockingPids=readerActivity.reduce((total,row)=>total
        +row.blockers.filter(pid=>readerPids.includes(pid)).length,0);
      if(exactReadBlockingPids!==0) throw new Error("concurrent exact checkpoint readers blocked one another");

      await waiter.query("BEGIN"); await waiter.query("SET LOCAL lock_timeout='5s'");
      await waiter.query("SET LOCAL statement_timeout='10s'");
      blockedTransition=callTransition(waiter,identifier,String(101+largeHistoryAcceptances),"c","d",String(1001+largeHistoryAcceptances));
      blockedTransition.catch(()=>{});
      let transitionBlockers=[];
      for(let attempt=0;attempt<100;attempt+=1) {
        const observed=await runtimePool.query("SELECT pg_blocking_pids($1::integer) AS blockers",[waiterPid]);
        transitionBlockers=observed.rows[0].blockers;
        if(transitionBlockers.length>0&&transitionBlockers.every(pid=>readerPids.includes(pid))) break;
        await new Promise(resolve=>setTimeout(resolve,20));
      }
      transitionBlockedByExactReaders=transitionBlockers.filter(pid=>readerPids.includes(pid)).length;
      if(transitionBlockedByExactReaders<1||transitionBlockers.some(pid=>!readerPids.includes(pid))) {
        throw new Error("serialized checkpoint transition was not blocked by a held exact reader");
      }

      const releasedAt=Date.now();
      const unlocked=await barrier.query("SELECT pg_advisory_unlock($1::bigint) AS unlocked",[barrierKey.toString()]);
      if(!unlocked.rows[0]?.unlocked) throw new Error("exact-read rehearsal barrier was not released");
      const exactRows=await Promise.all(exactCalls); exactCalls=undefined;
      exactReadReleaseMilliseconds=Date.now()-releasedAt;
      if(exactReadReleaseMilliseconds>exactReadReleaseLatencyCeilingMilliseconds) {
        throw new Error(`exact checkpoint readers exceeded ${exactReadReleaseLatencyCeilingMilliseconds}ms release ceiling`);
      }
      for(const exact of exactRows) if(exact.rowCount!==1||exact.rows[0].transition_kind!=="same"
        ||Number(exact.rows[0].acceptance_id)!==largeHistoryAcceptances) {
        throw new Error("large-history exact read did not return the indexed current checkpoint");
      }
      await Promise.all(readers.map(reader=>reader.query("COMMIT")));
      const transition=await blockedTransition; blockedTransition=undefined;
      if(transition.rowCount!==1||transition.rows[0].transition_kind!=="advance"
        ||Number(transition.rows[0].acceptance_id)!==largeHistoryAcceptances+1) {
        throw new Error("held exact readers did not release the serialized transition correctly");
      }
      await waiter.query("COMMIT");
    } finally {
      await barrier.query("SELECT pg_advisory_unlock($1::bigint)",[barrierKey.toString()]).catch(()=>{});
      if(exactCalls) await Promise.all(exactCalls.map(call=>call.catch(()=>{})));
      await Promise.all(readers.map(reader=>reader.query("ROLLBACK").catch(()=>{})));
      if(blockedTransition) await blockedTransition.catch(()=>{});
      readers.forEach(reader=>reader.release());
      barrier.release();
    }
    return {acceptedBlock,staleBlock,runtimeRole,ownerRole,largeHistoryAcceptances,
      concurrentExactReaders,exactReadBlockingPids,exactReadersObservedInFlight,
      transitionBlockedByExactReaders,exactReadReleaseMilliseconds};
  } finally {
    await holder.query("ROLLBACK").catch(() => {});
    if (waiterCall) await waiterCall.catch(() => {});
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

function callTransition(client, schema, block, hashDigit, digestDigit, timestamp) {
  return client.query(`SELECT * FROM ${schema}.p42_transition_indexer_checkpoint(
    $1::bigint,$2::text,$3::text,$4::bigint,$5::text,$6::text,$7::bigint,$8::text,$9::text,$10::text)`, [
    block, `0x${hashDigit.repeat(64)}`, `sha256:${digestDigit.repeat(64)}`, timestamp,
    `sha256:${"3".repeat(64)}`, `sha256:${"4".repeat(64)}`, "84532", "baseSepolia",
    "a".repeat(40), `0x${"5".repeat(64)}`,
  ]);
}

function callExactHeld(client,schema,acceptanceId,barrierKey) {
  const hex=acceptanceId.toString(16).padStart(64,"0");
  return client.query(`WITH exact AS MATERIALIZED (SELECT * FROM ${schema}.p42_read_exact_indexer_checkpoint(
    $1::bigint,$2::text,$3::text,$4::bigint,$5::text,$6::text,$7::bigint,$8::text,$9::text,$10::text))
    SELECT exact.* FROM exact CROSS JOIN LATERAL
      (SELECT pg_advisory_xact_lock_shared($11::bigint+(exact.acceptance_id-exact.acceptance_id))) AS held`,[
    String(100+acceptanceId),`0x${hex}`,`sha256:${hex}`,String(1000+acceptanceId),
    `sha256:${"3".repeat(64)}`,`sha256:${"4".repeat(64)}`,"84532","baseSepolia",
    "a".repeat(40),`0x${"5".repeat(64)}`,barrierKey.toString(),
  ]);
}

async function expectPermissionDenied(client, sql) {
  try { await client.query(sql); } catch (error) {
    if (error instanceof Error && error.message.includes("permission denied")) return;
    throw error;
  }
  throw new Error("runtime direct high-water mutation unexpectedly succeeded");
}

async function rehearseStateLock() {
  const holder = await runtimePool.connect();
  const waiter = await runtimePool.connect();
  let waiterLock;
  try {
    await holder.query("SELECT set_config('search_path',$1,false)", [productionSchema]);
    await waiter.query("SELECT set_config('search_path',$1,false)", [productionSchema]);
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
