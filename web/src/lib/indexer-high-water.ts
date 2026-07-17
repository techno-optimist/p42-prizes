import type { QueryResultRow } from "pg";
import type { ActivatedIndexerSnapshot } from "@/lib/indexer-provenance";
import { portalDatabasePool, portalDatabaseTimeouts, type PortalDatabaseClient } from "@/lib/portal-db";

type JsonObject = Record<string, unknown>;
const BLOCK_HASH=/^0x[0-9a-fA-F]{64}$/; const BYTES32=BLOCK_HASH;
const SHA256=/^sha256:[0-9a-f]{64}$/; const COMMIT=/^[0-9a-fA-F]{40}$/;

export interface IndexerCheckpointHighWaterCandidate {
  finalizedBlockNumber:string; finalizedBlockHash:string; checkpointDigest:string; checkpointTimestamp:string;
  releaseBindingDigest:string; authorizationDigest:string; chainId:string; chainName:string;
  deploymentCommit:string; deploymentConfigHash:string;
}
export interface IndexerIdentityEpoch extends QueryResultRow {
  epoch_id:string; release_binding_digest:string; authorization_digest:string; chain_id:string;
  chain_name:string; deployment_commit:string; deployment_config_hash:string; accepted_at:string;
}
export interface IndexerCheckpointAcceptance extends QueryResultRow {
  acceptance_id:string; epoch_id:string; finalized_block_number:string; finalized_block_hash:string;
  checkpoint_digest:string; checkpoint_timestamp:string; accepted_at:string;
}
export interface IndexerCheckpointControl extends QueryResultRow {
  current_epoch:string|null; current_acceptance:string|null; next_epoch:string; next_acceptance:string; updated_at:string|null;
}
interface RuntimeAuthorityRow extends QueryResultRow {
  identity_matches:boolean; function_matches:boolean; acl_matches:boolean; safe_role:boolean;
  no_direct_writes:boolean; no_dangerous_set_role:boolean; no_external_triggers:boolean;
}
interface TransitionRow extends QueryResultRow {
  transition_kind:"same"|"advance"|"first"|"renew";
  epoch_id:string; release_binding_digest:string; authorization_digest:string; chain_id:string;
  chain_name:string; deployment_commit:string; deployment_config_hash:string; epoch_accepted_at:string;
  acceptance_id:string; finalized_block_number:string; finalized_block_hash:string;
  checkpoint_digest:string; checkpoint_timestamp:string; acceptance_accepted_at:string;
  current_epoch:string; current_acceptance:string; next_epoch:string; next_acceptance:string;
  control_updated_at:string;
}
export type EpochDecision =
  | {kind:"same";epochId:string;acceptanceId:string}
  | {kind:"advance"|"first"|"renew";epochId:string;acceptanceId:string};

function object(value:unknown,label:string):JsonObject { if(value===null||typeof value!=="object"||Array.isArray(value)) throw new Error(`${label} must be an object`); return value as JsonObject; }
function uint(value:unknown,label:string,positive=false):string { if(!Number.isSafeInteger(value)||Number(value)<(positive?1:0)) throw new Error(`${label} must be a safe unsigned integer`); return String(value); }
function normalized(value:unknown,pattern:RegExp,label:string):string { if(typeof value!=="string"||!pattern.test(value)) throw new Error(`${label} is invalid`); return value.toLowerCase(); }

export function indexerCheckpointHighWaterCandidate(snapshot:ActivatedIndexerSnapshot):IndexerCheckpointHighWaterCandidate {
  const range=object(snapshot.checkpoint.range,"activated checkpoint range"); const identity=snapshot.highWaterIdentity;
  if(!/^[a-z][A-Za-z0-9]*$/.test(identity.chainName)) throw new Error("activated checkpoint chain name is invalid");
  return { finalizedBlockNumber:uint(range.toBlock,"activated checkpoint finalized block"),
    finalizedBlockHash:normalized(range.toBlockHash,BLOCK_HASH,"activated checkpoint finalized block hash"),
    checkpointDigest:normalized(identity.checkpointDigest,SHA256,"attested raw checkpoint digest"),
    checkpointTimestamp:uint(range.toBlockTimestamp,"activated checkpoint timestamp",true),
    releaseBindingDigest:normalized(identity.releaseBindingDigest,SHA256,"activated checkpoint release binding digest"),
    authorizationDigest:normalized(identity.authorizationDigest,SHA256,"activated checkpoint authorization digest"),
    chainId:uint(identity.chainId,"activated checkpoint chain id",true), chainName:identity.chainName,
    deploymentCommit:normalized(identity.deploymentCommit,COMMIT,"activated deployment commit"),
    deploymentConfigHash:normalized(identity.deploymentConfigHash,BYTES32,"activated deployment config hash") };
}
function sameIdentity(row:IndexerIdentityEpoch,c:IndexerCheckpointHighWaterCandidate):boolean { return row.release_binding_digest===c.releaseBindingDigest&&row.authorization_digest===c.authorizationDigest&&row.chain_id===c.chainId&&row.chain_name===c.chainName&&row.deployment_commit===c.deploymentCommit&&row.deployment_config_hash===c.deploymentConfigHash; }
function sameChain(row:IndexerIdentityEpoch,c:IndexerCheckpointHighWaterCandidate):boolean { return row.chain_id===c.chainId&&row.chain_name===c.chainName; }

export function decideIndexerCheckpointEpoch(control:IndexerCheckpointControl,epochs:readonly IndexerIdentityEpoch[],current:IndexerCheckpointAcceptance|null,c:IndexerCheckpointHighWaterCandidate):EpochDecision {
  if(control.current_epoch===null||control.current_acceptance===null) {
    if(control.current_epoch!==null||control.current_acceptance!==null||epochs.length||current||control.next_epoch!=="1"||control.next_acceptance!=="1") throw new Error("checkpoint epoch control/history mismatch");
    return {kind:"first",epochId:"1",acceptanceId:"1"};
  }
  const identity=epochs.find(row=>row.epoch_id===control.current_epoch);
  if(!identity||!current||current.acceptance_id!==control.current_acceptance||current.epoch_id!==control.current_epoch
    ||BigInt(control.next_epoch)!==BigInt(control.current_epoch)+1n||BigInt(control.next_acceptance)!==BigInt(control.current_acceptance)+1n) throw new Error("checkpoint epoch control/history mismatch");
  if(sameIdentity(identity,c)) {
    if(BigInt(c.checkpointTimestamp)<BigInt(current.checkpoint_timestamp)) throw new Error("activated checkpoint timestamp regression");
    const block=BigInt(c.finalizedBlockNumber), previous=BigInt(current.finalized_block_number);
    if(block<previous) throw new Error("activated checkpoint finalized block regression");
    if(block===previous) {
      if(c.finalizedBlockHash!==current.finalized_block_hash||c.checkpointDigest!==current.checkpoint_digest||c.checkpointTimestamp!==current.checkpoint_timestamp) throw new Error("activated checkpoint same-height conflict");
      return {kind:"same",epochId:identity.epoch_id,acceptanceId:current.acceptance_id};
    }
    return {kind:"advance",epochId:identity.epoch_id,acceptanceId:control.next_acceptance};
  }
  if(epochs.some(row=>sameIdentity(row,c))) throw new Error("activated checkpoint historical identity replay");
  if(BigInt(c.checkpointTimestamp)<=BigInt(current.checkpoint_timestamp)) throw new Error("activated checkpoint epoch timestamp must strictly advance");
  if(sameChain(identity,c)) {
    if(BigInt(c.finalizedBlockNumber)<=BigInt(current.finalized_block_number)) throw new Error("same-chain identity renewal requires a strictly higher finalized block");
  } else {
    if(epochs.some(row=>sameChain(row,c))) throw new Error("historical chain identity replay");
    if(c.releaseBindingDigest===identity.release_binding_digest||c.authorizationDigest===identity.authorization_digest||c.deploymentConfigHash===identity.deployment_config_hash) throw new Error("chain transition requires new release, authorization, and deployment configuration identities");
  }
  return {kind:"renew",epochId:control.next_epoch,acceptanceId:control.next_acceptance};
}

function validDate(value:unknown):boolean { return (typeof value==="string"||value instanceof Date)&&Number.isFinite(new Date(value).getTime()); }
async function rollback(client:PortalDatabaseClient):Promise<void>{await client.query("ROLLBACK").catch(()=>{});}

function checkpointSchema():string {
  const configured=process.env.P42_PORTAL_DATABASE_SCHEMA?.trim();
  if(!configured) {
    if(process.env.P42_PORTAL_DATABASE_REQUIRED==="1") throw new Error("P42_PORTAL_DATABASE_SCHEMA is required for production checkpoint authority");
    return "p42_portal";
  }
  if(!/^[a-z][a-z0-9_]{0,62}$/.test(configured)) throw new Error("P42_PORTAL_DATABASE_SCHEMA is invalid");
  return configured;
}
function quoted(value:string):string{return `"${value.replaceAll('"','""')}"`;}
function assertRuntimeAuthority(row:RuntimeAuthorityRow|undefined):void {
  if(!row||!row.identity_matches||!row.function_matches||!row.acl_matches||!row.safe_role
    ||!row.no_direct_writes||!row.no_dangerous_set_role||!row.no_external_triggers) {
    throw new Error("portal checkpoint runtime authority attestation failed");
  }
}
function assertTransition(row:TransitionRow|undefined,c:IndexerCheckpointHighWaterCandidate):void {
  if(!row||!["same","advance","first","renew"].includes(row.transition_kind)) throw new Error("checkpoint transition returned no exact persisted state");
  const expected:Record<string,string>={release_binding_digest:c.releaseBindingDigest,authorization_digest:c.authorizationDigest,
    chain_id:c.chainId,chain_name:c.chainName,deployment_commit:c.deploymentCommit,deployment_config_hash:c.deploymentConfigHash,
    finalized_block_number:c.finalizedBlockNumber,finalized_block_hash:c.finalizedBlockHash,
    checkpoint_digest:c.checkpointDigest,checkpoint_timestamp:c.checkpointTimestamp};
  for(const [key,value] of Object.entries(expected)) if(String(row[key])!==value) throw new Error(`persisted checkpoint transition mismatch for ${key}`);
  if(String(row.current_epoch)!==String(row.epoch_id)||String(row.current_acceptance)!==String(row.acceptance_id)
    ||BigInt(row.next_epoch)!==BigInt(row.epoch_id)+1n||BigInt(row.next_acceptance)!==BigInt(row.acceptance_id)+1n
    ||!validDate(row.epoch_accepted_at)||!validDate(row.acceptance_accepted_at)||!validDate(row.control_updated_at)) {
    throw new Error("persisted checkpoint transition control mismatch");
  }
}

function runtimeAuthoritySql(schema:string,q:string):string { return `WITH pinned AS (
      SELECT * FROM ${q}.p42_indexer_checkpoint_authority WHERE singleton=true
    ), objects AS (
      SELECT p.*, n.oid AS actual_schema_oid, n.nspname AS actual_schema_name,
        tf.proowner AS transition_owner, tf.prosecdef AS transition_secdef,
        tf.provolatile AS transition_volatile, tf.prokind AS transition_kind,
        tf.proconfig AS transition_config, tf.prosrc AS actual_transition_source,
        tl.lanname AS transition_language, tf.proisstrict AS transition_strict,
        tf.proleakproof AS transition_leakproof, tf.proparallel AS transition_parallel,
        tf.proretset AS transition_retset, pg_catalog.pg_get_function_result(tf.oid) AS transition_result,
        tf.oid AS actual_transition_oid,
        ef.proowner AS exact_owner, ef.prosecdef AS exact_secdef,
        ef.provolatile AS exact_volatile, ef.prokind AS exact_kind,
        ef.proconfig AS exact_config, ef.prosrc AS actual_exact_source,
        el.lanname AS exact_language, ef.proisstrict AS exact_strict,
        ef.proleakproof AS exact_leakproof, ef.proparallel AS exact_parallel,
        ef.proretset AS exact_retset, pg_catalog.pg_get_function_result(ef.oid) AS exact_result,
        ef.oid AS actual_exact_oid
      FROM pinned AS p
      JOIN pg_catalog.pg_namespace AS n ON n.oid=p.schema_oid
      JOIN pg_catalog.pg_proc AS tf ON tf.oid=p.transition_function_oid
      JOIN pg_catalog.pg_language AS tl ON tl.oid=tf.prolang
      JOIN pg_catalog.pg_proc AS ef ON ef.oid=p.exact_read_function_oid
      JOIN pg_catalog.pg_language AS el ON el.oid=ef.prolang
    ), runtime AS (
      SELECT r.* FROM pg_catalog.pg_roles AS r WHERE r.rolname=CURRENT_USER
    ) SELECT
      CURRENT_USER=SESSION_USER
        AND o.database_oid=(SELECT d.oid FROM pg_catalog.pg_database AS d WHERE d.datname=pg_catalog.current_database())
      AND o.database_name::text=pg_catalog.current_database()
        AND o.schema_oid=o.actual_schema_oid AND o.schema_name::text=$1 AND o.actual_schema_name=$1
        AND o.migration_owner_oid=(SELECT d.datdba FROM pg_catalog.pg_database AS d WHERE d.oid=o.database_oid)
        AND o.migration_owner_oid=(SELECT n.nspowner FROM pg_catalog.pg_namespace AS n WHERE n.oid=o.schema_oid)
        AND o.migration_owner_oid=(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.authority_oid)
        AND o.migration_owner_oid=(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.control_oid)
        AND o.migration_owner_oid=(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.epoch_oid)
        AND o.migration_owner_oid=(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.acceptance_oid)
        AND o.authority_oid='${schema}.p42_indexer_checkpoint_authority'::pg_catalog.regclass::oid
        AND o.control_oid='${schema}.p42_indexer_checkpoint_control'::pg_catalog.regclass::oid
        AND o.epoch_oid='${schema}.p42_indexer_checkpoint_epoch'::pg_catalog.regclass::oid
        AND o.acceptance_oid='${schema}.p42_indexer_checkpoint_acceptance'::pg_catalog.regclass::oid
        AND o.actual_transition_oid='${schema}.p42_transition_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)'::pg_catalog.regprocedure::oid
        AND o.actual_exact_oid='${schema}.p42_read_exact_indexer_checkpoint(bigint,text,text,bigint,text,text,bigint,text,text,text)'::pg_catalog.regprocedure::oid AS identity_matches,
      o.transition_owner=o.migration_owner_oid AND o.exact_owner=o.migration_owner_oid
        AND o.migration_owner_name::text=pg_catalog.pg_get_userbyid(o.transition_owner)
        AND o.transition_secdef AND o.exact_secdef
        AND o.transition_volatile='v' AND o.exact_volatile='v'
        AND o.transition_kind='f' AND o.exact_kind='f'
        AND o.transition_language='plpgsql' AND o.exact_language='plpgsql'
        AND NOT o.transition_strict AND NOT o.exact_strict
        AND NOT o.transition_leakproof AND NOT o.exact_leakproof
        AND o.transition_parallel='u' AND o.exact_parallel='u'
        AND o.transition_retset AND o.exact_retset
        AND o.transition_result=o.exact_result
        AND o.transition_result='TABLE(transition_kind text, epoch_id bigint, release_binding_digest text, authorization_digest text, chain_id bigint, chain_name text, deployment_commit text, deployment_config_hash text, epoch_accepted_at timestamp with time zone, acceptance_id bigint, finalized_block_number bigint, finalized_block_hash text, checkpoint_digest text, checkpoint_timestamp bigint, acceptance_accepted_at timestamp with time zone, current_epoch bigint, current_acceptance bigint, next_epoch bigint, next_acceptance bigint, control_updated_at timestamp with time zone)'
        AND o.transition_config=ARRAY['search_path=pg_catalog']::text[]
        AND o.exact_config=ARRAY['search_path=pg_catalog']::text[]
        AND o.actual_transition_source=o.transition_function_source
        AND o.actual_exact_source=o.exact_read_function_source AS function_matches,
      pg_catalog.has_function_privilege(CURRENT_USER,o.actual_transition_oid,'EXECUTE')
        AND pg_catalog.has_function_privilege(CURRENT_USER,o.actual_exact_oid,'EXECUTE')
        AND NOT pg_catalog.has_function_privilege('public',o.actual_transition_oid,'EXECUTE')
        AND NOT pg_catalog.has_function_privilege('public',o.actual_exact_oid,'EXECUTE')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(
          (SELECT p.proacl FROM pg_catalog.pg_proc AS p WHERE p.oid=o.actual_transition_oid),
          pg_catalog.acldefault('f',o.transition_owner))) AS acl
          WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>ALL(ARRAY[o.transition_owner,r.oid]))
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(
          (SELECT p.proacl FROM pg_catalog.pg_proc AS p WHERE p.oid=o.actual_exact_oid),
          pg_catalog.acldefault('f',o.exact_owner))) AS acl
          WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>ALL(ARRAY[o.exact_owner,r.oid])) AS acl_matches,
      NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolbypassrls
        AND (SELECT d.datdba<>r.oid FROM pg_catalog.pg_database AS d WHERE d.oid=o.database_oid)
        AND (SELECT n.nspowner<>r.oid FROM pg_catalog.pg_namespace AS n WHERE n.oid=o.schema_oid)
        AND r.oid<>ALL(ARRAY[(SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.authority_oid),
          (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.control_oid),
          (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.epoch_oid),
          (SELECT c.relowner FROM pg_catalog.pg_class AS c WHERE c.oid=o.acceptance_oid)])
        AND NOT pg_catalog.has_database_privilege(r.oid,o.database_oid,'CREATE')
        AND NOT pg_catalog.has_schema_privilege(r.oid,o.schema_oid,'CREATE') AS safe_role,
      NOT (pg_catalog.has_table_privilege(r.oid,o.authority_oid,'INSERT')
        OR pg_catalog.has_table_privilege(r.oid,o.authority_oid,'UPDATE')
        OR pg_catalog.has_table_privilege(r.oid,o.authority_oid,'DELETE')
        OR pg_catalog.has_table_privilege(r.oid,o.authority_oid,'TRUNCATE')
        OR pg_catalog.has_table_privilege(r.oid,o.authority_oid,'TRIGGER')
        OR pg_catalog.has_table_privilege(r.oid,o.control_oid,'INSERT')
        OR pg_catalog.has_table_privilege(r.oid,o.control_oid,'UPDATE')
        OR pg_catalog.has_table_privilege(r.oid,o.control_oid,'DELETE')
        OR pg_catalog.has_table_privilege(r.oid,o.control_oid,'TRUNCATE')
        OR pg_catalog.has_table_privilege(r.oid,o.control_oid,'TRIGGER')
        OR pg_catalog.has_table_privilege(r.oid,o.epoch_oid,'INSERT')
        OR pg_catalog.has_table_privilege(r.oid,o.epoch_oid,'UPDATE')
        OR pg_catalog.has_table_privilege(r.oid,o.epoch_oid,'DELETE')
        OR pg_catalog.has_table_privilege(r.oid,o.epoch_oid,'TRUNCATE')
        OR pg_catalog.has_table_privilege(r.oid,o.epoch_oid,'TRIGGER')
        OR pg_catalog.has_table_privilege(r.oid,o.acceptance_oid,'INSERT')
        OR pg_catalog.has_table_privilege(r.oid,o.acceptance_oid,'UPDATE')
        OR pg_catalog.has_table_privilege(r.oid,o.acceptance_oid,'DELETE')
        OR pg_catalog.has_table_privilege(r.oid,o.acceptance_oid,'TRUNCATE')
        OR pg_catalog.has_table_privilege(r.oid,o.acceptance_oid,'TRIGGER')) AS no_direct_writes,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS candidate
        WHERE candidate.oid<>r.oid AND pg_catalog.pg_has_role(r.oid,candidate.oid,'SET')
          AND (candidate.oid=o.migration_owner_oid OR candidate.rolsuper OR candidate.rolcreatedb
            OR candidate.rolcreaterole OR candidate.rolbypassrls
            OR pg_catalog.has_database_privilege(candidate.oid,o.database_oid,'CREATE')
            OR pg_catalog.has_schema_privilege(candidate.oid,o.schema_oid,'CREATE')
            OR candidate.oid=(SELECT d.datdba FROM pg_catalog.pg_database AS d WHERE d.oid=o.database_oid)
            OR candidate.oid=(SELECT n.nspowner FROM pg_catalog.pg_namespace AS n WHERE n.oid=o.schema_oid)
            OR pg_catalog.has_table_privilege(candidate.oid,o.authority_oid,'INSERT')
            OR pg_catalog.has_table_privilege(candidate.oid,o.authority_oid,'UPDATE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.authority_oid,'DELETE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.authority_oid,'TRUNCATE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.authority_oid,'TRIGGER')
            OR pg_catalog.has_table_privilege(candidate.oid,o.control_oid,'INSERT')
            OR pg_catalog.has_table_privilege(candidate.oid,o.control_oid,'UPDATE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.control_oid,'DELETE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.control_oid,'TRUNCATE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.control_oid,'TRIGGER')
            OR pg_catalog.has_table_privilege(candidate.oid,o.epoch_oid,'INSERT')
            OR pg_catalog.has_table_privilege(candidate.oid,o.epoch_oid,'UPDATE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.epoch_oid,'DELETE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.epoch_oid,'TRUNCATE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.epoch_oid,'TRIGGER')
            OR pg_catalog.has_table_privilege(candidate.oid,o.acceptance_oid,'INSERT')
            OR pg_catalog.has_table_privilege(candidate.oid,o.acceptance_oid,'UPDATE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.acceptance_oid,'DELETE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.acceptance_oid,'TRUNCATE')
            OR pg_catalog.has_table_privilege(candidate.oid,o.acceptance_oid,'TRIGGER'))) AS no_dangerous_set_role,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t
        WHERE t.tgrelid IN(o.authority_oid,o.control_oid,o.epoch_oid,o.acceptance_oid) AND NOT t.tgisinternal) AS no_external_triggers
      FROM objects AS o CROSS JOIN runtime AS r`; }

async function beginCheckpointTransaction(client:PortalDatabaseClient):Promise<void> {
  const timeouts=portalDatabaseTimeouts(); await client.query("BEGIN");
  await client.query("SELECT set_config('lock_timeout',$1,true)",[`${timeouts.lockMs}ms`]);
  await client.query("SELECT set_config('statement_timeout',$1,true)",[`${timeouts.statementMs}ms`]);
  await client.query("SELECT set_config('search_path','pg_catalog',true)");
}
async function attestRuntimeAuthority(client:PortalDatabaseClient,schema:string,q:string):Promise<void> {
  const authority=await client.query<RuntimeAuthorityRow>(runtimeAuthoritySql(schema,q),[schema]);
    if(authority.rowCount!==1) throw new Error("checkpoint runtime authority row is missing"); assertRuntimeAuthority(authority.rows[0]);
}
function candidateValues(c:IndexerCheckpointHighWaterCandidate):string[] { return [c.finalizedBlockNumber,c.finalizedBlockHash,c.checkpointDigest,c.checkpointTimestamp,
  c.releaseBindingDigest,c.authorizationDigest,c.chainId,c.chainName,c.deploymentCommit,c.deploymentConfigHash]; }

export async function enforceIndexerCheckpointHighWater(snapshot:ActivatedIndexerSnapshot):Promise<void> {
  const c=indexerCheckpointHighWaterCandidate(snapshot); const schema=checkpointSchema(); const q=quoted(schema);
  const client=await portalDatabasePool().connect(); let committed=false;
  try {
    await beginCheckpointTransaction(client); await attestRuntimeAuthority(client,schema,q);
    const exact=await client.query<TransitionRow>(`SELECT * FROM ${q}.p42_read_exact_indexer_checkpoint(
      $1::bigint,$2::text,$3::text,$4::bigint,$5::text,$6::text,$7::bigint,$8::text,$9::text,$10::text
    )`,candidateValues(c));
    if(exact.rowCount===1) {
      assertTransition(exact.rows[0],c);
      if(exact.rows[0]?.transition_kind!=="same") throw new Error("checkpoint exact read returned a transition");
      await client.query("COMMIT"); committed=true; return;
    }
    if(exact.rowCount!==0) throw new Error("checkpoint exact read returned multiple persisted states");
    await client.query("ROLLBACK");
    await beginCheckpointTransaction(client); await attestRuntimeAuthority(client,schema,q);
    const transitioned=await client.query<TransitionRow>(`SELECT * FROM ${q}.p42_transition_indexer_checkpoint(
      $1::bigint,$2::text,$3::text,$4::bigint,$5::text,$6::text,$7::bigint,$8::text,$9::text,$10::text
    )`,candidateValues(c));
    if(transitioned.rowCount!==1) throw new Error("checkpoint transition did not return one persisted state"); assertTransition(transitioned.rows[0],c);
    await client.query("COMMIT");committed=true;
  } finally {if(!committed) await rollback(client);client.release();}
}
