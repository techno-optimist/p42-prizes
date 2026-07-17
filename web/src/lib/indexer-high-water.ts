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
interface PrivilegeRow extends QueryResultRow {
  owns_control:boolean; owns_epoch:boolean; owns_acceptance:boolean; can_create:boolean;
  can_trigger_control:boolean; can_trigger_epoch:boolean; can_trigger_acceptance:boolean; external_triggers:boolean;
  can_insert_control:boolean; can_delete_control:boolean; can_update_epoch:boolean; can_delete_epoch:boolean;
  can_update_acceptance:boolean; can_delete_acceptance:boolean;
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

function assertPrivileges(row:PrivilegeRow):void { if(row.owns_control||row.owns_epoch||row.owns_acceptance||row.can_create||row.can_trigger_control||row.can_trigger_epoch||row.can_trigger_acceptance||row.external_triggers||row.can_insert_control||row.can_delete_control||row.can_update_epoch||row.can_delete_epoch||row.can_update_acceptance||row.can_delete_acceptance) throw new Error("portal checkpoint runtime role is not least-privilege"); }
function validDate(value:unknown):boolean { return (typeof value==="string"||value instanceof Date)&&Number.isFinite(new Date(value).getTime()); }
function assertEpoch(row:IndexerIdentityEpoch,c:IndexerCheckpointHighWaterCandidate,id:string):void {
  const expected:Record<string,string>={epoch_id:id,release_binding_digest:c.releaseBindingDigest,authorization_digest:c.authorizationDigest,chain_id:c.chainId,chain_name:c.chainName,deployment_commit:c.deploymentCommit,deployment_config_hash:c.deploymentConfigHash};
  for(const [key,value] of Object.entries(expected)) if(String(row[key])!==value) throw new Error(`persisted checkpoint epoch mismatch for ${key}`);
  if(!validDate(row.accepted_at)) throw new Error("persisted checkpoint epoch timestamp is invalid");
}
function assertAcceptance(row:IndexerCheckpointAcceptance,c:IndexerCheckpointHighWaterCandidate,epochId:string,id:string):void {
  const expected:Record<string,string>={acceptance_id:id,epoch_id:epochId,finalized_block_number:c.finalizedBlockNumber,finalized_block_hash:c.finalizedBlockHash,checkpoint_digest:c.checkpointDigest,checkpoint_timestamp:c.checkpointTimestamp};
  for(const [key,value] of Object.entries(expected)) if(String(row[key])!==value) throw new Error(`persisted checkpoint acceptance mismatch for ${key}`);
  if(!validDate(row.accepted_at)) throw new Error("persisted checkpoint acceptance timestamp is invalid");
}
function assertControl(row:IndexerCheckpointControl,d:EpochDecision):void { if(row.current_epoch!==d.epochId||row.current_acceptance!==d.acceptanceId||BigInt(row.next_epoch)!==BigInt(d.epochId)+1n||BigInt(row.next_acceptance)!==BigInt(d.acceptanceId)+1n||!validDate(row.updated_at)) throw new Error("persisted checkpoint control mismatch"); }
const EPOCH_COLUMNS="epoch_id,release_binding_digest,authorization_digest,chain_id,chain_name,deployment_commit,deployment_config_hash,accepted_at";
const ACCEPTANCE_COLUMNS="acceptance_id,epoch_id,finalized_block_number,finalized_block_hash,checkpoint_digest,checkpoint_timestamp,accepted_at";
async function rollback(client:PortalDatabaseClient):Promise<void>{await client.query("ROLLBACK").catch(()=>{});}

export async function enforceIndexerCheckpointHighWater(snapshot:ActivatedIndexerSnapshot):Promise<void> {
  const c=indexerCheckpointHighWaterCandidate(snapshot); const client=await portalDatabasePool().connect(); let committed=false;
  try { const timeouts=portalDatabaseTimeouts(); await client.query("BEGIN");
    await client.query("SELECT set_config('lock_timeout',$1,true)",[`${timeouts.lockMs}ms`]); await client.query("SELECT set_config('statement_timeout',$1,true)",[`${timeouts.statementMs}ms`]);
    const privilege=await client.query<PrivilegeRow>(`SELECT
      pg_get_userbyid(control.relowner)=current_user AS owns_control,
      pg_get_userbyid(epoch.relowner)=current_user AS owns_epoch,
      pg_get_userbyid(acceptance.relowner)=current_user AS owns_acceptance,
      has_schema_privilege(current_user,current_schema(),'CREATE') AS can_create,
      has_table_privilege(current_user,'p42_indexer_checkpoint_control','TRIGGER') AS can_trigger_control,
      has_table_privilege(current_user,'p42_indexer_checkpoint_epoch','TRIGGER') AS can_trigger_epoch,
      has_table_privilege(current_user,'p42_indexer_checkpoint_acceptance','TRIGGER') AS can_trigger_acceptance,
      has_table_privilege(current_user,'p42_indexer_checkpoint_control','INSERT') AS can_insert_control,
      has_table_privilege(current_user,'p42_indexer_checkpoint_control','DELETE') AS can_delete_control,
      has_table_privilege(current_user,'p42_indexer_checkpoint_epoch','UPDATE') AS can_update_epoch,
      has_table_privilege(current_user,'p42_indexer_checkpoint_epoch','DELETE') AS can_delete_epoch,
      has_table_privilege(current_user,'p42_indexer_checkpoint_acceptance','UPDATE') AS can_update_acceptance,
      has_table_privilege(current_user,'p42_indexer_checkpoint_acceptance','DELETE') AS can_delete_acceptance,
      EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN(control.oid,epoch.oid,acceptance.oid) AND NOT tgisinternal) AS external_triggers
      FROM pg_class control CROSS JOIN pg_class epoch CROSS JOIN pg_class acceptance
      WHERE control.oid='p42_indexer_checkpoint_control'::regclass AND epoch.oid='p42_indexer_checkpoint_epoch'::regclass
        AND acceptance.oid='p42_indexer_checkpoint_acceptance'::regclass`);
    if(privilege.rowCount!==1) throw new Error("checkpoint runtime privilege attestation failed"); assertPrivileges(privilege.rows[0]);
    const locked=await client.query<IndexerCheckpointControl>(`SELECT current_epoch,current_acceptance,next_epoch,next_acceptance,updated_at FROM p42_indexer_checkpoint_control WHERE singleton=true FOR UPDATE`);
    if(locked.rowCount!==1) throw new Error("indexer checkpoint control singleton is missing");
    const history=await client.query<IndexerIdentityEpoch>(`SELECT ${EPOCH_COLUMNS} FROM p42_indexer_checkpoint_epoch ORDER BY epoch_id`);
    const current=locked.rows[0].current_acceptance===null?null:(await client.query<IndexerCheckpointAcceptance>(`SELECT ${ACCEPTANCE_COLUMNS} FROM p42_indexer_checkpoint_acceptance WHERE acceptance_id=$1`,[locked.rows[0].current_acceptance])).rows[0]??null;
    const decision=decideIndexerCheckpointEpoch(locked.rows[0],history.rows,current,c);
    if(decision.kind==="same"){await client.query("COMMIT");committed=true;return;}
    if(decision.kind==="first"||decision.kind==="renew") {
      const insertedEpoch=await client.query<IndexerIdentityEpoch>(`INSERT INTO p42_indexer_checkpoint_epoch(epoch_id,release_binding_digest,authorization_digest,chain_id,chain_name,deployment_commit,deployment_config_hash,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()) RETURNING ${EPOCH_COLUMNS}`,[decision.epochId,c.releaseBindingDigest,c.authorizationDigest,c.chainId,c.chainName,c.deploymentCommit,c.deploymentConfigHash]);
      if(insertedEpoch.rowCount!==1) throw new Error("checkpoint epoch insert was not persisted"); assertEpoch(insertedEpoch.rows[0],c,decision.epochId);
    }
    const insertedAcceptance=await client.query<IndexerCheckpointAcceptance>(`INSERT INTO p42_indexer_checkpoint_acceptance(acceptance_id,epoch_id,finalized_block_number,finalized_block_hash,checkpoint_digest,checkpoint_timestamp,accepted_at) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()) RETURNING ${ACCEPTANCE_COLUMNS}`,[decision.acceptanceId,decision.epochId,c.finalizedBlockNumber,c.finalizedBlockHash,c.checkpointDigest,c.checkpointTimestamp]);
    if(insertedAcceptance.rowCount!==1) throw new Error("checkpoint acceptance insert was not persisted"); assertAcceptance(insertedAcceptance.rows[0],c,decision.epochId,decision.acceptanceId);
    const updated=await client.query<IndexerCheckpointControl>(`UPDATE p42_indexer_checkpoint_control SET current_epoch=$1,current_acceptance=$2,next_epoch=$1::bigint+1,next_acceptance=$2::bigint+1,updated_at=clock_timestamp() WHERE singleton=true RETURNING current_epoch,current_acceptance,next_epoch,next_acceptance,updated_at`,[decision.epochId,decision.acceptanceId]);
    if(updated.rowCount!==1) throw new Error("checkpoint control update was not persisted"); assertControl(updated.rows[0],decision);
    await client.query("COMMIT");committed=true;
  } finally {if(!committed) await rollback(client);client.release();}
}
