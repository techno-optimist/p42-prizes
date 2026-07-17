import type { QueryResultRow } from "pg";
import type { ActivatedIndexerSnapshot } from "@/lib/indexer-provenance";
import {
  portalDatabasePool,
  portalDatabaseTimeouts,
  type PortalDatabaseClient,
} from "@/lib/portal-db";

type JsonObject = Record<string, unknown>;

const BLOCK_HASH = /^0x[0-9a-fA-F]{64}$/;
const BYTES32 = /^0x[0-9a-fA-F]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-fA-F]{40}$/;

export interface IndexerCheckpointHighWaterCandidate {
  finalizedBlockNumber: string;
  finalizedBlockHash: string;
  checkpointDigest: string;
  checkpointTimestamp: string;
  releaseBindingDigest: string;
  authorizationDigest: string;
  chainId: string;
  chainName: string;
  deploymentCommit: string;
  deploymentConfigHash: string;
}

interface HighWaterRow extends QueryResultRow {
  finalized_block_number: string | null;
  finalized_block_hash: string | null;
  checkpoint_digest: string | null;
  checkpoint_timestamp: string | null;
  release_binding_digest: string | null;
  authorization_digest: string | null;
  chain_id: string | null;
  chain_name: string | null;
  deployment_commit: string | null;
  deployment_config_hash: string | null;
}

function object(value: unknown, label: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonObject;
}

function safeUnsignedInteger(value: unknown, label: string, positive = false): string {
  if (!Number.isSafeInteger(value) || Number(value) < (positive ? 1 : 0)) {
    throw new Error(`${label} must be a safe unsigned integer`);
  }
  return String(value);
}

function normalized(value: unknown, pattern: RegExp, label: string): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${label} is invalid`);
  return value.toLowerCase();
}

export function indexerCheckpointHighWaterCandidate(
  snapshot: ActivatedIndexerSnapshot,
): IndexerCheckpointHighWaterCandidate {
  const range = object(snapshot.checkpoint.range, "activated checkpoint range");
  const identity = snapshot.highWaterIdentity;
  const chainName = identity.chainName;
  if (typeof chainName !== "string" || !/^[a-z][A-Za-z0-9]*$/.test(chainName)) {
    throw new Error("activated checkpoint chain name is invalid");
  }
  return {
    finalizedBlockNumber: safeUnsignedInteger(range.toBlock, "activated checkpoint finalized block"),
    finalizedBlockHash: normalized(range.toBlockHash, BLOCK_HASH, "activated checkpoint finalized block hash"),
    checkpointDigest: normalized(identity.checkpointDigest, SHA256, "attested raw checkpoint digest"),
    checkpointTimestamp: safeUnsignedInteger(range.toBlockTimestamp, "activated checkpoint timestamp", true),
    releaseBindingDigest: normalized(
      identity.releaseBindingDigest,
      SHA256,
      "activated checkpoint release binding digest",
    ),
    authorizationDigest: normalized(identity.authorizationDigest, SHA256, "activated checkpoint authorization digest"),
    chainId: safeUnsignedInteger(identity.chainId, "activated checkpoint chain id", true),
    chainName,
    deploymentCommit: normalized(identity.deploymentCommit, COMMIT, "activated deployment commit"),
    deploymentConfigHash: normalized(
      identity.deploymentConfigHash,
      BYTES32,
      "activated deployment config hash",
    ),
  };
}

function assertIdentity(current: HighWaterRow, candidate: IndexerCheckpointHighWaterCandidate): void {
  const bindings: Array<[keyof HighWaterRow, keyof IndexerCheckpointHighWaterCandidate, string]> = [
    ["release_binding_digest", "releaseBindingDigest", "release"],
    ["authorization_digest", "authorizationDigest", "authorization"],
    ["chain_id", "chainId", "chain"],
    ["chain_name", "chainName", "chain"],
    ["deployment_commit", "deploymentCommit", "release"],
    ["deployment_config_hash", "deploymentConfigHash", "release"],
  ];
  for (const [rowKey, candidateKey, identity] of bindings) {
    if (current[rowKey] !== candidate[candidateKey]) {
      throw new Error(`activated checkpoint ${identity} identity drift`);
    }
  }
}

function assertMonotonic(current: HighWaterRow, candidate: IndexerCheckpointHighWaterCandidate): void {
  if (current.finalized_block_number === null) return;
  assertIdentity(current, candidate);
  if (BigInt(candidate.checkpointTimestamp) < BigInt(current.checkpoint_timestamp!)) {
    throw new Error("activated checkpoint timestamp regression");
  }
  const candidateBlock = BigInt(candidate.finalizedBlockNumber);
  const currentBlock = BigInt(current.finalized_block_number);
  if (candidateBlock < currentBlock) throw new Error("activated checkpoint finalized block regression");
  if (candidateBlock === currentBlock) {
    const exact = current.finalized_block_hash === candidate.finalizedBlockHash
      && current.checkpoint_digest === candidate.checkpointDigest
      && current.checkpoint_timestamp === candidate.checkpointTimestamp;
    if (!exact) throw new Error("activated checkpoint same-height conflict");
  }
}

async function rollback(client: PortalDatabaseClient): Promise<void> {
  await client.query("ROLLBACK").catch(() => {});
}

export async function enforceIndexerCheckpointHighWater(snapshot: ActivatedIndexerSnapshot): Promise<void> {
  const candidate = indexerCheckpointHighWaterCandidate(snapshot);
  const client = await portalDatabasePool().connect();
  let committed = false;
  try {
    const timeouts = portalDatabaseTimeouts();
    await client.query("BEGIN");
    await client.query("SELECT set_config('lock_timeout', $1, true)", [`${timeouts.lockMs}ms`]);
    await client.query("SELECT set_config('statement_timeout', $1, true)", [`${timeouts.statementMs}ms`]);
    const result = await client.query<HighWaterRow>(
      `SELECT finalized_block_number, finalized_block_hash, checkpoint_digest, checkpoint_timestamp,
              release_binding_digest, authorization_digest, chain_id, chain_name,
              deployment_commit, deployment_config_hash
         FROM p42_indexer_checkpoint_high_water
        WHERE singleton = true
        FOR UPDATE`,
    );
    if (result.rowCount !== 1) throw new Error("indexer checkpoint high-water singleton is missing");
    const current = result.rows[0];
    assertMonotonic(current, candidate);
    const update = await client.query(
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
              accepted_at = COALESCE(accepted_at, clock_timestamp()),
              updated_at = clock_timestamp()
        WHERE singleton = true`,
      [
        candidate.finalizedBlockNumber,
        candidate.finalizedBlockHash,
        candidate.checkpointDigest,
        candidate.checkpointTimestamp,
        candidate.releaseBindingDigest,
        candidate.authorizationDigest,
        candidate.chainId,
        candidate.chainName,
        candidate.deploymentCommit,
        candidate.deploymentConfigHash,
      ],
    );
    if (update.rowCount !== 1) throw new Error("indexer checkpoint high-water update was not persisted");
    await client.query("COMMIT");
    committed = true;
  } finally {
    if (!committed) await rollback(client);
    client.release();
  }
}
