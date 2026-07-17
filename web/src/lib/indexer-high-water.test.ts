import { afterEach, describe, expect, it } from "vitest";
import type { QueryResult, QueryResultRow } from "pg";
import type { ActivatedIndexerSnapshot } from "@/lib/indexer-provenance";
import {
  decideIndexerCheckpointEpoch,
  enforceIndexerCheckpointHighWater,
  indexerCheckpointHighWaterCandidate,
  type IndexerCheckpointAcceptance,
  type IndexerCheckpointHighWaterCandidate,
  type IndexerIdentityEpoch,
} from "@/lib/indexer-high-water";
import { setPortalDatabasePoolForTests, type PortalDatabaseClient } from "@/lib/portal-db";

const hash = (digit: string) => `0x${digit.repeat(64)}`;
const digest = (digit: string) => `sha256:${digit.repeat(64)}`;

function snapshot(): ActivatedIndexerSnapshot {
  return {
    manifest: {},
    checkpoint: { range: { toBlock: 100, toBlockHash: hash("1"), toBlockTimestamp: 1_000 } },
    provenance: new Map(),
    highWaterIdentity: {
      checkpointDigest: digest("9"), releaseBindingDigest: digest("2"), authorizationDigest: digest("3"),
      chainId: 84532, chainName: "baseSepolia", deploymentCommit: "a".repeat(40),
      deploymentConfigHash: hash("4"),
    },
  };
}

function result<R extends QueryResultRow>(rows: R[]): QueryResult<R> {
  return { rows, rowCount: rows.length, command: "SELECT", oid: 0, fields: [] };
}

function epoch(candidate: IndexerCheckpointHighWaterCandidate, epochId = "1"): IndexerIdentityEpoch {
  return {
    epoch_id: epochId, release_binding_digest: candidate.releaseBindingDigest,
    authorization_digest: candidate.authorizationDigest, chain_id: candidate.chainId,
    chain_name: candidate.chainName, deployment_commit: candidate.deploymentCommit,
    deployment_config_hash: candidate.deploymentConfigHash, accepted_at: "2026-01-01T00:00:00.000Z",
  };
}

function acceptance(candidate: IndexerCheckpointHighWaterCandidate, acceptanceId = "1", epochId = "1"): IndexerCheckpointAcceptance {
  return {
    acceptance_id: acceptanceId, epoch_id: epochId, finalized_block_number: candidate.finalizedBlockNumber,
    finalized_block_hash: candidate.finalizedBlockHash, checkpoint_digest: candidate.checkpointDigest,
    checkpoint_timestamp: candidate.checkpointTimestamp, accepted_at: "2026-01-01T00:00:00.000Z",
  };
}

function database(options: { authorityFailure?: string; returningMismatch?: boolean; exactMatch?: boolean } = {}) {
  const queries: string[] = [];
  const client: PortalDatabaseClient = {
    async query<R extends QueryResultRow>(text: string, values?: unknown[]) {
      const sql = text.replace(/\s+/g, " ").trim(); queries.push(sql);
      if (sql.includes("WITH pinned AS")) {
        const authority = {
          identity_matches: true, function_matches: true, acl_matches: true, safe_role: true,
          no_direct_writes: true, no_dangerous_set_role: true, no_external_triggers: true,
        };
        if (options.authorityFailure) authority[options.authorityFailure as keyof typeof authority] = false;
        return result([authority as unknown as R]);
      }
      if (sql.includes("p42_read_exact_indexer_checkpoint") && !options.exactMatch) return result([] as R[]);
      if (sql.includes("p42_transition_indexer_checkpoint") || sql.includes("p42_read_exact_indexer_checkpoint")) {
        const row = {
          transition_kind: options.exactMatch ? "same" : "first", epoch_id: "1", release_binding_digest: String(values![4]),
          authorization_digest: String(values![5]), chain_id: String(values![6]), chain_name: String(values![7]),
          deployment_commit: String(values![8]), deployment_config_hash: String(values![9]),
          epoch_accepted_at: "2026-01-01T00:00:00.000Z", acceptance_id: "1",
          finalized_block_number: String(values![0]), finalized_block_hash: String(values![1]),
          checkpoint_digest: options.returningMismatch ? digest("f") : String(values![2]),
          checkpoint_timestamp: String(values![3]), acceptance_accepted_at: "2026-01-01T00:00:00.000Z",
          current_epoch: "1", current_acceptance: "1", next_epoch: "2", next_acceptance: "2",
          control_updated_at: "2026-01-01T00:00:00.000Z",
        };
        return result([row as unknown as R]);
      }
      return result([] as R[]);
    },
    release() { queries.push("RELEASE"); },
  };
  setPortalDatabasePoolForTests({ connect: async () => client, query: async () => result([]) });
  return queries;
}

afterEach(() => {
  setPortalDatabasePoolForTests();
  delete process.env.P42_PORTAL_DATABASE_URL;
  delete process.env.P42_PORTAL_DATABASE_REQUIRED;
  delete process.env.P42_PORTAL_DATABASE_SCHEMA;
});

describe("database-enforced indexer checkpoint epoch gate", () => {
  it("uses the validated raw checkpoint digest", () => {
    const value = snapshot();
    expect(indexerCheckpointHighWaterCandidate(value).checkpointDigest).toBe(value.highWaterIdentity.checkpointDigest);
  });

  it("forces pg_catalog, calls only the pinned owner function, validates its return, then commits", async () => {
    process.env.P42_PORTAL_DATABASE_SCHEMA = "p42_portal";
    const queries = database();
    await enforceIndexerCheckpointHighWater(snapshot());
    expect(queries).toContain("SELECT set_config('search_path','pg_catalog',true)");
    expect(queries.some((query) => query.includes('FROM "p42_portal".p42_transition_indexer_checkpoint'))).toBe(true);
    expect(queries.some((query) => /INSERT INTO|UPDATE p42_indexer/.test(query))).toBe(false);
    expect(queries.at(-2)).toBe("COMMIT");
  });

  it("returns an exact unchanged checkpoint without invoking the serialized transition", async () => {
    process.env.P42_PORTAL_DATABASE_SCHEMA = "p42_portal";
    const queries = database({ exactMatch: true });
    await enforceIndexerCheckpointHighWater(snapshot());
    expect(queries.some((query) => query.includes('FROM "p42_portal".p42_read_exact_indexer_checkpoint'))).toBe(true);
    expect(queries.some((query) => query.includes('FROM "p42_portal".p42_transition_indexer_checkpoint'))).toBe(false);
    expect(queries.filter((query) => query === "BEGIN")).toHaveLength(1);
    expect(queries).not.toContain("ROLLBACK");
  });

  it("releases the shared exact-read transaction before entering serialized transition", async () => {
    process.env.P42_PORTAL_DATABASE_SCHEMA = "p42_portal";
    const queries = database();
    await enforceIndexerCheckpointHighWater(snapshot());
    const exact = queries.findIndex((query) => query.includes('FROM "p42_portal".p42_read_exact_indexer_checkpoint'));
    const rollback = queries.indexOf("ROLLBACK");
    const transition = queries.findIndex((query) => query.includes('FROM "p42_portal".p42_transition_indexer_checkpoint'));
    expect(exact).toBeLessThan(rollback); expect(rollback).toBeLessThan(transition);
    expect(queries.filter((query) => query === "BEGIN")).toHaveLength(2);
  });

  it.each(["identity_matches", "function_matches", "acl_matches", "safe_role", "no_direct_writes", "no_dangerous_set_role", "no_external_triggers"])(
    "fails closed when %s is false", async (authorityFailure) => {
      process.env.P42_PORTAL_DATABASE_SCHEMA = "p42_portal";
      const queries = database({ authorityFailure });
      await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow("authority attestation failed");
      expect(queries).toContain("ROLLBACK");
      expect(queries.some((query) => query.includes('FROM "p42_portal".p42_transition_indexer_checkpoint('))).toBe(false);
    },
  );

  it("rolls back a mismatched persisted function return", async () => {
    process.env.P42_PORTAL_DATABASE_SCHEMA = "p42_portal";
    const queries = database({ returningMismatch: true });
    await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow("persisted checkpoint transition mismatch");
    expect(queries).toContain("ROLLBACK"); expect(queries).not.toContain("COMMIT");
  });

  it("requires an explicit schema in production mode", async () => {
    process.env.P42_PORTAL_DATABASE_REQUIRED = "1"; database();
    await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow("P42_PORTAL_DATABASE_SCHEMA is required");
  });

  it("fails closed when PostgreSQL is unavailable", async () => {
    process.env.P42_PORTAL_DATABASE_SCHEMA = "p42_portal";
    setPortalDatabasePoolForTests({ connect: async () => { throw new Error("database unavailable"); }, query: async () => result([]) });
    await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow("database unavailable");
  });

  it("retains the monotonic epoch rules as a pure cross-check", () => {
    const first = indexerCheckpointHighWaterCandidate(snapshot());
    const currentIdentity = epoch(first); const currentAcceptance = acceptance(first);
    const control = { current_epoch: "1", current_acceptance: "1", next_epoch: "2", next_acceptance: "2", updated_at: currentIdentity.accepted_at };
    expect(decideIndexerCheckpointEpoch(control, [currentIdentity], currentAcceptance, first)).toEqual({ kind: "same", epochId: "1", acceptanceId: "1" });
    const renewed = { ...first, finalizedBlockNumber: "101", checkpointTimestamp: "1001",
      checkpointDigest: digest("5"), releaseBindingDigest: digest("6"), authorizationDigest: digest("7"),
      deploymentConfigHash: hash("8") };
    expect(decideIndexerCheckpointEpoch(control, [currentIdentity], currentAcceptance, renewed)).toEqual({ kind: "renew", epochId: "2", acceptanceId: "2" });
  });
});
