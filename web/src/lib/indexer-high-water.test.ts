import { afterEach, describe, expect, it } from "vitest";
import type { QueryResult, QueryResultRow } from "pg";
import type { ActivatedIndexerSnapshot } from "@/lib/indexer-provenance";
import {
  enforceIndexerCheckpointHighWater,
  indexerCheckpointHighWaterCandidate,
  type IndexerCheckpointHighWaterCandidate,
} from "@/lib/indexer-high-water";
import {
  setPortalDatabasePoolForTests,
  type PortalDatabaseClient,
  type PortalDatabasePool,
} from "@/lib/portal-db";

const BLOCK_HASH = `0x${"1".repeat(64)}`;
const RELEASE_DIGEST = `sha256:${"2".repeat(64)}`;
const AUTHORIZATION_DIGEST = `sha256:${"3".repeat(64)}`;
const CONFIG_HASH = `0x${"4".repeat(64)}`;

function snapshot(): ActivatedIndexerSnapshot {
  return {
    manifest: {
      network: { name: "baseSepolia", chainId: 84532, explorerBaseUrl: "https://sepolia.basescan.org" },
      releaseEvidence: { releaseBindingDigest: RELEASE_DIGEST },
      deploymentCommit: "a".repeat(40),
      deploymentConfigHash: CONFIG_HASH,
    },
    checkpoint: {
      schema: "p42-prizes/indexer-checkpoint/v4",
      range: { fromBlock: 1, toBlock: 100, toBlockHash: BLOCK_HASH, toBlockTimestamp: 1_000 },
      boards: [],
    },
    provenance: new Map([["board", { fundingAuthorizationDigest: AUTHORIZATION_DIGEST } as never]]),
    highWaterIdentity: {
      checkpointDigest: `sha256:${"9".repeat(64)}`,
      releaseBindingDigest: RELEASE_DIGEST,
      authorizationDigest: AUTHORIZATION_DIGEST,
      chainId: 84532,
      chainName: "baseSepolia",
      deploymentCommit: "a".repeat(40),
      deploymentConfigHash: CONFIG_HASH,
    },
  };
}

type StoredRow = {
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
};

function row(candidate?: IndexerCheckpointHighWaterCandidate): StoredRow {
  return {
    finalized_block_number: candidate?.finalizedBlockNumber ?? null,
    finalized_block_hash: candidate?.finalizedBlockHash ?? null,
    checkpoint_digest: candidate?.checkpointDigest ?? null,
    checkpoint_timestamp: candidate?.checkpointTimestamp ?? null,
    release_binding_digest: candidate?.releaseBindingDigest ?? null,
    authorization_digest: candidate?.authorizationDigest ?? null,
    chain_id: candidate?.chainId ?? null,
    chain_name: candidate?.chainName ?? null,
    deployment_commit: candidate?.deploymentCommit ?? null,
    deployment_config_hash: candidate?.deploymentConfigHash ?? null,
  };
}

function result<R extends QueryResultRow>(rows: R[]): QueryResult<R> {
  return { rows, rowCount: rows.length, command: "SELECT", oid: 0, fields: [] };
}

function database(current: StoredRow, failOn?: "update" | "commit") {
  const queries: string[] = [];
  const values: unknown[][] = [];
  const client: PortalDatabaseClient = {
    async query<R extends QueryResultRow>(text: string, parameters?: unknown[]) {
      const compact = text.replace(/\s+/g, " ").trim();
      queries.push(compact);
      if (parameters) values.push(parameters);
      if (compact.endsWith("FOR UPDATE")) return result([current as unknown as R]);
      if (compact.startsWith("UPDATE p42_indexer_checkpoint_high_water")) {
        if (failOn === "update") throw new Error("database write failed");
        Object.assign(current, row({
          finalizedBlockNumber: String(parameters![0]),
          finalizedBlockHash: String(parameters![1]),
          checkpointDigest: String(parameters![2]),
          checkpointTimestamp: String(parameters![3]),
          releaseBindingDigest: String(parameters![4]),
          authorizationDigest: String(parameters![5]),
          chainId: String(parameters![6]),
          chainName: String(parameters![7]),
          deploymentCommit: String(parameters![8]),
          deploymentConfigHash: String(parameters![9]),
        }));
        return result([{} as unknown as R]);
      }
      if (compact === "COMMIT" && failOn === "commit") throw new Error("database commit failed");
      return result([] as R[]);
    },
    release() {
      queries.push("RELEASE");
    },
  };
  const pool: PortalDatabasePool = {
    connect: async () => client,
    query: async <R extends QueryResultRow>() => result([] as R[]),
  };
  setPortalDatabasePoolForTests(pool);
  return { queries, values, current };
}

afterEach(() => {
  setPortalDatabasePoolForTests();
  delete process.env.P42_PORTAL_DATABASE_URL;
});

describe("durable indexer checkpoint high-water gate", () => {
  it("uses the already-validated raw checkpoint digest as the durable identity", () => {
    const value = snapshot();
    expect(indexerCheckpointHighWaterCandidate(value).checkpointDigest).toBe(value.highWaterIdentity.checkpointDigest);
  });

  it("accepts and commits the first checkpoint before resolving", async () => {
    const db = database(row());
    const candidate = indexerCheckpointHighWaterCandidate(snapshot());
    await enforceIndexerCheckpointHighWater(snapshot());

    expect(db.current).toEqual(row(candidate));
    expect(db.queries[0]).toBe("BEGIN");
    expect(db.queries.some((query) => query.endsWith("FOR UPDATE"))).toBe(true);
    expect(db.queries.indexOf("COMMIT")).toBeGreaterThan(db.queries.findIndex((query) => query.startsWith("UPDATE")));
    expect(db.queries.at(-1)).toBe("RELEASE");
  });

  it("accepts a higher finalized block and an exact same-height replay", async () => {
    const first = snapshot();
    const stored = row(indexerCheckpointHighWaterCandidate(first));
    const db = database(stored);
    const higher = structuredClone(first);
    (higher.checkpoint.range as Record<string, unknown>).toBlock = 101;
    (higher.checkpoint.range as Record<string, unknown>).toBlockHash = `0x${"5".repeat(64)}`;
    (higher.checkpoint.range as Record<string, unknown>).toBlockTimestamp = 1_001;

    await enforceIndexerCheckpointHighWater(higher);
    const accepted = indexerCheckpointHighWaterCandidate(higher);
    expect(db.current).toEqual(row(accepted));
    await enforceIndexerCheckpointHighWater(higher);
    expect(db.queries.filter((query) => query === "COMMIT")).toHaveLength(2);
  });

  it.each([
    ["lower finalized block", (value: ActivatedIndexerSnapshot) => {
      (value.checkpoint.range as Record<string, unknown>).toBlock = 99;
    }, "finalized block regression"],
    ["same-height block hash conflict", (value: ActivatedIndexerSnapshot) => {
      (value.checkpoint.range as Record<string, unknown>).toBlockHash = `0x${"6".repeat(64)}`;
    }, "same-height conflict"],
    ["same-height checkpoint digest conflict", (value: ActivatedIndexerSnapshot) => {
      value.highWaterIdentity = { ...value.highWaterIdentity, checkpointDigest: `sha256:${"a".repeat(64)}` };
    }, "same-height conflict"],
    ["timestamp regression", (value: ActivatedIndexerSnapshot) => {
      (value.checkpoint.range as Record<string, unknown>).toBlock = 101;
      (value.checkpoint.range as Record<string, unknown>).toBlockTimestamp = 999;
    }, "timestamp regression"],
    ["release identity drift", (value: ActivatedIndexerSnapshot) => {
      value.highWaterIdentity = { ...value.highWaterIdentity, releaseBindingDigest: `sha256:${"7".repeat(64)}` };
    }, "release identity drift"],
    ["authorization identity drift", (value: ActivatedIndexerSnapshot) => {
      value.highWaterIdentity = { ...value.highWaterIdentity, authorizationDigest: `sha256:${"8".repeat(64)}` };
    }, "authorization identity drift"],
    ["chain identity drift", (value: ActivatedIndexerSnapshot) => {
      value.highWaterIdentity = { ...value.highWaterIdentity, chainId: 8453 };
    }, "chain identity drift"],
  ])("rejects %s after locking and rolls back", async (_label, mutate, message) => {
    const first = snapshot();
    const db = database(row(indexerCheckpointHighWaterCandidate(first)));
    const contender = structuredClone(first);
    mutate(contender);

    await expect(enforceIndexerCheckpointHighWater(contender)).rejects.toThrow(message);
    expect(db.queries.some((query) => query.endsWith("FOR UPDATE"))).toBe(true);
    expect(db.queries).toContain("ROLLBACK");
    expect(db.queries).not.toContain("COMMIT");
  });

  it.each(["update", "commit"] as const)("fails closed when the database %s fails", async (failure) => {
    const db = database(row(), failure);
    await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow(
      failure === "update" ? "database write failed" : "database commit failed",
    );
    expect(db.queries).toContain("ROLLBACK");
    expect(db.queries.at(-1)).toBe("RELEASE");
  });

  it("fails closed when the locked singleton update affects no row", async () => {
    const queries: string[] = [];
    const client: PortalDatabaseClient = {
      async query<R extends QueryResultRow>(text: string) {
        const compact = text.replace(/\s+/g, " ").trim();
        queries.push(compact);
        if (compact.endsWith("FOR UPDATE")) return result([row() as unknown as R]);
        return result([] as R[]);
      },
      release() {},
    };
    setPortalDatabasePoolForTests({ connect: async () => client, query: async () => result([]) });

    await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow("update was not persisted");
    expect(queries).toContain("ROLLBACK");
    expect(queries).not.toContain("COMMIT");
  });

  it("fails closed when the database is unavailable", async () => {
    setPortalDatabasePoolForTests({
      connect: async () => { throw new Error("database unavailable"); },
      query: async <R extends QueryResultRow>() => result([] as R[]),
    });
    await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow("database unavailable");
  });
});
