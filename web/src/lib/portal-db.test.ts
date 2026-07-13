import { afterEach, describe, expect, it } from "vitest";
import { setPortalDatabasePoolForTests, type PortalDatabaseClient, type PortalDatabasePool } from "@/lib/portal-db";
import { enforceRateLimitShared } from "@/lib/rate-limit";
import { readPortalStateShared, updatePortalStateShared, type PortalStateSnapshot } from "@/lib/portal-store";

const emptyState = (): PortalStateSnapshot => ({
  schemaVersion: 1,
  commits: [],
  submissions: [],
  idempotency: [],
  events: [],
  eventOffset: 0,
  eventAnchorHash: "genesis",
});

function result(rows: unknown[]) {
  return { rows, rowCount: rows.length, command: "SELECT", oid: 0, fields: [] } as never;
}

afterEach(() => {
  setPortalDatabasePoolForTests();
  delete process.env.P42_PORTAL_DATABASE_URL;
  delete process.env.P42_PORTAL_DATABASE_REQUIRED;
});

describe("shared PostgreSQL portal state", () => {
  it("fails closed when the configured singleton is absent", async () => {
    setPortalDatabasePoolForTests({
      connect: async () => { throw new Error("unused"); },
      query: async () => result([]),
    });

    await expect(readPortalStateShared()).rejects.toThrow("portal database is not initialized");
  });

  it("fails closed when shared storage is required but the URL is absent", async () => {
    process.env.P42_PORTAL_DATABASE_REQUIRED = "1";
    await expect(readPortalStateShared()).rejects.toThrow("P42_PORTAL_DATABASE_REQUIRED=1");
  });

  it("rejects database state that runtime normalization would rewrite", async () => {
    const state = emptyState();
    state.submissions.push({
      id: "sub_noncanonical",
      problemId: 1,
      problemSlug: "hadamard-mini",
      agentName: "agent",
      solutionCid: "sha256:test",
      commitHash: `0x${"1".repeat(64)}`,
      score: "0/1",
      improvement: "1/1",
      credit: "1/1",
      state: "finalized",
      settlementState: "finalized",
      payoutEth: "1.000",
      submittedAt: new Date().toISOString(),
      windowEndsAt: new Date().toISOString(),
      source: "local-phase-0",
      transcriptCid: null,
    });
    setPortalDatabasePoolForTests({
      connect: async () => { throw new Error("unused"); },
      query: async () => result([{ state }]),
    });

    await expect(readPortalStateShared()).rejects.toThrow("not in canonical runtime form");
  });

  it("locks, updates, and commits the singleton transaction", async () => {
    const queries: string[] = [];
    const state = emptyState();
    const client: PortalDatabaseClient = {
      async query(text, values) {
        queries.push(text.replace(/\s+/g, " ").trim());
        if (text.includes("FOR UPDATE")) return result([{ state }]);
        if (text.includes("UPDATE p42_portal_state")) {
          expect(JSON.parse(String(values?.[0])).commits).toHaveLength(1);
        }
        return result([]);
      },
      release() {},
    };
    const pool: PortalDatabasePool = { connect: async () => client, query: async () => result([]) };
    setPortalDatabasePoolForTests(pool);

    const updated = await updatePortalStateShared((snapshot) => {
      snapshot.commits.push({
        id: "commit_test",
        problemId: 1,
        agentName: "agent",
        solverAddress: "0x0000000000000000000000000000000000000001",
        solutionCid: "sha256:test",
        commitHash: `0x${"1".repeat(64)}`,
        commitAlgorithm: "keccak256-p42-local-v0",
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        revealed: false,
      });
    });

    expect(updated.commits).toHaveLength(1);
    expect(queries[0]).toBe("BEGIN");
    expect(queries.some((query) => query.includes("FOR UPDATE"))).toBe(true);
    expect(queries.some((query) => query.startsWith("UPDATE p42_portal_state"))).toBe(true);
    expect(queries.at(-1)).toBe("COMMIT");
  });

  it("rolls back and preserves the original mutation error", async () => {
    const queries: string[] = [];
    const client: PortalDatabaseClient = {
      async query(text) {
        queries.push(text);
        if (text.includes("FOR UPDATE")) return result([{ state: emptyState() }]);
        return result([]);
      },
      release() {},
    };
    setPortalDatabasePoolForTests({ connect: async () => client, query: async () => result([]) });

    await expect(updatePortalStateShared(() => { throw new Error("mutator rejected"); })).rejects.toThrow(
      "mutator rejected",
    );
    expect(queries).toContain("ROLLBACK");
    expect(queries).not.toContain("COMMIT");
  });

  it("uses the database result as the atomic distributed rate-limit decision", async () => {
    let count = 1;
    setPortalDatabasePoolForTests({
      connect: async () => { throw new Error("unused"); },
      query: async () => result([{ count, expires_at: new Date(Date.now() + 30_000) }]),
    });
    const request = new Request("https://example.test/api/solutions");
    const policy = { id: "solutions", limit: 1, windowMs: 30_000 };

    await expect(enforceRateLimitShared(request, policy, "ip:test")).resolves.toBeUndefined();
    count = 2;
    await expect(enforceRateLimitShared(request, policy, "ip:test")).rejects.toMatchObject({ status: 429 });
  });
});
