import { afterEach, describe, expect, it } from "vitest";
import type { QueryResult, QueryResultRow } from "pg";
import type { ActivatedIndexerSnapshot } from "@/lib/indexer-provenance";
import {
  decideIndexerCheckpointEpoch,
  enforceIndexerCheckpointHighWater,
  indexerCheckpointHighWaterCandidate,
  type IndexerIdentityEpoch,
  type IndexerCheckpointAcceptance,
  type IndexerCheckpointHighWaterCandidate,
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

function epoch(candidate: IndexerCheckpointHighWaterCandidate, epochId = "1"): IndexerIdentityEpoch {
  return {
    epoch_id: epochId, release_binding_digest: candidate.releaseBindingDigest,
    authorization_digest: candidate.authorizationDigest, chain_id: candidate.chainId, chain_name: candidate.chainName,
    deployment_commit: candidate.deploymentCommit, deployment_config_hash: candidate.deploymentConfigHash,
    accepted_at: "2026-01-01T00:00:00.000Z",
  };
}
function acceptance(candidate: IndexerCheckpointHighWaterCandidate, acceptanceId="1", epochId="1"):IndexerCheckpointAcceptance {
  return {acceptance_id:acceptanceId,epoch_id:epochId,finalized_block_number:candidate.finalizedBlockNumber,
    finalized_block_hash:candidate.finalizedBlockHash,checkpoint_digest:candidate.checkpointDigest,
    checkpoint_timestamp:candidate.checkpointTimestamp,accepted_at:"2026-01-01T00:00:00.000Z"};
}

function result<R extends QueryResultRow>(rows: R[]): QueryResult<R> {
  return { rows, rowCount: rows.length, command: "SELECT", oid: 0, fields: [] };
}

type DbOptions = {
  epochs?: IndexerIdentityEpoch[];
  acceptances?: IndexerCheckpointAcceptance[];
  currentEpoch?: string | null;
  privilege?: Partial<Record<"owns_control" | "owns_epoch" | "can_create" | "can_trigger_control" | "can_trigger_epoch" | "external_triggers" | "can_update_epoch", boolean>>;
  returningMismatch?: boolean;
};

function database(options: DbOptions = {}) {
  const epochs = structuredClone(options.epochs ?? []);
  const acceptances=structuredClone(options.acceptances??[]);
  const control = {
    current_epoch: options.currentEpoch ?? null,
    current_acceptance: options.currentEpoch ? acceptances.at(-1)?.acceptance_id??"1" : null,
    next_epoch: options.currentEpoch ? String(BigInt(options.currentEpoch) + 1n) : "1",
    next_acceptance: options.currentEpoch ? String(BigInt(acceptances.at(-1)?.acceptance_id??"1")+1n) : "1",
    updated_at: options.currentEpoch ? "2026-01-01T00:00:00.000Z" : null,
  };
  const queries: string[] = [];
  const client: PortalDatabaseClient = {
    async query<R extends QueryResultRow>(text: string, values?: unknown[]) {
      const sql = text.replace(/\s+/g, " ").trim(); queries.push(sql);
      if (sql.includes("AS owns_control")) return result([{
        runtime_user: "p42_runtime", owns_control: false, owns_epoch: false, owns_acceptance:false, can_create: false,
        can_trigger_control: false, can_trigger_epoch: false, can_trigger_acceptance:false, external_triggers: false,
        can_insert_control:false,can_delete_control:false,can_update_epoch:false,can_delete_epoch:false,
        can_update_acceptance:false,can_delete_acceptance:false,
        ...options.privilege,
      } as unknown as R]);
      if (sql.includes("FROM p42_indexer_checkpoint_control") && sql.endsWith("FOR UPDATE")) {
        return result([control as unknown as R]);
      }
      if (sql.includes("FROM p42_indexer_checkpoint_epoch ORDER BY")) return result(epochs as unknown as R[]);
      if(sql.includes("FROM p42_indexer_checkpoint_acceptance WHERE acceptance_id")) return result(acceptances.slice(-1) as unknown as R[]);
      if (sql.startsWith("INSERT INTO p42_indexer_checkpoint_epoch")) {
        const candidate={releaseBindingDigest:String(values![1]),authorizationDigest:String(values![2]),chainId:String(values![3]),chainName:String(values![4]),deploymentCommit:String(values![5]),deploymentConfigHash:String(values![6])} as IndexerCheckpointHighWaterCandidate;
        const inserted=epoch(candidate,String(values![0]));
        if(options.returningMismatch) inserted.release_binding_digest=digest("f");
        epochs.push(inserted); return result([inserted as unknown as R]);
      }
      if(sql.startsWith("INSERT INTO p42_indexer_checkpoint_acceptance")) {
        const inserted={acceptance_id:String(values![0]),epoch_id:String(values![1]),finalized_block_number:String(values![2]),finalized_block_hash:String(values![3]),checkpoint_digest:options.returningMismatch?digest("f"):String(values![4]),checkpoint_timestamp:String(values![5]),accepted_at:"2026-01-01T00:00:01.000Z"};
        acceptances.push(inserted);return result([inserted as unknown as R]);
      }
      if (sql.startsWith("UPDATE p42_indexer_checkpoint_control")) {
        control.current_epoch=String(values![0]);control.current_acceptance=String(values![1]);control.next_epoch=String(BigInt(String(values![0]))+1n);control.next_acceptance=String(BigInt(String(values![1]))+1n);
        control.updated_at = "2026-01-01T00:00:01.000Z"; return result([control as unknown as R]);
      }
      return result([] as R[]);
    },
    release() { queries.push("RELEASE"); },
  };
  setPortalDatabasePoolForTests({ connect: async () => client, query: async () => result([]) });
  return { epochs, acceptances, control, queries };
}

function mutateIdentity(value: ActivatedIndexerSnapshot, digit: string): void {
  value.highWaterIdentity = {
    ...value.highWaterIdentity,
    checkpointDigest: digest(digit), releaseBindingDigest: digest(digit), authorizationDigest: digest(digit),
    deploymentCommit: digit.repeat(40), deploymentConfigHash: hash(digit),
  };
}

afterEach(() => { setPortalDatabasePoolForTests(); delete process.env.P42_PORTAL_DATABASE_URL; });

describe("append-preserving indexer checkpoint epoch gate", () => {
  it("uses the validated raw checkpoint digest", () => {
    const value = snapshot();
    expect(indexerCheckpointHighWaterCandidate(value).checkpointDigest).toBe(value.highWaterIdentity.checkpointDigest);
  });

  it("inserts the first epoch, verifies RETURNING, updates control, then commits", async () => {
    const db = database(); await enforceIndexerCheckpointHighWater(snapshot());
    expect(db.epochs).toHaveLength(1); expect(db.control).toMatchObject({ current_epoch: "1", next_epoch: "2" });
    expect(db.queries.indexOf("COMMIT")).toBeGreaterThan(db.queries.findIndex((query) => query.includes("RETURNING current_epoch")));
  });

  it("advances the current identity in place and permits an exact replay", async () => {
    const first = snapshot(); const initial=indexerCheckpointHighWaterCandidate(first); const stored = epoch(initial);
    const db = database({ epochs: [stored], acceptances:[acceptance(initial)], currentEpoch: "1" });
    const higher = structuredClone(first); (higher.checkpoint.range as Record<string, unknown>).toBlock = 101;
    (higher.checkpoint.range as Record<string, unknown>).toBlockHash = hash("5");
    (higher.checkpoint.range as Record<string, unknown>).toBlockTimestamp = 1_001;
    await enforceIndexerCheckpointHighWater(higher); await enforceIndexerCheckpointHighWater(higher);
    expect(db.epochs).toHaveLength(1); expect(db.acceptances.map(item=>item.finalized_block_number)).toEqual(["100","101"]);
    expect(db.queries.filter((query) => query === "COMMIT")).toHaveLength(2);
  });

  it("renews identity into a new same-chain epoch while preserving history", async () => {
    const first = snapshot(); const initial=indexerCheckpointHighWaterCandidate(first); const prior = epoch(initial);
    const db = database({ epochs: [prior], acceptances:[acceptance(initial)], currentEpoch: "1" });
    const renewed = structuredClone(first); mutateIdentity(renewed, "6");
    (renewed.checkpoint.range as Record<string, unknown>).toBlock = 101;
    (renewed.checkpoint.range as Record<string, unknown>).toBlockHash = hash("6");
    (renewed.checkpoint.range as Record<string, unknown>).toBlockTimestamp = 1_001;
    await enforceIndexerCheckpointHighWater(renewed);
    expect(db.epochs.map((item) => item.epoch_id)).toEqual(["1", "2"]);
    expect(db.epochs[0]).toEqual(prior); expect(db.control.current_epoch).toBe("2");
  });

  it("allows a conservative transition to a historically unseen chain without comparing block heights", () => {
    const first = indexerCheckpointHighWaterCandidate(snapshot()); const current = epoch(first); const currentAcceptance=acceptance(first);
    const next = { ...first, chainId: "8453", chainName: "baseMainnet", finalizedBlockNumber: "5",
      checkpointTimestamp: "1001", releaseBindingDigest: digest("6"), authorizationDigest: digest("7"),
      deploymentConfigHash: hash("8") };
    const control={current_epoch:"1",current_acceptance:"1",next_epoch:"2",next_acceptance:"2",updated_at:current.accepted_at};
    expect(decideIndexerCheckpointEpoch(control,[current],currentAcceptance,next))
      .toEqual({ kind: "renew", epochId: "2",acceptanceId:"2" });
    expect(() => decideIndexerCheckpointEpoch(
      control,[current],currentAcceptance,
      { ...next, releaseBindingDigest: first.releaseBindingDigest },
    )).toThrow("requires new release, authorization, and deployment configuration");
  });

  it("rejects historical identity and historical chain replay", () => {
    const first = indexerCheckpointHighWaterCandidate(snapshot()); const old = epoch(first, "1");
    const currentCandidate = { ...first, releaseBindingDigest: digest("6"), authorizationDigest: digest("7"),
      deploymentConfigHash: hash("8"), finalizedBlockNumber: "101", checkpointTimestamp: "1001" };
    const current = epoch(currentCandidate, "2");
    const currentAcceptance=acceptance(currentCandidate,"2","2");
    const control = {current_epoch:"2",current_acceptance:"2",next_epoch:"3",next_acceptance:"3",updated_at:current.accepted_at};
    expect(() => decideIndexerCheckpointEpoch(control,[old,current],currentAcceptance,{...first,checkpointTimestamp:"1002"}))
      .toThrow("historical identity replay");
    const oldChainNewRelease = { ...currentCandidate, releaseBindingDigest: digest("a"), authorizationDigest: digest("b"),
      deploymentConfigHash: hash("c"), chainId: "84532", chainName: "baseSepolia", checkpointTimestamp: "1002" };
    current.chain_id = "8453"; current.chain_name = "baseMainnet";
    expect(() => decideIndexerCheckpointEpoch(control,[old,current],currentAcceptance,oldChainNewRelease))
      .toThrow("historical chain identity replay");
  });

  it.each([
    ["same-height conflict", (value: ActivatedIndexerSnapshot) => { value.highWaterIdentity = { ...value.highWaterIdentity, checkpointDigest: digest("a") }; }, "same-height conflict"],
    ["lower block", (value: ActivatedIndexerSnapshot) => { (value.checkpoint.range as Record<string, unknown>).toBlock = 99; }, "finalized block regression"],
    ["timestamp regression", (value: ActivatedIndexerSnapshot) => { (value.checkpoint.range as Record<string, unknown>).toBlockTimestamp = 999; }, "timestamp regression"],
  ])("rejects %s", async (_label, mutate, message) => {
    const first=snapshot();const initial=indexerCheckpointHighWaterCandidate(first);database({epochs:[epoch(initial)],acceptances:[acceptance(initial)],currentEpoch:"1"});
    const contender = structuredClone(first); mutate(contender);
    await expect(enforceIndexerCheckpointHighWater(contender)).rejects.toThrow(message);
  });

  it("rolls back when RETURNING differs from every value requested", async () => {
    const db = database({ returningMismatch: true });
    await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow("persisted checkpoint epoch mismatch");
    expect(db.queries).toContain("ROLLBACK"); expect(db.queries).not.toContain("COMMIT");
  });

  it.each([
    ["table owner", { owns_epoch: true }], ["schema creator", { can_create: true }],
    ["trigger privilege", { can_trigger_control: true }], ["history update", { can_update_epoch: true }],
    ["non-internal trigger", { external_triggers: true }],
  ])("rejects a runtime role with %s authority", async (_label, privilege) => {
    const db = database({ privilege });
    await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow("not least-privilege");
    expect(db.queries).toContain("ROLLBACK");
    expect(db.queries.some((query) => query.endsWith("FOR UPDATE"))).toBe(false);
  });

  it("fails closed when PostgreSQL is unavailable", async () => {
    setPortalDatabasePoolForTests({ connect: async () => { throw new Error("database unavailable"); }, query: async () => result([]) });
    await expect(enforceIndexerCheckpointHighWater(snapshot())).rejects.toThrow("database unavailable");
  });
});
