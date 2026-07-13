import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { ApiError } from "@/lib/api";
import { portalDatabaseConfigured, portalDatabasePool, portalDatabaseTimeouts } from "@/lib/portal-db";
import { withPortalStateFileLock } from "@/lib/portal-lock";
import type { Submission } from "@/lib/types";

const DEFAULT_LOCK_TIMEOUT_MS = 5_000;
const DEFAULT_STATE_MAX_BYTES = 16 * 1024 * 1024;
const DEFAULT_COMMIT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_REVEAL_LEASE_MS = 2 * 60 * 1000;
const DEFAULT_IDEMPOTENCY_LEASE_MS = 2 * 60 * 1000;
const DEFAULT_TERMINAL_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_IDEMPOTENCY_RETENTION_MS = 24 * 60 * 60 * 1000;

export interface PortalLease {
  id: string;
  expiresAt: string;
}

export interface CommitRecord {
  id: string;
  problemId: number;
  agentName: string;
  solverAddress: string;
  solutionCid: string;
  commitHash: string;
  commitAlgorithm: "keccak256-p42-local-v0";
  createdAt: string;
  expiresAt: string;
  revealed: boolean;
  abandonedAt?: string;
  revealLease?: PortalLease;
}

export interface IdempotencyRecord {
  key: string;
  route: string;
  requestHash: string;
  state: "pending" | "completed";
  status?: number;
  response?: unknown;
  createdAt: string;
  reservationId?: string;
  leaseExpiresAt?: string;
}

export type PortalEventType =
  | "commit.created"
  | "submission.revealed"
  | "submission.rejected"
  | "verification.completed"
  | "idempotency.stored"
  | "idempotency.replayed"
  | "idempotency.conflict";

export interface PortalEventRecord {
  id: string;
  sequence: number;
  type: PortalEventType;
  createdAt: string;
  subjectId: string;
  problemId?: number;
  actor?: string;
  payload: unknown;
  prevHash: string;
  eventHash: string;
}

export interface PortalStateSnapshot {
  schemaVersion: 1;
  commits: CommitRecord[];
  submissions: Submission[];
  idempotency: IdempotencyRecord[];
  events: PortalEventRecord[];
  eventOffset: number;
  eventAnchorHash: string;
}

const EMPTY_STATE: PortalStateSnapshot = {
  schemaVersion: 1,
  commits: [],
  submissions: [],
  idempotency: [],
  events: [],
  eventOffset: 0,
  eventAnchorHash: "genesis",
};

function envInteger(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

export function portalStateLimits() {
  return {
    maxBytes: envInteger("P42_PORTAL_STATE_MAX_BYTES", DEFAULT_STATE_MAX_BYTES, 1024, 64 * 1024 * 1024),
    maxCommits: envInteger("P42_PORTAL_MAX_COMMITS", 1_000, 10, 5_000),
    maxSubmissions: envInteger("P42_PORTAL_MAX_SUBMISSIONS", 1_000, 10, 5_000),
    maxIdempotency: envInteger("P42_PORTAL_MAX_IDEMPOTENCY", 1_000, 10, 5_000),
    maxEvents: envInteger("P42_PORTAL_MAX_EVENTS", 2_000, 10, 10_000),
  };
}

export function portalLifecyclePolicy() {
  return {
    commitTtlMs: envInteger("P42_COMMIT_TTL_MS", DEFAULT_COMMIT_TTL_MS, 60_000, 7 * 24 * 60 * 60 * 1000),
    revealLeaseMs: envInteger("P42_REVEAL_LEASE_MS", DEFAULT_REVEAL_LEASE_MS, 10_000, 10 * 60 * 1000),
    idempotencyLeaseMs: envInteger(
      "P42_IDEMPOTENCY_LEASE_MS",
      DEFAULT_IDEMPOTENCY_LEASE_MS,
      10_000,
      10 * 60 * 1000,
    ),
    terminalRetentionMs: envInteger(
      "P42_TERMINAL_RETENTION_MS",
      DEFAULT_TERMINAL_RETENTION_MS,
      60_000,
      30 * 24 * 60 * 60 * 1000,
    ),
    idempotencyRetentionMs: envInteger(
      "P42_IDEMPOTENCY_RETENTION_MS",
      DEFAULT_IDEMPOTENCY_RETENTION_MS,
      60_000,
      30 * 24 * 60 * 60 * 1000,
    ),
  };
}

export function portalStatePath(): string {
  if (process.env.P42_PORTAL_STATE_PATH) {
    return process.env.P42_PORTAL_STATE_PATH;
  }
  return path.join(/*turbopackIgnore: true*/ process.cwd(), "data", "portal-state.json");
}

function cloneState(state: PortalStateSnapshot): PortalStateSnapshot {
  return {
    schemaVersion: 1,
    commits: state.commits.map((commit) => ({
      ...commit,
      ...(commit.revealLease ? { revealLease: { ...commit.revealLease } } : {}),
    })),
    submissions: state.submissions.map((submission) => ({ ...submission })),
    idempotency: state.idempotency.map((record) => ({ ...record })),
    events: state.events.map((event) => ({ ...event })),
    eventOffset: state.eventOffset,
    eventAnchorHash: state.eventAnchorHash,
  };
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function portalEventHash(event: Omit<PortalEventRecord, "eventHash">): string {
  return `sha256:${createHash("sha256").update(canonicalJson(event), "utf8").digest("hex")}`;
}

function validatePortalEventChain(
  events: PortalEventRecord[],
  eventOffset: number,
  anchorHash: string,
): void {
  let priorHash = anchorHash;
  for (const [index, event] of events.entries()) {
    if (!event || typeof event !== "object" || Array.isArray(event)) {
      throw new Error("portal event chain contains an invalid record");
    }
    const { eventHash, ...withoutHash } = event;
    if (event.sequence !== eventOffset + index + 1) {
      throw new Error("portal event chain sequence mismatch");
    }
    if (event.prevHash !== priorHash) throw new Error("portal event chain predecessor mismatch");
    if (!/^sha256:[a-f0-9]{64}$/.test(eventHash) || eventHash !== portalEventHash(withoutHash)) {
      throw new Error("portal event chain hash mismatch");
    }
    priorHash = eventHash;
  }
}

export function readPortalState(): PortalStateSnapshot {
  const filePath = portalStatePath();
  if (!existsSync(filePath)) return cloneState(EMPTY_STATE);
  const fileSize = statSync(filePath).size;
  if (fileSize > portalStateLimits().maxBytes) {
    throw new Error(`portal state file exceeds configured size limit: ${filePath}`);
  }
  const parsed = JSON.parse(readFileSync(filePath, "utf8")) as Partial<PortalStateSnapshot>;
  return normalizePortalState(parsed, `file ${filePath}`);
}

function normalizePortalState(
  parsed: Partial<PortalStateSnapshot>,
  source: string,
  canonicalRequired = false,
): PortalStateSnapshot {
  if (parsed.schemaVersion !== 1 || !Array.isArray(parsed.commits) || !Array.isArray(parsed.submissions)) {
    throw new Error(`unsupported portal state: ${source}`);
  }
  const limits = portalStateLimits();
  const idempotency = Array.isArray(parsed.idempotency) ? parsed.idempotency : [];
  if (
    parsed.commits.length > limits.maxCommits
    || parsed.submissions.length > limits.maxSubmissions
    || idempotency.length > limits.maxIdempotency
  ) {
    throw new Error(`portal state collection exceeds configured capacity: ${source}`);
  }
  const parsedEvents = Array.isArray(parsed.events) ? parsed.events as PortalEventRecord[] : [];
  const parsedEventOffset = Number.isInteger(parsed.eventOffset) && Number(parsed.eventOffset) >= 0
    ? Number(parsed.eventOffset)
    : 0;
  const parsedAnchorHash = typeof parsed.eventAnchorHash === "string"
    ? parsed.eventAnchorHash
    : "genesis";
  if ((parsedEventOffset === 0 && parsedAnchorHash !== "genesis")
    || (parsedEventOffset > 0 && !/^sha256:[a-f0-9]{64}$/.test(parsedAnchorHash))) {
    throw new Error("portal event chain anchor mismatch");
  }
  validatePortalEventChain(parsedEvents, parsedEventOffset, parsedAnchorHash);
  const eventOverflow = Math.max(0, parsedEvents.length - limits.maxEvents);
  const retainedEvents = eventOverflow > 0 ? parsedEvents.slice(eventOverflow) : parsedEvents;
  const eventAnchorHash = eventOverflow > 0
    ? parsedEvents[eventOverflow - 1].eventHash
    : parsedAnchorHash;
  const normalized = cloneState({
    schemaVersion: 1,
    commits: (parsed.commits as Array<Partial<CommitRecord>>).map((commit) => {
      const createdAt = String(commit.createdAt);
      return {
        ...commit,
        commitAlgorithm: "keccak256-p42-local-v0",
        expiresAt: commit.expiresAt ?? new Date(Date.parse(createdAt) + portalLifecyclePolicy().commitTtlMs).toISOString(),
      } as CommitRecord;
    }),
    submissions: (parsed.submissions as Submission[]).map((submission) => {
      const source = submission.source ?? "local-phase-0";
      if (source === "local-phase-0") {
        const priorImprovement = submission.provisionalImprovement ?? submission.improvement;
        const localState = submission.state === "finalized" ? "revealed" : submission.state;
        return {
          ...submission,
          source,
          state: localState,
          settlementState: localState === "rejected" ? "ineligible" : "unsettled",
          improvement: "0/1",
          provisionalImprovement: priorImprovement,
          credit: "0/1",
          payoutEth: "0.000",
        };
      }
      return {
        ...submission,
        source,
        settlementState: submission.state === "finalized" ? "finalized" : "unsettled",
      };
    }),
    idempotency: idempotency.length > 0
      ? (idempotency as Array<Partial<IdempotencyRecord>>).map((record) => ({
          ...record,
          state: record.state ?? "completed",
        } as IdempotencyRecord))
      : [],
    events: retainedEvents,
    eventOffset: parsedEventOffset + eventOverflow,
    eventAnchorHash,
  });
  if (canonicalRequired && canonicalJson(normalized) !== canonicalJson(parsed)) {
    throw new Error(`portal database state is not in canonical runtime form: ${source}`);
  }
  return normalized;
}

export async function readPortalStateShared(): Promise<PortalStateSnapshot> {
  if (!portalDatabaseConfigured()) return readPortalState();
  const result = await portalDatabasePool().query<{ state: Partial<PortalStateSnapshot> }>(
    "SELECT state FROM p42_portal_state WHERE singleton = true",
  );
  if (result.rowCount !== 1) {
    throw new Error("portal database is not initialized; run npm run db:migrate and import portal state");
  }
  return normalizePortalState(result.rows[0].state, "PostgreSQL singleton row", true);
}

function validTimestamp(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

export function commitIsExpired(commit: CommitRecord, now = Date.now()): boolean {
  const expiresAt = validTimestamp(commit.expiresAt);
  return commit.abandonedAt !== undefined || expiresAt === undefined || expiresAt <= now;
}

export function leaseIsActive(lease: PortalLease | undefined, now = Date.now()): boolean {
  const expiresAt = validTimestamp(lease?.expiresAt);
  return expiresAt !== undefined && expiresAt > now;
}

function maintainPortalState(state: PortalStateSnapshot, now = Date.now()): void {
  const policy = portalLifecyclePolicy();
  const limits = portalStateLimits();
  const nowIso = new Date(now).toISOString();

  for (const commit of state.commits) {
    if (!commit.expiresAt) {
      commit.expiresAt = new Date(Date.parse(commit.createdAt) + policy.commitTtlMs).toISOString();
    }
    if (commit.revealLease && !leaseIsActive(commit.revealLease, now)) delete commit.revealLease;
    if (!commit.revealed && !commit.abandonedAt && !commit.revealLease && commitIsExpired(commit, now)) {
      commit.abandonedAt = nowIso;
    }
  }

  state.commits = state.commits.filter((commit) => {
    const terminalAt = commit.abandonedAt ?? (commit.revealed ? commit.createdAt : undefined);
    const terminalMs = validTimestamp(terminalAt);
    return terminalMs === undefined || now - terminalMs <= policy.terminalRetentionMs;
  });
  state.submissions = state.submissions.filter((submission) => {
    if (submission.source === "chain-p42-v1") return true;
    const submittedAt = validTimestamp(submission.submittedAt);
    return submittedAt === undefined || now - submittedAt <= policy.terminalRetentionMs;
  });
  state.idempotency = state.idempotency.filter((record) => {
    if (record.state === "pending") {
      const leaseExpiresAt = validTimestamp(record.leaseExpiresAt);
      return leaseExpiresAt !== undefined && leaseExpiresAt > now;
    }
    const createdAt = validTimestamp(record.createdAt);
    return createdAt === undefined || now - createdAt <= policy.idempotencyRetentionMs;
  });

  if (state.events.length > limits.maxEvents) {
    const removed = state.events.splice(0, state.events.length - limits.maxEvents);
    state.eventOffset += removed.length;
    state.eventAnchorHash = removed.at(-1)?.eventHash ?? state.eventAnchorHash;
  }
}

export function assertPortalCapacity(
  state: PortalStateSnapshot,
  collection: "commits" | "submissions" | "idempotency",
): void {
  const limits = portalStateLimits();
  const maximum = collection === "commits"
    ? limits.maxCommits
    : collection === "submissions"
      ? limits.maxSubmissions
      : limits.maxIdempotency;
  if (state[collection].length >= maximum) {
    throw new ApiError(`portal ${collection} capacity reached`, 503);
  }
}

function fsyncPath(filePath: string): void {
  const fd = openSync(filePath, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function fsyncDirectory(dirPath: string): void {
  try {
    fsyncPath(dirPath);
  } catch {
    // Some local/dev filesystems refuse to open directories; the atomic rename
    // still protects readers, but production needs a real datastore.
  }
}

export function writePortalState(state: PortalStateSnapshot): void {
  const filePath = portalStatePath();
  mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.${randomUUID()}.tmp`;
  maintainPortalState(state);
  const serialized = `${JSON.stringify(cloneState(state), null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > portalStateLimits().maxBytes) {
    throw new Error("portal state write exceeds configured size limit");
  }
  writeFileSync(tempPath, serialized, "utf8");
  fsyncPath(tempPath);
  renameSync(tempPath, filePath);
  fsyncDirectory(path.dirname(filePath));
}

// A cross-process advisory lock (atomic mkdir) so the read-modify-write in
// updatePortalState is serialized: without it, two settlements can both read the
// same frontier, credit the same delta, and race their writes. This is a local
// stopgap — multi-instance production still needs a transactional datastore
// (see docs/GATE_LEDGER.md, "Additional Known-Open Operational Blockers").
function withPortalStateLock<T>(operation: () => T): T {
  const filePath = portalStatePath();
  const lockPath = `${filePath}.lock`;
  const lockTimeoutMs = Number(process.env.P42_PORTAL_STATE_LOCK_TIMEOUT_MS ?? DEFAULT_LOCK_TIMEOUT_MS);
  mkdirSync(path.dirname(filePath), { recursive: true });
  return withPortalStateFileLock(lockPath, () => {
    return operation();
  }, { timeoutMs: lockTimeoutMs });
}

export function updatePortalState(mutator: (state: PortalStateSnapshot) => void): PortalStateSnapshot {
  return withPortalStateLock(() => {
    const state = readPortalState();
    maintainPortalState(state);
    mutator(state);
    writePortalState(state);
    return state;
  });
}

export async function updatePortalStateShared(
  mutator: (state: PortalStateSnapshot) => void,
): Promise<PortalStateSnapshot> {
  if (!portalDatabaseConfigured()) return updatePortalState(mutator);

  const client = await portalDatabasePool().connect();
  const timeouts = portalDatabaseTimeouts();
  try {
    await client.query("BEGIN");
    await client.query(`SET LOCAL lock_timeout = '${timeouts.lockMs}ms'`);
    await client.query(`SET LOCAL statement_timeout = '${timeouts.statementMs}ms'`);
    const result = await client.query<{ state: Partial<PortalStateSnapshot> }>(
      "SELECT state FROM p42_portal_state WHERE singleton = true FOR UPDATE",
    );
    if (result.rowCount !== 1) {
      throw new Error("portal database is not initialized; run npm run db:migrate and import portal state");
    }
    const state = normalizePortalState(result.rows[0].state, "PostgreSQL singleton row", true);
    maintainPortalState(state);
    mutator(state);
    maintainPortalState(state);
    const serialized = JSON.stringify(cloneState(state));
    if (Buffer.byteLength(serialized, "utf8") > portalStateLimits().maxBytes) {
      throw new Error("portal database state exceeds configured size limit");
    }
    await client.query(
      `UPDATE p42_portal_state
         SET state = $1::jsonb, revision = revision + 1, updated_at = clock_timestamp()
       WHERE singleton = true`,
      [serialized],
    );
    await client.query("COMMIT");
    return state;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // Preserve the original transaction error.
    }
    throw error;
  } finally {
    client.release();
  }
}

export function appendPortalEvent(
  state: PortalStateSnapshot,
  input: {
    type: PortalEventType;
    subjectId: string;
    problemId?: number;
    actor?: string;
    payload: unknown;
  },
): PortalEventRecord {
  const prior = state.events.at(-1);
  const eventWithoutHash: Omit<PortalEventRecord, "eventHash"> = {
    id: `evt_${randomUUID().slice(0, 10)}`,
    sequence: prior ? prior.sequence + 1 : state.eventOffset + 1,
    type: input.type,
    createdAt: new Date().toISOString(),
    subjectId: input.subjectId,
    ...(input.problemId === undefined ? {} : { problemId: input.problemId }),
    ...(input.actor ? { actor: input.actor } : {}),
    payload: input.payload,
    prevHash: prior?.eventHash ?? state.eventAnchorHash,
  };
  const event = {
    ...eventWithoutHash,
    eventHash: portalEventHash(eventWithoutHash),
  };
  state.events.push(event);
  return event;
}

export function resetPortalStateForTests(): void {
  rmSync(portalStatePath(), { force: true });
  rmSync(`${portalStatePath()}.lock`, { recursive: true, force: true });
}
