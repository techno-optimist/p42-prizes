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
  writeFileSync,
} from "node:fs";
import path from "node:path";
import type { Submission } from "@/lib/types";

export interface CommitRecord {
  id: string;
  problemId: number;
  agentName: string;
  solverAddress: string;
  solutionCid: string;
  commitHash: string;
  commitAlgorithm: "keccak256-p42-v0";
  createdAt: string;
  revealed: boolean;
  revealState?: "pending";
}

export interface IdempotencyRecord {
  key: string;
  route: string;
  requestHash: string;
  state?: "pending" | "completed" | "cancelled";
  status: number;
  response: unknown;
  createdAt: string;
  completedAt?: string;
  cancelledAt?: string;
}

export type PortalEventType =
  | "commit.created"
  | "submission.revealed"
  | "submission.rejected"
  | "verification.completed"
  | "idempotency.stored"
  | "idempotency.reserved"
  | "idempotency.cancelled"
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
}

export interface EventChainVerification {
  ok: boolean;
  latestHash: string;
  error?: string;
}

const EMPTY_STATE: PortalStateSnapshot = {
  schemaVersion: 1,
  commits: [],
  submissions: [],
  idempotency: [],
  events: [],
};
const LOCK_WAIT_MS = 25;
const DEFAULT_LOCK_TIMEOUT_MS = 2_000;
const DEFAULT_STALE_LOCK_MS = 30_000;

export function portalStatePath(): string {
  if (process.env.NODE_ENV === "test" && process.env.P42_PORTAL_STATE_PATH) {
    return process.env.P42_PORTAL_STATE_PATH;
  }
  return path.join(/*turbopackIgnore: true*/ process.cwd(), "data", "portal-state.json");
}

function cloneState(state: PortalStateSnapshot): PortalStateSnapshot {
  return {
    schemaVersion: 1,
    commits: state.commits.map((commit) => ({ ...commit })),
    submissions: state.submissions.map((submission) => ({ ...submission })),
    idempotency: state.idempotency.map((record) => ({ ...record })),
    events: state.events.map((event) => ({ ...event })),
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

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
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
    // Some local/dev filesystems do not allow opening directories; the atomic
    // rename still protects readers, but production needs a real datastore.
  }
}

function portalStateLockPath(filePath: string): string {
  return `${filePath}.lock`;
}

function readPortalStateUnlocked(filePath: string): PortalStateSnapshot {
  if (!existsSync(filePath)) return cloneState(EMPTY_STATE);
  const parsed = JSON.parse(readFileSync(filePath, "utf8")) as Partial<PortalStateSnapshot>;
  if (parsed.schemaVersion !== 1 || !Array.isArray(parsed.commits) || !Array.isArray(parsed.submissions)) {
    throw new Error(`unsupported portal state file: ${filePath}`);
  }
  return cloneState({
    schemaVersion: 1,
    commits: parsed.commits as CommitRecord[],
    submissions: parsed.submissions as Submission[],
    idempotency: Array.isArray(parsed.idempotency) ? parsed.idempotency as IdempotencyRecord[] : [],
    events: Array.isArray(parsed.events) ? parsed.events as PortalEventRecord[] : [],
  });
}

function writePortalStateUnlocked(filePath: string, state: PortalStateSnapshot): void {
  mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.${randomUUID()}.tmp`;
  writeFileSync(tempPath, `${JSON.stringify(cloneState(state), null, 2)}\n`, "utf8");
  fsyncPath(tempPath);
  renameSync(tempPath, filePath);
  fsyncDirectory(path.dirname(filePath));
}

function withPortalStateLock<T>(filePath: string, operation: () => T): T {
  const lockPath = portalStateLockPath(filePath);
  const lockTimeoutMs = Number(process.env.P42_PORTAL_STATE_LOCK_TIMEOUT_MS ?? DEFAULT_LOCK_TIMEOUT_MS);
  const staleLockMs = Number(process.env.P42_PORTAL_STATE_STALE_LOCK_MS ?? DEFAULT_STALE_LOCK_MS);
  const startedAt = Date.now();
  mkdirSync(path.dirname(filePath), { recursive: true });

  for (;;) {
    try {
      mkdirSync(lockPath);
      try {
        writeFileSync(
          path.join(lockPath, "owner.json"),
          `${JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() })}\n`,
          "utf8",
        );
        return operation();
      } finally {
        rmSync(lockPath, { recursive: true, force: true });
      }
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      if (code !== "EEXIST") throw error;

      try {
        const owner = JSON.parse(readFileSync(path.join(lockPath, "owner.json"), "utf8")) as { createdAt?: string };
        const createdAt = owner.createdAt ? Date.parse(owner.createdAt) : Number.NaN;
        if (Number.isFinite(createdAt) && Date.now() - createdAt > staleLockMs) {
          rmSync(lockPath, { recursive: true, force: true });
          continue;
        }
      } catch {
        if (Date.now() - startedAt > staleLockMs) {
          rmSync(lockPath, { recursive: true, force: true });
          continue;
        }
      }

      if (Date.now() - startedAt > lockTimeoutMs) {
        throw new Error("portal state lock acquisition timed out");
      }
      sleepSync(LOCK_WAIT_MS);
    }
  }
}

export function readPortalState(): PortalStateSnapshot {
  return readPortalStateUnlocked(portalStatePath());
}

export function writePortalState(state: PortalStateSnapshot): void {
  const filePath = portalStatePath();
  withPortalStateLock(filePath, () => writePortalStateUnlocked(filePath, state));
}

export function updatePortalState(mutator: (state: PortalStateSnapshot) => void): PortalStateSnapshot {
  const filePath = portalStatePath();
  return withPortalStateLock(filePath, () => {
    const state = readPortalStateUnlocked(filePath);
    mutator(state);
    writePortalStateUnlocked(filePath, state);
    return state;
  });
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
    sequence: prior ? prior.sequence + 1 : 1,
    type: input.type,
    createdAt: new Date().toISOString(),
    subjectId: input.subjectId,
    ...(input.problemId === undefined ? {} : { problemId: input.problemId }),
    ...(input.actor ? { actor: input.actor } : {}),
    payload: input.payload,
    prevHash: prior?.eventHash ?? "genesis",
  };
  const event = {
    ...eventWithoutHash,
    eventHash: portalEventHash(eventWithoutHash),
  };
  state.events.push(event);
  return event;
}

export function verifyEventChain(events: PortalEventRecord[]): EventChainVerification {
  let priorHash = "genesis";
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const expectedSequence = index + 1;
    if (event.sequence !== expectedSequence) {
      return {
        ok: false,
        latestHash: priorHash,
        error: `event ${event.id} has sequence ${event.sequence}; expected ${expectedSequence}`,
      };
    }
    if (event.prevHash !== priorHash) {
      return {
        ok: false,
        latestHash: priorHash,
        error: `event ${event.id} prevHash does not match prior event hash`,
      };
    }
    const { eventHash: _eventHash, ...eventWithoutHash } = event;
    const recomputed = portalEventHash(eventWithoutHash);
    if (event.eventHash !== recomputed) {
      return {
        ok: false,
        latestHash: priorHash,
        error: `event ${event.id} eventHash does not match its canonical payload`,
      };
    }
    priorHash = event.eventHash;
  }
  return { ok: true, latestHash: priorHash };
}

export function resetPortalStateForTests(): void {
  const filePath = portalStatePath();
  rmSync(filePath, { force: true });
  rmSync(portalStateLockPath(filePath), { recursive: true, force: true });
}
