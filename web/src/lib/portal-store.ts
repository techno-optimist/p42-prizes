import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
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
}

export interface IdempotencyRecord {
  key: string;
  route: string;
  requestHash: string;
  status: number;
  response: unknown;
  createdAt: string;
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
}

const EMPTY_STATE: PortalStateSnapshot = {
  schemaVersion: 1,
  commits: [],
  submissions: [],
  idempotency: [],
  events: [],
};

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

export function readPortalState(): PortalStateSnapshot {
  const filePath = portalStatePath();
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

export function writePortalState(state: PortalStateSnapshot): void {
  const filePath = portalStatePath();
  mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tempPath, `${JSON.stringify(cloneState(state), null, 2)}\n`, "utf8");
  renameSync(tempPath, filePath);
}

export function updatePortalState(mutator: (state: PortalStateSnapshot) => void): PortalStateSnapshot {
  const state = readPortalState();
  mutator(state);
  writePortalState(state);
  return state;
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

export function resetPortalStateForTests(): void {
  rmSync(portalStatePath(), { force: true });
}
