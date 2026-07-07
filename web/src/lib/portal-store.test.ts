import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  appendPortalEvent,
  portalStatePath,
  readPortalState,
  resetPortalStateForTests,
  updatePortalState,
  writePortalState,
} from "@/lib/portal-store";

let stateDir: string;

describe("portal-store local durability guardrails", () => {
  beforeEach(() => {
    stateDir = mkdtempSync(path.join(tmpdir(), "p42-store-state-"));
    process.env.P42_PORTAL_STATE_PATH = path.join(stateDir, "state.json");
    resetPortalStateForTests();
  });

  afterEach(() => {
    resetPortalStateForTests();
    delete process.env.P42_PORTAL_STATE_PATH;
    delete process.env.P42_PORTAL_STATE_LOCK_TIMEOUT_MS;
    delete process.env.P42_PORTAL_STATE_STALE_LOCK_MS;
    rmSync(stateDir, { recursive: true, force: true });
  });

  it("serializes local read-mutate-write updates through the shared store path", () => {
    updatePortalState((state) => {
      appendPortalEvent(state, {
        type: "verification.completed",
        subjectId: "sha256:first",
        payload: { index: 1 },
      });
    });
    updatePortalState((state) => {
      appendPortalEvent(state, {
        type: "verification.completed",
        subjectId: "sha256:second",
        payload: { index: 2 },
      });
    });

    expect(readPortalState().events).toMatchObject([
      { sequence: 1, subjectId: "sha256:first", prevHash: "genesis" },
      { sequence: 2, subjectId: "sha256:second" },
    ]);
    expect(readPortalState().events[1].prevHash).toBe(readPortalState().events[0].eventHash);
  });

  it("fails closed when another local writer holds the state lock", () => {
    process.env.P42_PORTAL_STATE_LOCK_TIMEOUT_MS = "50";
    process.env.P42_PORTAL_STATE_STALE_LOCK_MS = "60000";
    const lockPath = `${portalStatePath()}.lock`;
    mkdirSync(lockPath, { recursive: true });
    writeFileSync(
      path.join(lockPath, "owner.json"),
      `${JSON.stringify({ pid: 999999, createdAt: new Date().toISOString() })}\n`,
      "utf8",
    );

    expect(() => updatePortalState(() => undefined)).toThrow("portal state lock acquisition timed out");
  });

  it("recovers from stale local lock directories", () => {
    process.env.P42_PORTAL_STATE_LOCK_TIMEOUT_MS = "200";
    process.env.P42_PORTAL_STATE_STALE_LOCK_MS = "1";
    const lockPath = `${portalStatePath()}.lock`;
    mkdirSync(lockPath, { recursive: true });
    writeFileSync(
      path.join(lockPath, "owner.json"),
      `${JSON.stringify({ pid: 999999, createdAt: "2000-01-01T00:00:00.000Z" })}\n`,
      "utf8",
    );

    updatePortalState((state) => {
      appendPortalEvent(state, {
        type: "verification.completed",
        subjectId: "sha256:after-stale-lock",
        payload: {},
      });
    });

    expect(readPortalState().events[0]).toMatchObject({ subjectId: "sha256:after-stale-lock" });
  });

  it("writes through temp file plus rename without leaving local temp files behind", () => {
    writePortalState({
      schemaVersion: 1,
      commits: [],
      submissions: [],
      idempotency: [],
      events: [],
    });

    expect(readdirSync(stateDir).filter((name) => name.includes(".tmp"))).toEqual([]);
    expect(readPortalState()).toMatchObject({ schemaVersion: 1, commits: [], events: [] });
  });
});
