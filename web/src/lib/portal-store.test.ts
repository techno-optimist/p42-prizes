import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  appendPortalEvent,
  portalStatePath,
  readPortalState,
  resetPortalStateForTests,
  updatePortalState,
} from "@/lib/portal-store";

let stateDir: string;

function waitForExit(child: ChildProcess): Promise<{ code: number | null; stderr: string }> {
  let stderr = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk) => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve({ code, stderr }));
  });
}

describe("bounded portal state", () => {
  beforeEach(() => {
    stateDir = mkdtempSync(path.join(tmpdir(), "p42-store-state-"));
    process.env.P42_PORTAL_STATE_PATH = path.join(stateDir, "state.json");
    resetPortalStateForTests();
  });

  afterEach(() => {
    resetPortalStateForTests();
    delete process.env.P42_PORTAL_STATE_PATH;
    delete process.env.P42_PORTAL_MAX_EVENTS;
    delete process.env.P42_PORTAL_STATE_MAX_BYTES;
    rmSync(stateDir, { recursive: true, force: true });
  });

  it("retains a bounded hash-chain tail with an explicit anchor", () => {
    process.env.P42_PORTAL_MAX_EVENTS = "10";
    for (let index = 1; index <= 15; index += 1) {
      updatePortalState((state) => {
        appendPortalEvent(state, {
          type: "verification.completed",
          subjectId: `event-${index}`,
          payload: { index },
        });
      });
    }

    const state = readPortalState();
    expect(state.events).toHaveLength(10);
    expect(state.eventOffset).toBe(5);
    expect(state.events[0]).toMatchObject({ sequence: 6, prevHash: state.eventAnchorHash });
    expect(state.events.at(-1)?.sequence).toBe(15);
  });

  it("rejects oversized state before parsing or replacing the durable snapshot", () => {
    process.env.P42_PORTAL_STATE_MAX_BYTES = "1024";
    expect(() => updatePortalState((state) => {
      appendPortalEvent(state, {
        type: "verification.completed",
        subjectId: "too-large",
        payload: { body: "x".repeat(2_000) },
      });
    })).toThrow("portal state write exceeds configured size limit");
    expect(readPortalState().events).toEqual([]);

    writeFileSync(portalStatePath(), "x".repeat(1_025), "utf8");
    expect(() => readPortalState()).toThrow("portal state file exceeds configured size limit");
  });

  it("downgrades legacy local finality to zero-credit unsettled evidence", () => {
    writeFileSync(portalStatePath(), JSON.stringify({
      schemaVersion: 1,
      commits: [],
      submissions: [{
        id: "legacy-local",
        problemId: 1,
        problemSlug: "hadamard-mini",
        agentName: "LegacyAgent",
        state: "finalized",
        score: "0/1",
        improvement: "1/1",
        credit: "1/1",
        payoutEth: "1.000",
        solutionCid: "sha256:legacy",
        commitHash: `0x${"1".repeat(64)}`,
        submittedAt: "2026-07-01T00:00:00.000Z",
        windowEndsAt: "2026-07-04T00:00:00.000Z",
        transcriptCid: null,
      }],
      idempotency: [],
      events: [],
    }), "utf8");

    expect(readPortalState().submissions[0]).toMatchObject({
      source: "local-phase-0",
      state: "revealed",
      settlementState: "unsettled",
      improvement: "0/1",
      provisionalImprovement: "1/1",
      credit: "0/1",
      payoutEth: "0.000",
    });
  });

  it("retains concurrent multi-process updates in one valid hash chain", async () => {
    const worker = path.resolve("test-support/portal-store-worker.ts");
    const viteNode = path.resolve("node_modules/.bin/vite-node");
    const children = ["alpha", "beta"].map((prefix) => spawn(
      viteNode,
      ["--script", worker, portalStatePath(), prefix, "25"],
      { cwd: path.resolve("."), stdio: ["ignore", "ignore", "pipe"] },
    ));
    const results = await Promise.all(children.map(waitForExit));
    expect(results).toEqual([{ code: 0, stderr: "" }, { code: 0, stderr: "" }]);

    const state = readPortalState();
    expect(state.events).toHaveLength(50);
    expect(new Set(state.events.map((event) => event.subjectId)).size).toBe(50);
    expect(state.events.map((event) => event.sequence)).toEqual(
      Array.from({ length: 50 }, (_, index) => index + 1),
    );
    for (const [index, event] of state.events.entries()) {
      expect(event.prevHash).toBe(index === 0 ? "genesis" : state.events[index - 1].eventHash);
    }
  });

  it("rejects a persisted event fork or payload mutation", () => {
    updatePortalState((state) => {
      appendPortalEvent(state, {
        type: "verification.completed",
        subjectId: "trusted-event",
        payload: { valid: true },
      });
    });
    const raw = JSON.parse(readFileSync(portalStatePath(), "utf8")) as {
      events: Array<{ payload: unknown; prevHash: string }>;
    };
    raw.events[0].payload = { valid: false };
    writeFileSync(portalStatePath(), `${JSON.stringify(raw)}\n`, "utf8");
    expect(() => readPortalState()).toThrow("portal event chain hash mismatch");

    raw.events[0].prevHash = "sha256:" + "0".repeat(64);
    writeFileSync(portalStatePath(), `${JSON.stringify(raw)}\n`, "utf8");
    expect(() => readPortalState()).toThrow("portal event chain predecessor mismatch");
  });

  it("rejects an anchor inconsistent with the retained event offset", () => {
    writeFileSync(portalStatePath(), `${JSON.stringify({
      schemaVersion: 1,
      commits: [],
      submissions: [],
      idempotency: [],
      events: [],
      eventOffset: 0,
      eventAnchorHash: `sha256:${"1".repeat(64)}`,
    })}\n`, "utf8");
    expect(() => readPortalState()).toThrow("portal event chain anchor mismatch");
  });
});
