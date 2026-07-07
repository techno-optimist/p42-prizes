import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  cancelIdempotentReservation,
  idempotencyKey,
  rememberIdempotentResponse,
  replayIdempotentResponse,
  requestHash,
  reserveIdempotentRequest,
} from "@/lib/idempotency";
import { readPortalState, resetPortalStateForTests } from "@/lib/portal-store";

let stateDir: string;

describe("idempotency", () => {
  beforeEach(() => {
    stateDir = mkdtempSync(path.join(tmpdir(), "p42-idempotency-state-"));
    process.env.P42_PORTAL_STATE_PATH = path.join(stateDir, "state.json");
    resetPortalStateForTests();
  });

  afterEach(() => {
    resetPortalStateForTests();
    delete process.env.P42_PORTAL_STATE_PATH;
    rmSync(stateDir, { recursive: true, force: true });
  });

  it("hashes semantically identical JSON objects independent of field order", () => {
    expect(requestHash({ b: 2, a: 1, nested: { z: true, m: "x" } })).toBe(
      requestHash({ nested: { m: "x", z: true }, a: 1, b: 2 }),
    );
  });

  it("validates idempotency key syntax", () => {
    const valid = new Request("http://localhost/api/solutions", {
      headers: { "Idempotency-Key": "solver:commit-001" },
    });
    expect(idempotencyKey(valid)).toBe("solver:commit-001");

    const invalid = new Request("http://localhost/api/solutions", {
      headers: { "Idempotency-Key": "bad key" },
    });
    expect(() => idempotencyKey(invalid)).toThrow("Idempotency-Key must be 8-128 chars");
  });

  it("reserves a pending request before the side effect runs", () => {
    const req = new Request("http://localhost/api/submissions/commit", {
      headers: { "Idempotency-Key": "commit-retry-1" },
    });
    const body = { problem_id: 1, solution_cid: "cid" };

    expect(reserveIdempotentRequest(req, "submissions.commit", body)).toBeUndefined();
    expect(readPortalState().idempotency).toMatchObject([
      {
        key: "commit-retry-1",
        route: "submissions.commit",
        requestHash: requestHash(body),
        state: "pending",
        status: 0,
        response: null,
      },
    ]);
    expect(readPortalState().events.map((event) => event.type)).toEqual(["idempotency.reserved"]);
    expect(() => reserveIdempotentRequest(req, "submissions.commit", body)).toThrow(
      "Idempotency-Key request is already in progress",
    );
    expect(readPortalState().events.map((event) => event.type)).toEqual(["idempotency.reserved"]);
  });

  it("records key reuse conflicts during reservation", () => {
    const req = new Request("http://localhost/api/submissions/commit", {
      headers: { "Idempotency-Key": "commit-retry-2" },
    });
    reserveIdempotentRequest(req, "submissions.commit", { problem_id: 1 });

    expect(() => reserveIdempotentRequest(req, "submissions.commit", { problem_id: 2 })).toThrow(
      "Idempotency-Key was already used for a different request body",
    );
    expect(readPortalState().events.map((event) => event.type)).toEqual([
      "idempotency.reserved",
      "idempotency.conflict",
    ]);
  });

  it("cancels a pre-effect reservation without allowing changed-body reuse", () => {
    const req = new Request("http://localhost/api/solutions", {
      headers: { "Idempotency-Key": "verify-retry-1" },
    });
    const body = { problem_id: 1, solution_raw: "{}" };
    reserveIdempotentRequest(req, "solutions.verify", body);

    cancelIdempotentReservation(req, "solutions.verify", body, "side-effect-not-committed");
    expect(replayIdempotentResponse(req, "solutions.verify", body)).toBeUndefined();
    expect(readPortalState().idempotency).toMatchObject([
      {
        key: "verify-retry-1",
        route: "solutions.verify",
        state: "cancelled",
        status: 0,
        response: null,
      },
    ]);
    expect(readPortalState().events.map((event) => event.type)).toEqual([
      "idempotency.reserved",
      "idempotency.cancelled",
    ]);

    expect(reserveIdempotentRequest(req, "solutions.verify", body)).toBeUndefined();
    expect(readPortalState().idempotency[0]).toMatchObject({
      state: "pending",
      status: 0,
      response: null,
    });

    expect(() => reserveIdempotentRequest(req, "solutions.verify", { ...body, solution_raw: "[]" })).toThrow(
      "Idempotency-Key was already used for a different request body",
    );
    expect(readPortalState().events.map((event) => event.type)).toEqual([
      "idempotency.reserved",
      "idempotency.cancelled",
      "idempotency.reserved",
      "idempotency.conflict",
    ]);
  });

  it("completes a reservation and replays the stored response", async () => {
    const req = new Request("http://localhost/api/submissions/reveal", {
      headers: { "Idempotency-Key": "reveal-retry-1" },
    });
    const body = { commit_id: "commit_1" };
    reserveIdempotentRequest(req, "submissions.reveal", body);

    const headers = rememberIdempotentResponse(
      req,
      "submissions.reveal",
      body,
      { submission: { id: "sub_1" } },
      422,
    );
    expect(headers).toMatchObject({
      "Idempotency-Status": "stored",
      "Idempotency-Key": "reveal-retry-1",
    });

    expect(readPortalState().idempotency).toMatchObject([
      {
        key: "reveal-retry-1",
        route: "submissions.reveal",
        state: "completed",
        status: 422,
        response: { submission: { id: "sub_1" } },
      },
    ]);
    expect(readPortalState().events.map((event) => event.type)).toEqual([
      "idempotency.reserved",
      "idempotency.stored",
    ]);

    const replay = replayIdempotentResponse(req, "submissions.reveal", body);
    expect(replay?.status).toBe(422);
    expect(replay?.headers.get("Idempotency-Status")).toBe("replayed");
    await expect(replay?.json()).resolves.toEqual({ submission: { id: "sub_1" } });
    expect(readPortalState().events.map((event) => event.type)).toEqual([
      "idempotency.reserved",
      "idempotency.stored",
      "idempotency.replayed",
    ]);
  });
});
