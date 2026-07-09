import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  beginIdempotentRequest,
  completeIdempotentOperation,
  idempotencyKey,
  releaseIdempotencyReservation,
  requestHash,
} from "@/lib/idempotency";
import { appendPortalEvent, readPortalState, resetPortalStateForTests, updatePortalState } from "@/lib/portal-store";

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
    delete process.env.P42_IDEMPOTENCY_LEASE_MS;
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

  it("reserves before work, blocks a concurrent owner, and atomically completes with the mutation", async () => {
    const request = new Request("http://localhost/api/solutions", {
      headers: { "Idempotency-Key": "atomic-request-1" },
    });
    const payload = { problem_id: 1, solution_raw: "{}" };
    const first = beginIdempotentRequest(request, "solutions.verify", payload);
    expect(first.reservation).toBeDefined();
    expect(() => beginIdempotentRequest(request, "solutions.verify", payload)).toThrow(
      "an idempotent request with this key is already in progress",
    );

    const completed = completeIdempotentOperation(first.reservation, 201, (state) => {
      appendPortalEvent(state, {
        type: "verification.completed",
        subjectId: "sha256:test",
        payload: { valid: true },
      });
      return { accepted: true };
    });
    expect(completed.headers).toMatchObject({ "Idempotency-Status": "stored" });

    const replay = beginIdempotentRequest(request, "solutions.verify", payload).replay;
    expect(replay?.status).toBe(201);
    await expect(replay?.json()).resolves.toEqual({ accepted: true });
    expect(readPortalState().events.map((event) => event.type)).toEqual([
      "verification.completed",
      "idempotency.stored",
      "idempotency.replayed",
    ]);
  });

  it("reclaims an expired reservation and does not persist a failed operation", () => {
    const request = new Request("http://localhost/api/solutions", {
      headers: { "Idempotency-Key": "recover-request-1" },
    });
    const payload = { problem_id: 1 };
    const first = beginIdempotentRequest(request, "solutions.verify", payload).reservation;
    expect(first).toBeDefined();

    updatePortalState((state) => {
      const record = state.idempotency[0];
      record.leaseExpiresAt = new Date(Date.now() - 1_000).toISOString();
    });
    const recovered = beginIdempotentRequest(request, "solutions.verify", payload).reservation;
    expect(recovered?.reservationId).not.toBe(first?.reservationId);

    expect(() => completeIdempotentOperation(recovered, 201, (state) => {
      appendPortalEvent(state, {
        type: "verification.completed",
        subjectId: "never-committed",
        payload: {},
      });
      throw new Error("operation failed");
    })).toThrow("operation failed");
    expect(readPortalState().events).toEqual([]);
    expect(readPortalState().idempotency[0]).toMatchObject({ state: "pending" });

    releaseIdempotencyReservation(recovered);
    expect(readPortalState().idempotency).toEqual([]);
  });
});
