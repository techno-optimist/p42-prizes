import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { idempotencyKey, requestHash } from "@/lib/idempotency";
import { resetPortalStateForTests } from "@/lib/portal-store";

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
});
