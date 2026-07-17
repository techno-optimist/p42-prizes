import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { canonicalTopologyDescriptors } from "../../agent/canonical-topology.mjs";
import { validateAndReserveCanonicalDeployment } from "../scripts/canonical-deployment-reservation-gate.js";

function preflight(definitions) {
  return {
    definitions,
    startNonce: 12,
    addresses: Object.fromEntries(definitions.map(({ id }, index) => [id, `0x${String(index + 1).padStart(40, "0")}`])),
    steps: definitions.map((definition) => ({
      ...definition,
      expectedInitCode: "0x01",
      unsigned: { data: "0x02" },
    })),
  };
}

describe("canonical deployment reservation gate", () => {
  it("leaves no stale reservation on topology drift and accepts the corrected retry", async () => {
    const root = await mkdtemp(join(tmpdir(), "p42-canonical-reservation-"));
    try {
      const reservationPath = join(root, "p42-prizes.json.deployment-reservation.json");
      const definitions = canonicalTopologyDescriptors().map(({ id, name }) => ({ id, name }));
      let reservationCalls = 0;
      const reserve = async () => {
        reservationCalls += 1;
        await writeFile(reservationPath, "reserved\n", { flag: "wx" });
        return { path: reservationPath };
      };
      const common = {
        boardCount: 10,
        executableDefinitions: definitions,
        executablePreflight: preflight(definitions),
        setupOperations: Array.from({ length: 110 }, (_, sequence) => ({ sequence })),
        expectedOperationCount: 110,
        reserve,
      };

      const cases = [
        {
          name: "canonical topology drift",
          canonicalDefinitions: definitions.slice(0, -1),
          executableDefinitions: definitions,
          setupOperations: Array.from({ length: 110 }, (_, sequence) => ({ sequence })),
          expectedError: /canonical 47-contract topology/,
        },
        {
          name: "executable topology count drift",
          canonicalDefinitions: definitions,
          executableDefinitions: definitions.slice(0, -1),
          setupOperations: Array.from({ length: 110 }, (_, sequence) => ({ sequence })),
          expectedError: /exactly 47 contract definitions/,
        },
        {
          name: "materialized payload drift",
          canonicalDefinitions: definitions,
          executableDefinitions: definitions,
          executablePreflight: {
            ...preflight(definitions),
            steps: preflight(definitions).steps.map((step, index) => (
              index === 46 ? { ...step, unsigned: {} } : step
            )),
          },
          setupOperations: Array.from({ length: 110 }, (_, sequence) => ({ sequence })),
          expectedError: /did not freeze all 47 initcode\/calldata payloads/,
        },
        {
          name: "setup operation count drift",
          canonicalDefinitions: definitions,
          executableDefinitions: definitions,
          setupOperations: Array.from({ length: 109 }, (_, sequence) => ({ sequence })),
          expectedError: /operation plan is incomplete/,
        },
      ];

      for (const testCase of cases) {
        await assert.rejects(
          validateAndReserveCanonicalDeployment({
            ...common,
            ...testCase,
          }),
          testCase.expectedError,
          testCase.name,
        );
      }
      assert.equal(reservationCalls, 0);
      assert.equal(existsSync(reservationPath), false);

      const { frozenPreflight, reservation } = await validateAndReserveCanonicalDeployment({
        ...common,
        canonicalDefinitions: definitions,
      });
      assert.equal(reservationCalls, 1);
      assert.equal(reservation.path, reservationPath);
      assert.equal(Object.isFrozen(frozenPreflight), true);
      assert.equal(Object.isFrozen(frozenPreflight.steps), true);
      assert.equal(frozenPreflight.steps.length, 47);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
