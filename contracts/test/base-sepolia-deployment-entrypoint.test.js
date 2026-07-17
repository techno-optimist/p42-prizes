import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

import {
  PRODUCTION_DEPLOY_MODE,
  dispatchBaseSepoliaDeployment,
  runCanonicalProductionEntryPoint,
} from "../scripts/base-sepolia-deployment-entrypoint.js";

function sideEffectHarness() {
  const topology = JSON.parse(readFileSync(
    resolve(import.meta.dirname, "../../protocol/canonical-topology-v1.json"),
    "utf8",
  ));
  const canonicalContractCount = topology.shared.length
    + topology.boardCount * topology.perBoard.length;
  const calls = {
    rpc: 0,
    nonceReservation: 0,
    manifestReservation: 0,
    signing: 0,
    broadcast: 0,
    productionPlanner: 0,
    legacyPlanner: 0,
  };
  return {
    calls,
    options: {
      requireRpc: () => { calls.rpc += 1; },
      inspectReservation: () => { calls.manifestReservation += 1; },
      connectRpc: async () => ({ close: async () => {} }),
      deployProduction: async () => {
        calls.productionPlanner += 1;
        calls.nonceReservation += 1;
        calls.manifestReservation += 1;
        calls.signing += 1;
        calls.broadcast += 1;
        return Array.from({ length: canonicalContractCount }, (_, index) => `contract-${index + 1}`);
      },
      deployLegacyTestOnly: async () => { calls.legacyPlanner += 1; },
      continueDeployment: async () => {},
    },
  };
}

describe("Base Sepolia deployment entry points", () => {
  for (const [label, requestedMode] of [["missing", undefined], ["legacy default", "deploy"]]) {
    it(`rejects ${label} mode before RPC, reservation, nonce, signing, or broadcast`, async () => {
      const harness = sideEffectHarness();
      await assert.rejects(
        dispatchBaseSepoliaDeployment({ requestedMode, ...harness.options }),
        /P42_DEPLOY_MODE/,
      );
      assert.deepEqual(harness.calls, {
        rpc: 0,
        nonceReservation: 0,
        manifestReservation: 0,
        signing: 0,
        broadcast: 0,
        productionPlanner: 0,
        legacyPlanner: 0,
      });
    });
  }

  it("rejects absent and wrong canonical modes before dispatch", async () => {
    for (const requestedMode of [undefined, "test-only-legacy-single-board", "continue"]) {
      let dispatches = 0;
      await assert.rejects(
        runCanonicalProductionEntryPoint({
          requestedMode,
          dispatch: async () => { dispatches += 1; },
        }),
        /P42_DEPLOY_MODE/,
      );
      assert.equal(dispatches, 0);
    }
  });

  it("selects only the canonical 47-contract production planner", async () => {
    const harness = sideEffectHarness();
    const plan = await runCanonicalProductionEntryPoint({
      requestedMode: PRODUCTION_DEPLOY_MODE,
      dispatch: (mode) => dispatchBaseSepoliaDeployment({
        requestedMode: mode,
        ...harness.options,
      }),
    });
    assert.equal(plan.length, 47);
    assert.equal(harness.calls.productionPlanner, 1);
    assert.equal(harness.calls.legacyPlanner, 0);
    const implementation = readFileSync(
      resolve(import.meta.dirname, "../scripts/deploy-base-sepolia.js"),
      "utf8",
    );
    assert.match(
      implementation,
      /deployProduction:[\s\S]*deployMultiBoardCeremony\(ethers, "production"\)/,
    );
  });

  it("binds npm commands to production and test-only noncanonical outputs", () => {
    const packageJson = JSON.parse(readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"));
    assert.match(packageJson.scripts["deploy:base-sepolia"], /deploy-base-sepolia-production\.js/);
    assert.match(packageJson.scripts["deploy:base-sepolia"], /P42_DEPLOY_MODE=deploy-multiboard-production/);
    assert.match(packageJson.scripts["deploy:test-only-legacy-base-sepolia"], /test-only-legacy-single-board/);
    const implementation = readFileSync(
      resolve(import.meta.dirname, "../scripts/deploy-base-sepolia.js"),
      "utf8",
    );
    assert.match(implementation, /test-only-legacy-p42-prizes\.json/);
    assert.doesNotMatch(packageJson.scripts["deploy:base-sepolia"], /test-only|legacy/);
  });
});
