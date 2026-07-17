import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, it } from "node:test";

import {
  PRODUCTION_DEPLOY_MODE,
  dispatchBaseSepoliaDeployment,
  runCanonicalProductionEntryPoint,
} from "../scripts/base-sepolia-deployment-entrypoint.js";

const libraryImport = Symbol.for("p42-prizes.deploy-base-sepolia.library-import");
globalThis[libraryImport] = true;
const { runBaseSepoliaDeployment } = await import("../scripts/deploy-base-sepolia.js");
const CONTRACTS_ROOT = resolve(import.meta.dirname, "..");

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
    const previousRpc = process.env.BASE_SEPOLIA_RPC_URL;
    process.env.BASE_SEPOLIA_RPC_URL = "http://127.0.0.1:1";
    const calls = { production: 0, legacy: 0, continuation: 0, close: 0 };
    try {
      const plan = await runBaseSepoliaDeployment({
        mode: PRODUCTION_DEPLOY_MODE,
        networkApi: {
          create: async () => ({
            ethers: { provider: { getNetwork: async () => ({ chainId: 84532n }) } },
            close: async () => { calls.close += 1; },
          }),
        },
        planners: {
          production: async () => {
            calls.production += 1;
            return canonicalPlan();
          },
          legacyTestOnly: async () => { calls.legacy += 1; },
          continuation: async () => { calls.continuation += 1; },
        },
      });
      assert.equal(plan.length, 47);
      assert.deepEqual(calls, { production: 1, legacy: 0, continuation: 0, close: 1 });
    } finally {
      if (previousRpc === undefined) delete process.env.BASE_SEPOLIA_RPC_URL;
      else process.env.BASE_SEPOLIA_RPC_URL = previousRpc;
    }
  });

  it("binds npm commands to production and test-only noncanonical outputs", () => {
    const packageJson = JSON.parse(readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"));
    assert.equal(
      packageJson.scripts["deploy:base-sepolia"],
      "P42_DEPLOY_MODE=deploy-multiboard-production hardhat run scripts/deploy-base-sepolia-production.js --network baseSepolia",
    );
    assert.equal(
      packageJson.scripts["deploy:test-only-legacy-base-sepolia"],
      "P42_DEPLOY_MODE=test-only-legacy-single-board hardhat run scripts/deploy-base-sepolia.js --network baseSepolia",
    );
  });

  it("enforces canonical mode at real wrapper and npm process boundaries without deployment side effects", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "p42-entrypoint-process-"));
    try {
      const manifest = resolve(root, "p42-prizes.json");
      const sentinel = resolve(root, "deploy-module-imported");
      const loader = resolve(root, "import-observer.mjs");
      await writeFile(loader, `
        import { appendFileSync } from "node:fs";
        export async function resolve(specifier, context, nextResolve) {
          if (specifier.endsWith("/deploy-base-sepolia.js") || specifier === "./deploy-base-sepolia.js") {
            appendFileSync(process.env.P42_IMPORT_SENTINEL, "imported\\n");
          }
          return nextResolve(specifier, context);
        }
      `);
      const baseEnv = { ...process.env,
        NODE_OPTIONS: `--experimental-loader=${loader}`,
        P42_DEPLOYMENT_MANIFEST: manifest,
        P42_IMPORT_SENTINEL: sentinel,
      };
      delete baseEnv.BASE_SEPOLIA_RPC_URL;
      delete baseEnv.P42_DEPLOY_MODE;

      const missing = spawnSync(process.execPath, ["scripts/deploy-base-sepolia-production.js"], {
        cwd: CONTRACTS_ROOT, env: baseEnv, encoding: "utf8",
      });
      assert.notEqual(missing.status, 0);
      assert.match(missing.stderr, /P42_DEPLOY_MODE is required/);
      assert.equal(existsSync(sentinel), false);
      assertNoDeploymentArtifacts(manifest);

      const wrong = spawnSync(process.execPath, ["scripts/deploy-base-sepolia-production.js"], {
        cwd: CONTRACTS_ROOT,
        env: { ...baseEnv, P42_DEPLOY_MODE: "test-only-legacy-single-board" },
        encoding: "utf8",
      });
      assert.notEqual(wrong.status, 0);
      assert.match(wrong.stderr, /requires P42_DEPLOY_MODE=deploy-multiboard-production/);
      assert.equal(existsSync(sentinel), false);
      assertNoDeploymentArtifacts(manifest);

      const overridden = spawnSync("npm", ["run", "deploy:base-sepolia"], {
        cwd: CONTRACTS_ROOT,
        env: { ...baseEnv, P42_DEPLOY_MODE: "test-only-legacy-single-board" },
        encoding: "utf8",
      });
      assert.notEqual(overridden.status, 0);
      assert.match(`${overridden.stdout}\n${overridden.stderr}`, /Missing required env var: BASE_SEPOLIA_RPC_URL/);
      assert.equal(existsSync(sentinel), true);
      assertNoDeploymentArtifacts(manifest);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

function canonicalPlan() {
  const topology = JSON.parse(readFileSync(
    resolve(import.meta.dirname, "../../protocol/canonical-topology-v1.json"),
    "utf8",
  ));
  const count = topology.shared.length + topology.boardCount * topology.perBoard.length;
  return Array.from({ length: count }, (_, index) => `contract-${index + 1}`);
}

function assertNoDeploymentArtifacts(manifest) {
  for (const path of [
    manifest,
    `${manifest}.deployment-reservation.json`,
    `${manifest}.signed-transactions.json`,
    `${manifest}.governance-operations.json`,
  ]) assert.equal(existsSync(path), false, `${path} must not exist`);
}
