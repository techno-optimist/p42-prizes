import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runRuntimeCycle } from "./runtime-supervisor.mjs";
import { verifyRuntimeUnitExecStart } from "../scripts/verify-runtime-execstart.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const FIXTURE = join(HERE, "fixtures", "runtime-systemd", "poll-cycle.mjs");

function startRpc() {
  const server = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1" }));
    });
  });
  return new Promise((resolvePromise) => {
    server.listen(0, "127.0.0.1", () => {
      resolvePromise({
        endpoint: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

function substituteFixtureValues(argv, primaryRpc, secondaryRpc) {
  const replacements = new Map([
    ["${P42_RPC_URL}", primaryRpc],
    ["${P42_NONCE_RPC_SECONDARY_URL}", secondaryRpc],
    ["${P42_PROBLEM_SLUG}", "fixture-problem"],
    ["${P42_REGISTRY_PROBLEM_ID}", "1"],
    ["${P42_AGENT_WALLET_ADDRESS}", "0x1111111111111111111111111111111111111111"],
    ["${P42_RUNNER_HEALTH_PUBLIC_KEY}", "fixture-health-key"],
    ["${P42_RUNNER_RECOVERY_PUBLIC_KEY}", "fixture-recovery-key"],
    ["${P42_RUNNER_HOST_ID}", "fixture-host"],
    ["${P42_RUNNER_BOOT_ID}", "fixture-boot"],
    ["${P42_RUNNER_QUEUE_ID}", "fixture-queue"],
    ["${P42_TRANSCRIPT_ENDPOINT_PRIMARY}", "https://arweave.net"],
    ["${P42_TRANSCRIPT_ENDPOINT_SECONDARY}", "https://ar-io.net"],
  ]);
  return argv.map((value) => replacements.get(value) ?? value);
}

for (const role of ["operator", "resolver"]) {
  test(`${role} systemd template completes one supervised poll cycle with fixture RPC/publisher`, async () => {
    const primary = await startRpc();
    const secondary = await startRpc();
    const scratch = mkdtempSync(join(tmpdir(), `p42-${role}-systemd-`));
    const publisherOutput = join(scratch, "publisher.json");
    try {
      const unit = join(ROOT, "deployments", `p42-${role}@.service.example`);
      const { argv, supervisor } = verifyRuntimeUnitExecStart(unit, role);
      const output = new PassThrough();
      let stdout = "";
      output.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
      const outcome = await runRuntimeCycle({
        runtime: process.execPath,
        runtimeArgs: [FIXTURE, ...substituteFixtureValues(argv, primary.endpoint, secondary.endpoint)],
        cycleTimeoutMs: supervisor.cycleTimeoutMs,
        killGraceMs: supervisor.killGraceMs,
        env: { ...process.env, P42_RUNTIME_SMOKE_PUBLISHER_OUTPUT: publisherOutput },
        stdout: output,
        stderr: output,
      });
      assert.equal(outcome.classification, "success", stdout);
      assert.match(stdout, new RegExp(`"poll_cycles":1,"role":"${role}"`));
      if (role === "resolver") {
        assert.equal(existsSync(publisherOutput), true);
        assert.deepEqual(JSON.parse(readFileSync(publisherOutput, "utf8")), {
          publisher: "stub", polls: 1, role: "resolver",
        });
      }
    } finally {
      await primary.close();
      await secondary.close();
    }
  });
}
