import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
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
      const fixtureEnv = { ...process.env, P42_RUNTIME_SMOKE_PUBLISHER_OUTPUT: publisherOutput };
      for (const name of [
        "P42_TRANSCRIPT_ENDPOINTS", "P42_TRANSCRIPT_RECEIPT_SPOOL", "P42_TRANSCRIPT_STORE",
        "OPERATOR_PRIVATE_KEY", "RESOLVER_PRIVATE_KEY", "ARWEAVE_JWK_JSON",
      ]) delete fixtureEnv[name];
      const outcome = await runRuntimeCycle({
        runtime: process.execPath,
        runtimeArgs: [FIXTURE, ...substituteFixtureValues(argv, primary.endpoint, secondary.endpoint)],
        cycleTimeoutMs: supervisor.cycleTimeoutMs,
        killGraceMs: supervisor.killGraceMs,
        env: fixtureEnv,
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

function productionArgs(role) {
  if (role === "operator") {
    return [
      "--rpc", "https://rpc.example", "--nonce-rpc-secondary", "https://secondary.example",
      "--manifest", "/etc/p42/manifest.json", "--problem", "/opt/p42/problems/fixture",
      "--registry-problem-id", "1", "--repo-root", "/opt/p42", "--runtime", "/var/lib/p42/operator/fixture",
      "--coordination-root", "/var/lib/p42/operator/coordination",
      "--challenge-provisioning", "/etc/p42/challenge.json", "--sandbox-staging-root", "/var/lib/p42/operator/fixture/sandbox-staging",
      "--operator-private-key-file", "/run/credentials/p42/operator-private-key", "--agent-wallet", "0x1111111111111111111111111111111111111111",
      "--runner-health-public-key", "health", "--runner-recovery-public-key", "recovery",
      "--runner-host-id", "host", "--runner-boot-id", "boot", "--runner-queue-id", "queue",
    ];
  }
  return [
    "--rpc", "https://rpc.example", "--manifest", "/etc/p42/manifest.json", "--problem-id", "fixture",
    "--registry-problem-id", "1", "--transcripts", "/var/lib/p42/resolver/fixture/transcripts",
    "--quorum-signatures", "/var/lib/p42/resolver/fixture/quorum-signatures", "--runtime", "/var/lib/p42/resolver/fixture",
    "--coordination-root", "/var/lib/p42/resolver/coordination", "--resolver-private-key-file", "/run/credentials/p42/resolver-private-key",
    "--arweave-jwk-file", "/run/credentials/p42/arweave-jwk", "--agent-wallet", "0x1111111111111111111111111111111111111111",
    "--transcript-store", "arweave", "--transcript-endpoint", "https://one.example", "--transcript-endpoint", "https://two.test",
  ];
}

test("exact production entrypoints reject incomplete credential/staging preflight", () => {
  const operator = spawnSync(process.execPath, [join(ROOT, "agent", "operator.mjs"), ...productionArgs("operator").filter((value) => value !== "--sandbox-staging-root" && value !== "/var/lib/p42/operator/fixture/sandbox-staging")], {
    cwd: ROOT, encoding: "utf8", env: { PATH: process.env.PATH },
  });
  assert.equal(operator.status, 2);
  assert.match(operator.stderr, /--sandbox-staging-root must be provided exactly once/);

  const resolver = spawnSync(process.execPath, [join(ROOT, "agent", "resolver.mjs"), ...productionArgs("resolver").filter((value) => value !== "--arweave-jwk-file" && value !== "/run/credentials/p42/arweave-jwk")], {
    cwd: ROOT, encoding: "utf8", env: { PATH: process.env.PATH },
  });
  assert.equal(resolver.status, 1);
  assert.match(resolver.stderr, /--arweave-jwk-file must be provided exactly once/);
});

test("exact resolver entrypoint rejects legacy publication environment conflicts", () => {
  const resolver = spawnSync(process.execPath, [join(ROOT, "agent", "resolver.mjs"), ...productionArgs("resolver")], {
    cwd: ROOT,
    encoding: "utf8",
    env: { PATH: process.env.PATH, P42_TRANSCRIPT_ENDPOINTS: "https://legacy.one,https://legacy.two" },
  });
  assert.equal(resolver.status, 1);
  assert.match(resolver.stderr, /P42_TRANSCRIPT_ENDPOINTS conflicts with explicit --transcript-endpoint values/);
});
