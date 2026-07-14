import assert from "node:assert/strict";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, it } from "node:test";

import {
  buildFallbackAlertRecord,
  persistFallbackAlert,
} from "./censorship-fallback-alert.mjs";
import { canonicalJson, sha256Canonical } from "./lib.mjs";

const roots = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

it("records exact systemd failure metadata in an exclusive private alert", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-fallback-alert-"));
  chmodSync(root, 0o700);
  roots.push(root);
  const record = buildFallbackAlertRecord({
    unit: "p42-censorship-fallback.service",
    systemctlOutput: "Result=exit-code\nExecMainCode=1\nExecMainStatus=64\n",
    observedAtUtc: "2026-07-14T01:02:03.000Z",
  });
  const { alertHash, ...body } = record;
  assert.equal(alertHash, sha256Canonical(body));
  const path = persistFallbackAlert(record, root);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(readFileSync(path, "utf8"), `${canonicalJson(record)}\n`);
  assert.throws(() => persistFallbackAlert(record, root), /already exists/);
});

it("rejects fabricated units, malformed manager output, and unsafe roots", () => {
  for (const unit of ["../p42-censorship-fallback.service", "ssh.service", "p42-censorship-fallback"]) {
    assert.throws(() => buildFallbackAlertRecord({
      unit,
      systemctlOutput: "Result=exit-code\nExecMainCode=1\nExecMainStatus=64\n",
      observedAtUtc: "2026-07-14T01:02:03Z",
    }), /unit identity/);
  }
  assert.throws(() => buildFallbackAlertRecord({
    unit: "p42-censorship-fallback.service",
    systemctlOutput: "Result=exit-code\nExecMainStatus=64\n",
    observedAtUtc: "2026-07-14T01:02:03Z",
  }), /metadata is incomplete/);
  const root = mkdtempSync(join(tmpdir(), "p42-fallback-alert-unsafe-"));
  roots.push(root);
  chmodSync(root, 0o755);
  assert.throws(() => persistFallbackAlert({
    observedAtUtc: "2026-07-14T01:02:03.000Z",
    alertHash: `sha256:${"a".repeat(64)}`,
  }, root), /private trusted directory/);
  chmodSync(root, 0o700);
  const link = `${root}-link`;
  roots.push(link);
  symlinkSync(root, link);
  assert.throws(() => persistFallbackAlert({
    observedAtUtc: "2026-07-14T01:02:04.000Z",
    alertHash: `sha256:${"b".repeat(64)}`,
  }, link), /must not be a symlink/);
});

it("ships a bounded writable systemd service and its named alert unit", () => {
  const service = readFileSync(new URL("../deployments/p42-censorship-fallback.service.example", import.meta.url), "utf8");
  const alert = readFileSync(new URL("../deployments/p42-censorship-fallback-alert@.service.example", import.meta.url), "utf8");
  assert.match(service, /^OnFailure=p42-censorship-fallback-alert@%n\.service$/m);
  assert.match(service, /^StartLimitIntervalSec=20min$/m);
  assert.match(service, /^StartLimitBurst=6$/m);
  assert.match(service, /^ExecStart=\/usr\/local\/bin\/p42-censorship-fallback-supervisor \\$/m);
  assert.match(service, /--step-timeout-ms 120000 --kill-grace-ms 10000 --retry-delay-ms 15000 \\$/m);
  assert.match(service, /--max-rpc-retries 8 -- \\$/m);
  assert.match(service, /^TimeoutStopSec=20s$/m);
  assert.match(service, /^TimeoutStartSec=infinity$/m);
  assert.match(service, /^RestartMode=direct$/m);
  assert.match(service, /^KillMode=mixed$/m);
  assert.doesNotMatch(service, /^RuntimeMaxSec=/m);
  assert.match(service, /^StateDirectory=p42-censorship-fallback$/m);
  assert.match(service, /^ReadWritePaths=\/var\/lib\/p42-censorship-fallback$/m);
  assert.doesNotMatch(service, /^ReadWritePaths=.*\$\{/m);
  assert.match(alert, /^ExecStart=\/usr\/local\/bin\/p42-censorship-fallback-alert \\$/m);
  assert.match(alert, /^TimeoutStartSec=30s$/m);
  assert.match(alert, /^User=p42-fallback-alert$/m);
  assert.match(alert, /^StateDirectory=p42-censorship-fallback-alerts$/m);
  assert.match(alert, /^ReadWritePaths=\/var\/lib\/p42-censorship-fallback-alerts$/m);
  assert.doesNotMatch(service, /p42-censorship-fallback-alerts/);
});
