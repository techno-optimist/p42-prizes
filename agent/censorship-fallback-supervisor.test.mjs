import assert from "node:assert/strict";
import { it } from "node:test";

import {
  assertCompleteOutcome,
  classifyRetryOutcome,
  parseSupervisorArgs,
  superviseFallback,
} from "./censorship-fallback-supervisor.mjs";
import { canonicalJson } from "./lib.mjs";

it("keeps expected pending progress outside the crash budget", async () => {
  const statuses = [75, 75, 0];
  let sleeps = 0;
  assert.equal(await superviseFallback({
    runStep: async () => {
      const status = statuses.shift();
      return status === 75 ? { status, reasonCode: "awaiting-finalized-chain-evidence" } : status;
    },
    sleep: async () => { sleeps += 1; },
  }), 0);
  assert.equal(sleeps, 2);
});

it("returns terminal policy refusal and maps abnormal child failure", async () => {
  assert.equal(await superviseFallback({ runStep: async () => 64, sleep: async () => {} }), 64);
  assert.equal(await superviseFallback({ runStep: async () => 1, sleep: async () => {} }), 70);
});

it("bounds RPC retry failures and rejects an unclassified exit 75", async () => {
  let attempts = 0;
  assert.equal(await superviseFallback({
    runStep: async () => {
      attempts += 1;
      return { status: 75, reasonCode: "rpc-unavailable" };
    },
    sleep: async () => {},
    maxRpcRetries: 2,
  }), 70);
  assert.equal(attempts, 3);
  assert.equal(await superviseFallback({ runStep: async () => 75, sleep: async () => {} }), 70);
  assert.equal(await superviseFallback({ runStep: async () => "stopped", sleep: async () => {} }), 0);
});

it("stops cleanly before another child step after termination during retry delay", async () => {
  let attempts = 0;
  let stopped = false;
  assert.equal(await superviseFallback({
    runStep: async () => {
      attempts += 1;
      return { status: 75, reasonCode: "awaiting-finalized-chain-evidence" };
    },
    sleep: async () => { stopped = true; },
    shouldStop: () => stopped,
  }), 0);
  assert.equal(attempts, 1);
});

it("accepts only canonical classified retry outcomes on the correct stream", () => {
  const waiting = Buffer.from(`${canonicalJson({
    schema: "p42-censorship-fallback-outcome/v1",
    status: "retry",
    stage: "policy_broadcast",
    reason_code: "awaiting-finalized-chain-evidence",
    retry_after_seconds: 15,
    plan_hash: `sha256:${"a".repeat(64)}`,
  })}\n`);
  assert.deepEqual(classifyRetryOutcome([waiting], []), {
    status: 75, reasonCode: "awaiting-finalized-chain-evidence",
  });
  const rpc = Buffer.from(`${canonicalJson({
    schema: "p42-censorship-fallback-outcome/v1",
    status: "retry",
    reason_code: "rpc-unavailable",
    message: "timeout",
    retry_after_seconds: 15,
  })}\n`);
  assert.deepEqual(classifyRetryOutcome([], [rpc]), { status: 75, reasonCode: "rpc-unavailable" });
  assert.throws(() => classifyRetryOutcome([Buffer.from("{}\n")], []), /envelope is invalid/);
  assert.throws(() => classifyRetryOutcome([waiting], [rpc]), /exactly one output stream/);
});

it("requires an exact canonical completion outcome", () => {
  const complete = Buffer.from(`${canonicalJson({
    schema: "p42-censorship-fallback-outcome/v1",
    status: "complete",
    stage: "challenge_l2_confirmed",
    reason_code: null,
    retry_after_seconds: null,
    plan_hash: `sha256:${"b".repeat(64)}`,
  })}\n`);
  assert.doesNotThrow(() => assertCompleteOutcome([complete], []));
  assert.throws(() => assertCompleteOutcome([], []), /stdout only/);
  assert.throws(() => assertCompleteOutcome([complete], [Buffer.from("warning\n")]), /stdout only/);
});

it("requires exact bounded options and an absolute runtime", () => {
  const parsed = parseSupervisorArgs([
    "--runtime", "/usr/local/bin/p42-censorship-fallback",
    "--step-timeout-ms", "120000",
    "--kill-grace-ms", "10000",
    "--retry-delay-ms", "15000",
    "--max-rpc-retries", "8",
    "--", "--plan", "/srv/p42/plan.json",
  ]);
  assert.equal(parsed.runtimeArgs[0], "--plan");
  assert.throws(() => parseSupervisorArgs([
    "--runtime", "relative", "--step-timeout-ms", "1", "--kill-grace-ms", "1",
    "--retry-delay-ms", "1", "--max-rpc-retries", "1", "--",
  ]), /must be absolute/);
});
