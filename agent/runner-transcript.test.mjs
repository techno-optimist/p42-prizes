import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, sha256Canonical } from "./lib.mjs";
import { verifyRunnerTranscript } from "./runner-transcript.mjs";

function fixture() {
  const body = {
    schema_version: "p42-runner-transcript/v1",
    job_id: "job-1",
    verifier: { ok: true, valid: true },
  };
  const transcript = { ...body, transcript_hash: sha256Canonical(body) };
  const directory = mkdtempSync(join(tmpdir(), "p42-runner-transcript-"));
  const path = join(directory, `${transcript.transcript_hash.slice(7)}.json`);
  writeFileSync(path, `${canonicalJson(transcript)}\n`, { mode: 0o600 });
  return { path, transcript };
}

test("runner transcript must match the hash committed by the queue", () => {
  const { path, transcript } = fixture();
  assert.equal(verifyRunnerTranscript(path, transcript.transcript_hash).transcript.job_id, "job-1");
  assert.throws(
    () => verifyRunnerTranscript(path, `sha256:${"f".repeat(64)}`),
    /queue transcript hash mismatch/,
  );
});

test("runner transcript rejects a missing queue hash", () => {
  const { path } = fixture();
  assert.throws(() => verifyRunnerTranscript(path, undefined), /missing or malformed/);
});
