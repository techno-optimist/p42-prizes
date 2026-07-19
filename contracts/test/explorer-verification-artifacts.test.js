import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  assertNoSigningSecrets,
  randomNonce,
  readExplorerArtifactExact,
  sha256,
  writeExplorerArtifactExclusive,
} from "../scripts/explorer-verification-artifacts.js";

function privateRoot() {
  const root = mkdtempSync(join(tmpdir(), "p42-explorer-artifacts-"));
  chmodSync(root, 0o700);
  return root;
}

test("explorer artifacts require exact bytes and refuse replacement", () => {
  const root = privateRoot();
  const path = join(root, "artifact.json");
  const value = { schema: "fixture/v1", nested: { b: 2, a: 1 } };
  const result = writeExplorerArtifactExclusive(path, root, value);

  assert.equal(result.sha256, sha256(readFileSync(path)));
  assert.deepEqual(readExplorerArtifactExact(path, result.sha256, { trustedRoot: root }).value, value);
  assert.throws(() => readExplorerArtifactExact(path, `sha256:${"0".repeat(64)}`, { trustedRoot: root }), /exact-bytes digest mismatch/);
  assert.throws(() => writeExplorerArtifactExclusive(path, root, value), /refusing to overwrite/);
});

test("explorer artifacts reject symlinks and paths outside the trusted root", () => {
  const root = privateRoot();
  const outside = privateRoot();
  const target = join(root, "target.json");
  const link = join(root, "link.json");
  const bytes = Buffer.from("{\"ok\":true}\n");
  writeFileSync(target, bytes, { mode: 0o600 });
  symlinkSync(target, link);

  assert.throws(() => readExplorerArtifactExact(link, sha256(bytes), { trustedRoot: root }), /symbolic link|symlink|no-follow|regular file/i);
  assert.throws(() => writeExplorerArtifactExclusive(join(outside, "escape.json"), root, { ok: true }), /trusted root|outside/i);
});

test("offline explorer phases reject signing secrets and use bytes32 CSPRNG nonces", () => {
  assert.doesNotThrow(() => assertNoSigningSecrets({}));
  for (const name of ["BASE_SEPOLIA_PRIVATE_KEY", "OPERATOR_PRIVATE_KEY", "RESOLVER_PRIVATE_KEY", "AGENT_PRIVATE_KEY", "P42_FUNDING_SIGNER_PRIVATE_KEY", "P42_INDEXER_ATTESTATION_PRIVATE_KEY", "ARWEAVE_JWK_JSON", "SIGNING_SEED"]) {
    assert.throws(() => assertNoSigningSecrets({ [name]: "secret" }), new RegExp(name));
  }
  const nonces = new Set(Array.from({ length: 32 }, () => randomNonce()));
  assert.equal(nonces.size, 32);
  for (const nonce of nonces) assert.match(nonce, /^0x[0-9a-f]{64}$/);
});

test("every explorer ceremony CLI rejects signing authority before inputs or network", () => {
  for (const script of [
    "collect-explorer-verification-evidence.js",
    "prepare-explorer-verification-request.js",
    "record-explorer-verification-attestation.js",
    "assemble-explorer-verification-dossier.js",
  ]) {
    const result = spawnSync(process.execPath, [new URL(`../scripts/${script}`, import.meta.url).pathname], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, OPERATOR_PRIVATE_KEY: `0x${"1".repeat(64)}` },
    });
    assert.notEqual(result.status, 0, script);
    assert.match(result.stderr, /OPERATOR_PRIVATE_KEY is forbidden/, script);
    assert.doesNotMatch(result.stderr, /Missing required env var/, script);
  }
});
