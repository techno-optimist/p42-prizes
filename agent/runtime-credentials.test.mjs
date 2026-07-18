import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { readCredentialJson, readCredentialText, readCredentialUrl } from "./runtime-credentials.mjs";

test("systemd credential files are read without environment fallback", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-credential-"));
  const key = join(root, "private-key");
  writeFileSync(key, "0x" + "1".repeat(64) + "\n", { mode: 0o600 });
  assert.equal(readCredentialText(key, "operator key"), "0x" + "1".repeat(64));

  const jwk = join(root, "jwk.json");
  writeFileSync(jwk, '{"kty":"RSA"}\n', { mode: 0o600 });
  assert.deepEqual(readCredentialJson(jwk, "Arweave JWK"), { kty: "RSA" });

  const rpc = join(root, "rpc-url");
  writeFileSync(rpc, "https://rpc.example/path\n", { mode: 0o600 });
  assert.equal(readCredentialUrl(rpc, "RPC URL"), "https://rpc.example/path");
});

test("credential files reject symlinks and permissive modes", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-credential-reject-"));
  const source = join(root, "source");
  const link = join(root, "link");
  writeFileSync(source, "secret\n", { mode: 0o600 });
  symlinkSync(source, link);
  assert.throws(() => readCredentialText(link), /symlink|ELOOP/);
  chmodSync(source, 0o644);
  assert.throws(() => readCredentialText(source), /group\/world-readable/);

  const invalid = join(root, "invalid-url");
  writeFileSync(invalid, "http://rpc.example\n", { mode: 0o600 });
  assert.throws(() => readCredentialUrl(invalid), /authenticated HTTPS URL/);
});
