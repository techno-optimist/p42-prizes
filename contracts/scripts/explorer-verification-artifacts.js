import { createHash, randomBytes } from "node:crypto";
import { resolve } from "node:path";

import { readStrictJsonFileSyncWithBytes, writeTrustedFileExclusiveSync } from "../../agent/strict-json.mjs";

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const canonical = (value) => value === null || typeof value !== "object"
  ? JSON.stringify(value)
  : Array.isArray(value)
    ? `[${value.map(canonical).join(",")}]`
    : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;

export function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function readExplorerArtifactExact(path, expectedDigest, { trustedRoot, publicFile = false, maxBytes = 64 * 1024 * 1024 } = {}) {
  if (!DIGEST.test(expectedDigest ?? "")) throw new Error("artifact requires an exact out-of-band sha256 digest");
  const file = readStrictJsonFileSyncWithBytes(resolve(path), { trustedRoot: resolve(trustedRoot), publicFile, maxBytes, maxDepth: 256, trailingNewline: "allow" });
  if (sha256(file.bytes) !== expectedDigest) throw new Error("artifact exact-bytes digest mismatch");
  return file;
}

export function writeExplorerArtifactExclusive(path, trustedRoot, value) {
  const bytes = Buffer.from(`${canonical(value)}\n`);
  if (!writeTrustedFileExclusiveSync(resolve(path), resolve(trustedRoot), bytes)) throw new Error("refusing to overwrite explorer verification artifact");
  return { path: resolve(path), byteLength: bytes.length, sha256: sha256(bytes) };
}

export function randomNonce() {
  return `0x${randomBytes(32).toString("hex")}`;
}

export function assertNoSigningSecrets(env = process.env) {
  for (const [name, value] of Object.entries(env)) {
    if (typeof value === "string" && value !== "" && /(PRIVATE_KEY|SIGNING_KEY|SECRET|PASSWORD|MNEMONIC|JWK|(?:^|_)SEED(?:_|$))/i.test(name)) throw new Error(`${name} is forbidden in an explorer ceremony environment`);
  }
}
