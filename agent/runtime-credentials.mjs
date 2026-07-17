import {
  closeSync,
  fstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { O_NOFOLLOW, O_RDONLY } from "node:constants";
import { parseStrictJsonText } from "./strict-json.mjs";

const MAX_CREDENTIAL_BYTES = 4 * 1024 * 1024;

function readCredentialBytes(path, label) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new Error(`${label} must be an absolute credential file path`);
  }
  const flags = O_RDONLY | O_NOFOLLOW;
  let descriptor;
  try {
    descriptor = openSync(path, flags);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile()) throw new Error(`${label} must be a regular file`);
    if (metadata.mode & 0o077) throw new Error(`${label} must not be group/world-readable`);
    if (metadata.size > MAX_CREDENTIAL_BYTES) throw new Error(`${label} exceeds the credential size limit`);
    return readFileSync(descriptor);
  } catch (error) {
    if (error?.code === "ELOOP") throw new Error(`${label} must not be a symlink`);
    throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function readCredentialText(path, label = "credential") {
  const text = readCredentialBytes(path, label).toString("utf8").trim();
  if (!text) throw new Error(`${label} must not be empty`);
  return text;
}

export function readCredentialJson(path, label = "credential") {
  const text = readCredentialText(path, label);
  const value = parseStrictJsonText(text, { label, maxBytes: MAX_CREDENTIAL_BYTES, maxDepth: 32 });
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must contain a JSON object`);
  }
  return value;
}
