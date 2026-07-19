import { randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, linkSync, mkdirSync, openSync, readFileSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

import { roleAcceptanceBytesDigest } from "./role-acceptance.mjs";

function assertOwnedDirectory(path, label) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (typeof process.getuid === "function" && stat.uid !== process.getuid()) || (stat.mode & 0o022) !== 0) throw new Error(`${label} is not an owner-controlled non-writable-by-others directory`);
}

function readImmutableTarget(path, expectedBytes = null) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o444 || (typeof process.getuid === "function" && stat.uid !== process.getuid())) throw new Error("content-addressed role acceptance artifact metadata is unsafe");
    const stored = readFileSync(fd);
    const after = fstatSync(fd);
    if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size || after.mode !== stat.mode || after.nlink !== stat.nlink || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) throw new Error("content-addressed role acceptance artifact changed while reading");
    if (expectedBytes && !stored.equals(expectedBytes)) throw new Error("content-addressed role acceptance artifact collision");
    return stored;
  } finally { closeSync(fd); }
}

export function readPreservedRoleAcceptanceArtifact(path, expectedDigest, label) {
  if (!/^sha256:[0-9a-f]{64}$/.test(expectedDigest ?? "")) throw new Error(`${label} expected digest is invalid`);
  const absolute = resolve(path); const hex = expectedDigest.slice("sha256:".length);
  if (basename(absolute) !== `${hex}.json` || basename(dirname(absolute)) !== "sha256") throw new Error(`${label} path is not the expected content-addressed path`);
  assertOwnedDirectory(dirname(dirname(absolute)), `${label} artifact root`);
  assertOwnedDirectory(dirname(absolute), `${label} sha256 directory`);
  const bytes = readImmutableTarget(absolute);
  if (roleAcceptanceBytesDigest(bytes) !== expectedDigest) throw new Error(`${label} preserved exact bytes digest mismatch`);
  return Object.freeze({ bytes, bytesDigest: expectedDigest, path: absolute, uri: `sha256://${hex}` });
}

export function publishRoleAcceptanceArtifact(bytes, artifactRoot, label) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) throw new Error(`${label} bytes are empty or invalid`);
  const requestedRoot = resolve(artifactRoot);
  assertOwnedDirectory(requestedRoot, "role acceptance artifact root");
  const root = realpathSync(requestedRoot);
  assertOwnedDirectory(root, "role acceptance artifact root");
  const directory = join(root, "sha256");
  try { mkdirSync(directory, { mode: 0o700 }); } catch (error) { if (error.code !== "EEXIST") throw error; }
  assertOwnedDirectory(directory, "role acceptance sha256 directory");
  const digest = roleAcceptanceBytesDigest(bytes);
  const hex = digest.slice("sha256:".length);
  const target = join(directory, `${hex}.json`);
  const temporary = join(directory, `.${hex}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`);
  let fd;
  try {
    fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o444);
    writeFileSync(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined;
    try { linkSync(temporary, target); } catch (error) { if (error.code !== "EEXIST") throw error; }
    unlinkSync(temporary);
    readImmutableTarget(target, Buffer.from(bytes));
    const directoryFd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } finally {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temporary); } catch {}
  }
  return Object.freeze({ label, bytesDigest: digest, uri: `sha256://${hex}`, path: target });
}

export function preserveRoleAcceptanceInputs({ manifestFile, capsuleFile, artifactRoot }) {
  return Object.freeze({
    pendingManifest: publishRoleAcceptanceArtifact(manifestFile.bytes, artifactRoot, "pending-manifest"),
    capsule: publishRoleAcceptanceArtifact(capsuleFile.bytes, artifactRoot, "capsule"),
  });
}
