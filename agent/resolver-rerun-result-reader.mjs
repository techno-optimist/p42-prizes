import {
  closeSync, constants, fstatSync, lstatSync, openSync, readSync,
} from "node:fs";
import { relative, resolve, sep } from "node:path";

import { canonicalJson } from "./lib.mjs";
import { readCredentialJson } from "./runtime-credentials.mjs";
import { parseStrictJsonBytes } from "./strict-json.mjs";

export const RESOLVER_RERUN_RESULT_AUTHORITY_SCHEMA = "p42-resolver-rerun-result-authority/v1";
const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertDirectory(metadata, expectedUid, expectedGid) {
  if (!metadata.isDirectory() || metadata.isSymbolicLink?.()
      || metadata.uid !== expectedUid || metadata.gid !== expectedGid
      || (metadata.mode & 0o777) !== 0o750) {
    throw new Error("resolver rerun result ancestor authority mismatch");
  }
}

function assertFile(metadata, expectedUid, expectedGid, maxBytes) {
  if (!metadata.isFile() || metadata.isSymbolicLink?.() || metadata.nlink !== 1
      || metadata.uid !== expectedUid || metadata.gid !== expectedGid
      || (metadata.mode & 0o777) !== 0o640 || metadata.size > maxBytes) {
    throw new Error("resolver rerun result file authority mismatch");
  }
}

export function validateResolverRerunResultAuthority(value) {
  if (!exactKeys(value, ["schema_version", "submitter_gid", "boards"])
      || value.schema_version !== RESOLVER_RERUN_RESULT_AUTHORITY_SCHEMA
      || !Number.isSafeInteger(value.submitter_gid) || value.submitter_gid < 1
      || !Array.isArray(value.boards) || value.boards.length < 1) {
    throw new Error("resolver rerun result authority credential is malformed");
  }
  const seen = new Set();
  const boards = value.boards.map((board) => {
    if (!exactKeys(board, ["registry_problem_id", "rerun_uid"])
        || !/^[1-9][0-9]*$/.test(board.registry_problem_id ?? "")
        || !Number.isSafeInteger(board.rerun_uid) || board.rerun_uid < 1
        || seen.has(board.registry_problem_id)) {
      throw new Error("resolver rerun result board authority is malformed or duplicated");
    }
    seen.add(board.registry_problem_id);
    return Object.freeze({ ...board });
  });
  return Object.freeze({ ...value, boards: Object.freeze(boards) });
}

export function loadResolverRerunResultAuthority(path) {
  return validateResolverRerunResultAuthority(readCredentialJson(path, "resolver rerun result authority"));
}

export function resolverRerunResultBoardAuthority(authorityValue, registryProblemId) {
  const authority = validateResolverRerunResultAuthority(authorityValue);
  const board = authority.boards.find((item) => item.registry_problem_id === String(registryProblemId));
  if (!board) throw new Error("resolver rerun result authority does not include this board");
  return Object.freeze({ uid: board.rerun_uid, gid: authority.submitter_gid });
}

export function readResolverRerunResultJsonSync(pathValue, options) {
  const path = resolve(pathValue);
  const root = resolve(options.root);
  const expectedUid = options.expectedUid;
  const expectedGid = options.expectedGid;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  if (!Number.isSafeInteger(expectedUid) || expectedUid < 1
      || !Number.isSafeInteger(expectedGid) || expectedGid < 1
      || !Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new Error("resolver rerun result reader authority is invalid");
  }
  const rel = relative(root, path);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`)) {
    throw new Error("resolver rerun result path escapes its board root");
  }
  const io = {
    closeSync: options.io?.closeSync ?? closeSync,
    fstatSync: options.io?.fstatSync ?? fstatSync,
    lstatSync: options.io?.lstatSync ?? lstatSync,
    openSync: options.io?.openSync ?? openSync,
    readSync: options.io?.readSync ?? readSync,
  };
  const held = [];
  let file = -1;
  try {
    let descriptor = io.openSync(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    held.push(descriptor);
    const rootBefore = io.lstatSync(root);
    const rootOpened = io.fstatSync(descriptor);
    assertDirectory(rootBefore, expectedUid, expectedGid);
    assertDirectory(rootOpened, expectedUid, expectedGid);
    if (!sameInode(rootBefore, rootOpened)) throw new Error("resolver rerun result root changed during open");
    const parts = rel.split(sep);
    const name = parts.pop();
    let traversed = root;
    for (const part of parts) {
      traversed = resolve(traversed, part);
      const before = io.lstatSync(traversed);
      descriptor = io.openSync(`/dev/fd/${descriptor}/${part}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      held.push(descriptor);
      const opened = io.fstatSync(descriptor);
      const after = io.lstatSync(traversed);
      for (const metadata of [before, opened, after]) assertDirectory(metadata, expectedUid, expectedGid);
      if (!sameInode(before, opened) || !sameInode(opened, after)) {
        throw new Error("resolver rerun result ancestor changed during traversal");
      }
    }
    const before = io.lstatSync(path);
    file = io.openSync(`/dev/fd/${descriptor}/${name}`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const opened = io.fstatSync(file);
    assertFile(before, expectedUid, expectedGid, maxBytes);
    assertFile(opened, expectedUid, expectedGid, maxBytes);
    if (!sameInode(before, opened)) throw new Error("resolver rerun result file changed during open");
    const chunks = [];
    let total = 0;
    for (;;) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes - total + 1));
      const count = io.readSync(file, chunk, 0, chunk.length, null);
      if (count === 0) break;
      total += count;
      if (total > maxBytes) throw new Error("resolver rerun result exceeds its size limit");
      chunks.push(chunk.subarray(0, count));
    }
    const after = io.lstatSync(path);
    assertFile(after, expectedUid, expectedGid, maxBytes);
    if (!sameInode(opened, after) || after.size !== total) {
      throw new Error("resolver rerun result file changed during read");
    }
    return parseStrictJsonBytes(Buffer.concat(chunks, total), {
      maxBytes, maxDepth: options.maxDepth ?? 64, canonicalBytes: true, trailingNewline: "require",
    });
  } finally {
    if (file >= 0) io.closeSync(file);
    for (const descriptor of held.reverse()) io.closeSync(descriptor);
  }
}
