#!/usr/bin/env node
// Root-owned bridge from signer-issued requests to per-board rerun units.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync, closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, realpathSync, renameSync, unlinkSync, writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "./lib.mjs";
import { validateResolverRerunRequest } from "./resolver-rerun-executor.mjs";
import { readResolverRerunResultJsonSync } from "./resolver-rerun-result-reader.mjs";
import { readCredentialJson } from "./runtime-credentials.mjs";
import { parseStrictJsonBytes } from "./strict-json.mjs";

export const DISPATCH_MAP_SCHEMA = "p42-resolver-rerun-dispatch-map/v1";
const REQUEST_NAME_RE = /^([0-9a-f]{64})-([0-9a-f]{64})\.json$/;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function fsyncDirectory(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function assertProtectedDirectory(path, { uid = 0, gid, writableByGroup = false, requireCanonicalPath = true } = {}) {
  const metadata = lstatSync(path);
  const forbidden = writableByGroup ? 0o002 : 0o022;
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== uid
      || (requireCanonicalPath && realpathSync(path) !== resolve(path))
      || (gid !== undefined && metadata.gid !== gid) || (metadata.mode & forbidden)) {
    throw new Error(`dispatcher directory authority mismatch: ${path}`);
  }
}

function durableReplace(path, value, mode = 0o600) {
  const directory = dirname(path);
  const temporary = `${path}.tmp-${process.pid}`;
  const payload = `${canonicalJson(value)}\n`;
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try { writeFileSync(fd, payload); fsyncSync(fd); } finally { closeSync(fd); }
  try {
    renameSync(temporary, path);
    fsyncDirectory(directory);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

function installExactRequest(path, bytes, { allowReplace = false } = {}) {
  const directory = dirname(path);
  if (existsSync(path)) {
    if (readFileSync(path).equals(bytes)) {
      const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try { fsyncSync(fd); } finally { closeSync(fd); }
      fsyncDirectory(directory);
      return;
    }
    if (!allowReplace) throw new Error("installed rerun request does not match the durable board slot");
  }
  const temporary = `${path}.tmp-${process.pid}`;
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o640);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  try {
    renameSync(temporary, path);
    fsyncDirectory(directory);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

export function validateDispatchMap(value) {
  if (!exactKeys(value, ["schema_version", "request_signer", "request_reader_gid", "submitter_gid", "boards"])
      || value.schema_version !== DISPATCH_MAP_SCHEMA
      || !/^0x[0-9a-f]{40}$/.test(value.request_signer ?? "")
      || !Number.isSafeInteger(value.request_reader_gid) || value.request_reader_gid < 1
      || !Number.isSafeInteger(value.submitter_gid) || value.submitter_gid < 1
      || !Array.isArray(value.boards) || value.boards.length < 1) {
    throw new Error("resolver rerun dispatch map is malformed");
  }
  const ids = new Set();
  const boards = value.boards.map((board) => {
    if (!exactKeys(board, ["registry_problem_id", "board_id", "rerun_uid"])
        || !/^[1-9][0-9]*$/.test(board.registry_problem_id ?? "")
        || !/^[0-9]+:[1-9][0-9]*:[a-z0-9][a-z0-9._-]+$/.test(board.board_id ?? "")
        || board.board_id.split(":", 3)[1] !== board.registry_problem_id
        || !Number.isSafeInteger(board.rerun_uid) || board.rerun_uid < 1
        || ids.has(board.registry_problem_id)) throw new Error("resolver rerun dispatch board is malformed or duplicated");
    ids.add(board.registry_problem_id);
    return Object.freeze({ ...board });
  });
  return Object.freeze({ ...value, boards: Object.freeze(boards) });
}

export function systemManager(systemctl = "/usr/bin/systemctl", run = spawnSync) {
  const invoke = (args) => {
    const completed = run(systemctl, args, { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
    if (completed.status !== 0) throw new Error((completed.stderr || completed.stdout || "system manager failed").trim());
    return completed.stdout ?? "";
  };
  return {
    status(unit) {
      const values = Object.fromEntries(invoke(["show", "--no-pager", "--property=LoadState,ActiveState,SubState,Result", unit])
        .trim().split("\n").filter(Boolean).map((line) => line.split("=", 2)));
      if (values.LoadState !== "loaded") throw new Error("resolver rerun unit is not loaded");
      return values;
    },
    start(unit) { invoke(["start", "--no-block", unit]); },
    resetFailed(unit) { invoke(["reset-failed", unit]); },
  };
}

function assertUnit(unit, registryProblemId) {
  const expected = `p42-resolver-rerun@${registryProblemId}.service`;
  if (unit !== expected) throw new Error("dispatcher refused a noncanonical rerun unit");
  return expected;
}

function sourceRequest(path, sourceRoot) {
  const name = basename(path);
  const match = name.match(REQUEST_NAME_RE);
  if (!match) throw new Error("rerun signer spool filename is noncanonical");
  const rootMetadata = lstatSync(sourceRoot);
  const metadata = lstatSync(path);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink() || (rootMetadata.mode & 0o077)
      || !metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
      || metadata.uid !== rootMetadata.uid || (metadata.mode & 0o077)) {
    throw new Error("rerun signer spool authority mismatch");
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.uid !== metadata.uid
        || opened.dev !== metadata.dev || opened.ino !== metadata.ino || (opened.mode & 0o077)) {
      throw new Error("rerun signer spool changed during protected open");
    }
    const bytes = readFileSync(fd);
    const after = lstatSync(path);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== bytes.length) {
      throw new Error("rerun signer spool changed during read");
    }
    const request = parseStrictJsonBytes(bytes, {
      maxBytes: 16 * 1024 * 1024, maxDepth: 96, canonicalBytes: true, trailingNewline: "require",
    });
    if (request.packet_hash !== `sha256:${match[1]}` || request.orchestrator_nonce !== `0x${match[2]}`) {
      throw new Error("rerun signer spool filename does not bind its request");
    }
    return { bytes, request };
  } finally { closeSync(fd); }
}

function resultReady(resultRoot, board, request, submitterGid, resultReader) {
  const root = join(resultRoot, board.registry_problem_id);
  const directory = join(root, request.packet_hash.slice(7), request.orchestrator_nonce.slice(2));
  try {
    for (const name of ["transcript.json", "receipt.json"]) resultReader(join(directory, name), {
      root, expectedUid: board.rerun_uid, expectedGid: submitterGid,
    });
    return true;
  } catch (error) {
    if (["ENOENT", "ENOTDIR"].includes(error.code)) return false;
    throw error;
  }
}

export function dispatchResolverReruns(options) {
  const sourceRoot = resolve(options.sourceRoot);
  const requestRoot = resolve(options.requestRoot);
  const journalRoot = resolve(options.journalRoot);
  const resultRoot = resolve(options.resultRoot);
  const map = validateDispatchMap(options.dispatchMap ?? readCredentialJson(options.dispatchMapPath, "resolver rerun dispatch map"));
  const manager = options.manager ?? systemManager(options.systemctl, options.run);
  const resultReader = options.resultReader ?? readResolverRerunResultJsonSync;
  const authorityUid = options.authorityUid ?? 0;
  const requireCanonicalPath = options.requireCanonicalPath ?? process.platform === "linux";
  assertProtectedDirectory(sourceRoot, { uid: options.sourceUid ?? lstatSync(sourceRoot).uid, requireCanonicalPath });
  assertProtectedDirectory(requestRoot, { uid: authorityUid, gid: map.request_reader_gid, requireCanonicalPath });
  assertProtectedDirectory(journalRoot, { uid: authorityUid, requireCanonicalPath });
  const reports = [];
  const busyBoards = new Set();
  const slotRoot = join(journalRoot, "slots");
  if (!existsSync(slotRoot)) { mkdirSync(slotRoot, { mode: 0o700 }); fsyncDirectory(journalRoot); }
  assertProtectedDirectory(slotRoot, { uid: authorityUid, requireCanonicalPath });
  const names = readdirSync(sourceRoot).filter((item) => item.endsWith(".json"));
  const priority = new Map(names.map((name) => {
    try {
      const candidate = sourceRequest(join(sourceRoot, name), sourceRoot).request;
      const path = SHA256_RE.test(candidate.request_hash ?? "") ? join(journalRoot, `${candidate.request_hash.slice(7)}.json`) : "";
      const journal = path && existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : null;
      return [name, ["rotating", "dispatching", "dispatched"].includes(journal?.status) ? 0 : 1];
    } catch { return [name, 1]; }
  }));
  names.sort((left, right) => priority.get(left) - priority.get(right) || left.localeCompare(right));
  for (const name of names) {
    const sourcePath = join(sourceRoot, name);
    const { bytes, request: candidate } = sourceRequest(sourcePath, sourceRoot);
    const request = validateResolverRerunRequest(candidate, { requestSignerAddress: map.request_signer });
    const board = map.boards.find((item) => item.board_id === request.board_id);
    if (!board) throw new Error("rerun request board is not in the protected dispatch map");
    if (busyBoards.has(board.registry_problem_id)) continue;
    const boardRoot = join(requestRoot, board.registry_problem_id);
    assertProtectedDirectory(boardRoot, { uid: authorityUid, gid: map.request_reader_gid, requireCanonicalPath });
    const requestPath = join(boardRoot, "request.json");
    const journalPath = join(journalRoot, `${request.request_hash.slice(7)}.json`);
    const slotPath = join(slotRoot, `${board.registry_problem_id}.json`);
    const unit = assertUnit(`p42-resolver-rerun@${board.registry_problem_id}.service`, board.registry_problem_id);
    let journal = existsSync(journalPath) ? parseStrictJsonBytes(readFileSync(journalPath), {
      maxBytes: 1024 * 1024, maxDepth: 32, canonicalBytes: true, trailingNewline: "require",
    }) : null;
    if (journal && (journal.request_hash !== request.request_hash || journal.unit !== unit
        || journal.source_name !== name || journal.board_id !== request.board_id)) {
      throw new Error("resolver rerun dispatch journal binding conflict");
    }
    if (journal?.status === "completed") { reports.push(journal); continue; }
    if (resultReady(resultRoot, board, request, map.submitter_gid, resultReader)) {
      journal = { schema_version: "p42-resolver-rerun-dispatch/v1", status: "completed", request_hash: request.request_hash,
        request_digest: sha256(bytes), source_name: name, board_id: request.board_id, unit };
      durableReplace(journalPath, journal);
      options.crash?.("after-completion", request);
      reports.push(journal); continue;
    }
    const status = manager.status(unit);
    let slot = existsSync(slotPath) ? parseStrictJsonBytes(readFileSync(slotPath), {
      maxBytes: 1024 * 1024, maxDepth: 16, canonicalBytes: true, trailingNewline: "require",
    }) : null;
    if (status.ActiveState === "active" || status.ActiveState === "activating") {
      if (!slot || slot.request_hash !== request.request_hash
          || !journal || !["dispatching", "dispatched"].includes(journal.status)) {
        throw new Error("active rerun unit has no matching durable dispatch journal");
      }
      installExactRequest(requestPath, bytes);
      journal = { schema_version: "p42-resolver-rerun-dispatch/v1", status: "dispatched", request_hash: request.request_hash,
        request_digest: sha256(bytes), source_name: name, board_id: request.board_id, unit };
      durableReplace(journalPath, journal); busyBoards.add(board.registry_problem_id); reports.push(journal); continue;
    }
    if ((options.now ?? Date.now()) >= Date.parse(request.expires_at_utc)) {
      journal = { schema_version: "p42-resolver-rerun-dispatch/v1", status: "terminal-expired", request_hash: request.request_hash,
        request_digest: sha256(bytes), source_name: name, board_id: request.board_id, unit };
      durableReplace(journalPath, journal); reports.push(journal); continue;
    }
    if (slot?.request_hash !== request.request_hash) {
      if (slot) {
        if (!SHA256_RE.test(slot.request_hash ?? "")) throw new Error("resolver rerun board slot is malformed");
        const priorPath = join(journalRoot, `${slot.request_hash.slice(7)}.json`);
        const prior = existsSync(priorPath) ? parseStrictJsonBytes(readFileSync(priorPath), {
          maxBytes: 1024 * 1024, maxDepth: 32, canonicalBytes: true, trailingNewline: "require",
        }) : null;
        if (!prior || !["completed", "terminal-expired"].includes(prior.status)) {
          throw new Error("resolver rerun board slot cannot rotate before prior terminal durability");
        }
      } else if (existsSync(requestPath) && !readFileSync(requestPath).equals(bytes)) {
        throw new Error("resolver rerun board has unbound request bytes");
      }
      journal = { schema_version: "p42-resolver-rerun-dispatch/v1", status: "rotating", request_hash: request.request_hash,
        request_digest: sha256(bytes), source_name: name, board_id: request.board_id, unit };
      durableReplace(journalPath, journal);
      options.crash?.("after-rotation-journal", request);
      installExactRequest(requestPath, bytes, { allowReplace: Boolean(slot) });
      options.crash?.("after-install", request);
      slot = { schema_version: "p42-resolver-rerun-slot/v1", registry_problem_id: board.registry_problem_id,
        request_hash: request.request_hash, request_digest: sha256(bytes), unit };
      durableReplace(slotPath, slot);
      options.crash?.("after-slot", request);
    } else {
      installExactRequest(requestPath, bytes);
    }
    journal = { schema_version: "p42-resolver-rerun-dispatch/v1", status: "dispatching", request_hash: request.request_hash,
      request_digest: sha256(bytes), source_name: name, board_id: request.board_id, unit };
    durableReplace(journalPath, journal);
    options.crash?.("after-dispatching-journal", request);
    if (status.ActiveState === "failed") manager.resetFailed(unit);
    manager.start(unit);
    options.crash?.("after-systemctl-start", request);
    journal = { ...journal, status: "dispatched" };
    durableReplace(journalPath, journal);
    busyBoards.add(board.registry_problem_id); reports.push(journal);
  }
  return reports;
}

function arg(argv, name, fallback) {
  const index = argv.indexOf(`--${name}`);
  return index >= 0 ? argv[index + 1] : fallback;
}

export function main(argv = process.argv.slice(2)) {
  if (argv.length === 0) throw new Error("required: root-owned dispatcher paths and dispatch map credential");
  const result = dispatchResolverReruns({
    sourceRoot: arg(argv, "source-root", "/var/lib/p42/resolver-quorum-signatures/rerun-requests"),
    requestRoot: arg(argv, "request-root", "/var/lib/p42/resolver-rerun-requests"),
    journalRoot: arg(argv, "journal-root", "/var/lib/p42/resolver-rerun-dispatcher"),
    resultRoot: arg(argv, "result-root", "/var/lib/p42/resolver-rerun-results"),
    dispatchMapPath: arg(argv, "dispatch-map", "/run/credentials/p42/resolver-rerun-dispatch-map"),
  });
  process.stdout.write(`${canonicalJson({ dispatched: result })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
