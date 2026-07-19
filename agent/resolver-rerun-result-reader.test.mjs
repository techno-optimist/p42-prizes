import assert from "node:assert/strict";
import {
  chmodSync, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync,
  readSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readResolverRerunResultJsonSync } from "./resolver-rerun-result-reader.mjs";

const RERUN_UID = 42002;
const SUBMITTER_GID = 42042;

function projected(metadata, overrides = {}) {
  return new Proxy(metadata, {
    get(target, property) {
      if (property === "uid") return overrides.uid ?? RERUN_UID;
      if (property === "gid") return overrides.gid ?? SUBMITTER_GID;
      if (Object.hasOwn(overrides, property)) return overrides[property];
      return Reflect.get(target, property, target);
    },
  });
}

function projectedIo(overrides = {}) {
  const descriptors = new Map();
  return {
    readSync,
    openSync(path, flags, mode) {
      const match = String(path).match(/^\/dev\/fd\/(\d+)\/(.+)$/);
      const resolved = match ? join(descriptors.get(Number(match[1])), match[2]) : path;
      const fd = openSync(resolved, flags, mode);
      descriptors.set(fd, String(resolved));
      return fd;
    },
    fstatSync(fd) { return projected(fstatSync(fd), overrides); },
    lstatSync(path) { return projected(lstatSync(path), overrides); },
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "p42-rerun-cross-uid-"));
  const directory = join(root, "a".repeat(64), "b".repeat(64));
  mkdirSync(directory, { recursive: true, mode: 0o750 });
  chmodSync(root, 0o750);
  chmodSync(join(root, "a".repeat(64)), 0o750);
  chmodSync(directory, 0o750);
  const path = join(directory, "receipt.json");
  writeFileSync(path, "{\"ok\":true}\n", { mode: 0o640 });
  chmodSync(path, 0o640);
  return { root, path };
}

test("cross-UID result reader accepts only the pinned rerun UID and submitter group", () => {
  const value = fixture();
  try {
    assert.deepEqual(readResolverRerunResultJsonSync(value.path, {
      root: value.root, expectedUid: RERUN_UID, expectedGid: SUBMITTER_GID,
      io: projectedIo(),
    }), { ok: true });
    assert.throws(() => readResolverRerunResultJsonSync(value.path, {
      root: value.root, expectedUid: RERUN_UID + 1, expectedGid: SUBMITTER_GID,
      io: projectedIo(),
    }), /ancestor authority mismatch/);
    assert.throws(() => readResolverRerunResultJsonSync(value.path, {
      root: value.root, expectedUid: RERUN_UID, expectedGid: SUBMITTER_GID + 1,
      io: projectedIo(),
    }), /ancestor authority mismatch/);
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("cross-UID result reader rejects permissive modes and symlink substitution", () => {
  const value = fixture();
  try {
    chmodSync(value.path, 0o660);
    assert.throws(() => readResolverRerunResultJsonSync(value.path, {
      root: value.root, expectedUid: RERUN_UID, expectedGid: SUBMITTER_GID, io: projectedIo(),
    }), /file authority mismatch/);
    rmSync(value.path);
    const target = join(value.root, "target.json");
    writeFileSync(target, "{\"ok\":true}\n", { mode: 0o640 });
    symlinkSync(target, value.path);
    assert.throws(() => readResolverRerunResultJsonSync(value.path, {
      root: value.root, expectedUid: RERUN_UID, expectedGid: SUBMITTER_GID, io: projectedIo(),
    }), /ELOOP|file authority mismatch/);
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("cross-UID result reader rejects inode drift during the read", () => {
  const value = fixture();
  let targetStats = 0;
  try {
    const io = projectedIo();
    io.lstatSync = (path) => {
      const metadata = lstatSync(path);
      if (path === value.path && ++targetStats === 2) return projected(metadata, { ino: metadata.ino + 1 });
      return projected(metadata);
    };
    assert.throws(() => readResolverRerunResultJsonSync(value.path, {
      root: value.root, expectedUid: RERUN_UID, expectedGid: SUBMITTER_GID, io,
    }), /changed during read/);
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});
