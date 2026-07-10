import assert from "node:assert/strict";
import {
  existsSync,
  fsyncSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";

import { writeFileAtomicSync } from "./indexer.mjs";

function assertOldJsonPreserved(path, expectedBytes) {
  const actualBytes = readFileSync(path, "utf8");
  assert.equal(actualBytes, expectedBytes);
  assert.deepEqual(JSON.parse(actualBytes), JSON.parse(expectedBytes));
}

describe("indexer atomic publication", () => {
  it("fsyncs before and after an atomic same-directory rename with private permissions", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-atomic-success-"));
    const outputPath = join(root, "private", "checkpoint.json");
    const events = [];
    let temporaryPath;
    let renamed = false;

    try {
      writeFileAtomicSync(outputPath, '{"generation":"new"}\n', {
        openSync(path, flags, mode) {
          if (flags === "wx") temporaryPath = path;
          return openSync(path, flags, mode);
        },
        writeFileSync(descriptor, data) {
          events.push("write");
          return writeFileSync(descriptor, data);
        },
        fsyncSync(descriptor) {
          events.push(renamed ? "directory-fsync" : "file-fsync");
          return fsyncSync(descriptor);
        },
        renameSync(from, to) {
          events.push("rename");
          renameSync(from, to);
          renamed = true;
        },
      });

      assert.equal(dirname(temporaryPath), dirname(outputPath));
      assert.deepEqual(events, ["write", "file-fsync", "rename", "directory-fsync"]);
      assert.equal(readFileSync(outputPath, "utf8"), '{"generation":"new"}\n');
      assert.equal(statSync(outputPath).mode & 0o777, 0o600);
      assert.equal(statSync(dirname(outputPath)).mode & 0o777, 0o700);
      assert.equal(existsSync(temporaryPath), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("removes a truncated temp file and preserves the previous JSON when writing is interrupted", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-atomic-write-failure-"));
    const outputPath = join(root, "checkpoint.json");
    const previousBytes = '{"generation":"previous","valid":true}\n';
    let temporaryPath;
    writeFileSync(outputPath, previousBytes);

    try {
      assert.throws(
        () => writeFileAtomicSync(outputPath, '{"generation":"replacement","valid":true}\n', {
          openSync(path, flags, mode) {
            if (flags === "wx") temporaryPath = path;
            return openSync(path, flags, mode);
          },
          writeFileSync(descriptor) {
            writeFileSync(descriptor, '{"generation":');
            throw new Error("simulated interrupted write");
          },
        }),
        /simulated interrupted write/,
      );

      assertOldJsonPreserved(outputPath, previousBytes);
      assert.equal(existsSync(temporaryPath), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("removes a complete temp file and preserves the previous JSON when rename is interrupted", () => {
    const root = mkdtempSync(join(tmpdir(), "p42-indexer-atomic-rename-failure-"));
    const outputPath = join(root, "checkpoint.json");
    const previousBytes = '{"generation":"previous","valid":true}\n';
    let temporaryPath;
    writeFileSync(outputPath, previousBytes);

    try {
      assert.throws(
        () => writeFileAtomicSync(outputPath, '{"generation":"replacement","valid":true}\n', {
          renameSync(from) {
            temporaryPath = from;
            throw new Error("simulated interrupted rename");
          },
        }),
        /simulated interrupted rename/,
      );

      assertOldJsonPreserved(outputPath, previousBytes);
      assert.equal(existsSync(temporaryPath), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
