import assert from "node:assert/strict";
import {
  mkdtemp,
  open as openFile,
  readFile,
  rename as renameFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";

import { writeReconciliationReportAtomic } from "../scripts/reconciliation-helper.js";

async function assertOldJsonPreserved(path, expectedBytes) {
  const actualBytes = await readFile(path, "utf8");
  assert.equal(actualBytes, expectedBytes);
  assert.deepEqual(JSON.parse(actualBytes), JSON.parse(expectedBytes));
}

function instrumentHandle(handle, syncEvent, events) {
  return {
    writeFile(...args) {
      events.push("write");
      return handle.writeFile(...args);
    },
    sync() {
      events.push(syncEvent);
      return handle.sync();
    },
    close() {
      return handle.close();
    },
  };
}

describe("reconciliation report atomic publication", () => {
  it("fsyncs before and after an atomic same-directory rename with private permissions", async () => {
    const root = await mkdtemp(join(tmpdir(), "p42-reconciliation-atomic-success-"));
    const outputPath = join(root, "private", "latest.json");
    const events = [];
    let temporaryPath;

    try {
      await writeReconciliationReportAtomic(outputPath, { generation: "new" }, {
        async open(path, flags, mode) {
          const handle = await openFile(path, flags, mode);
          if (flags === "wx") {
            temporaryPath = path;
            return instrumentHandle(handle, "file-fsync", events);
          }
          return instrumentHandle(handle, "directory-fsync", events);
        },
        async rename(from, to) {
          events.push("rename");
          await renameFile(from, to);
        },
      });

      assert.equal(dirname(temporaryPath), dirname(outputPath));
      assert.deepEqual(events, ["write", "file-fsync", "rename", "directory-fsync"]);
      assert.deepEqual(JSON.parse(await readFile(outputPath, "utf8")), { generation: "new" });
      assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
      assert.equal((await stat(dirname(outputPath))).mode & 0o777, 0o700);
      await assert.rejects(() => stat(temporaryPath), { code: "ENOENT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("removes a truncated temp file and preserves the previous JSON when writing is interrupted", async () => {
    const root = await mkdtemp(join(tmpdir(), "p42-reconciliation-atomic-write-failure-"));
    const outputPath = join(root, "latest.json");
    const previousBytes = '{"generation":"previous","valid":true}\n';
    let temporaryPath;
    await writeFile(outputPath, previousBytes);

    try {
      await assert.rejects(
        () => writeReconciliationReportAtomic(
          outputPath,
          { generation: "replacement", valid: true },
          {
            async open(path, flags, mode) {
              const handle = await openFile(path, flags, mode);
              if (flags !== "wx") return handle;
              temporaryPath = path;
              return {
                async writeFile() {
                  await handle.writeFile('{"generation":');
                  throw new Error("simulated interrupted write");
                },
                sync() {
                  return handle.sync();
                },
                close() {
                  return handle.close();
                },
              };
            },
          },
        ),
        /simulated interrupted write/,
      );

      await assertOldJsonPreserved(outputPath, previousBytes);
      await assert.rejects(() => stat(temporaryPath), { code: "ENOENT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("removes a complete temp file and preserves the previous JSON when rename is interrupted", async () => {
    const root = await mkdtemp(join(tmpdir(), "p42-reconciliation-atomic-rename-failure-"));
    const outputPath = join(root, "latest.json");
    const previousBytes = '{"generation":"previous","valid":true}\n';
    let temporaryPath;
    await writeFile(outputPath, previousBytes);

    try {
      await assert.rejects(
        () => writeReconciliationReportAtomic(
          outputPath,
          { generation: "replacement", valid: true },
          {
            async rename(from) {
              temporaryPath = from;
              throw new Error("simulated interrupted rename");
            },
          },
        ),
        /simulated interrupted rename/,
      );

      await assertOldJsonPreserved(outputPath, previousBytes);
      await assert.rejects(() => stat(temporaryPath), { code: "ENOENT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
