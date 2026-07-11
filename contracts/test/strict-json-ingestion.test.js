import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { readManifestOutputReservation } from "../scripts/deployment-ceremony-helper.js";
import { loadManifestFromPath } from "../scripts/reconciliation-helper.js";
import {
  readContractsArtifactJson,
  readContractsConfigJson,
  readContractsConfigJsonSync,
} from "../scripts/strict-json-helper.js";

async function withTempDirectory(prefix, callback) {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  try {
    await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("contracts strict JSON ingestion", () => {
  it("rejects duplicate and prototype-mutating object keys", async () => {
    await withTempDirectory("p42-strict-json-keys-", async (directory) => {
      for (const [name, bytes, pattern] of [
        ["duplicate.json", '{"schema":"first","schema":"second"}', /duplicate object key "schema"/],
        ["proto.json", '{"nested":{"__proto__":{}}}', /forbidden object key "__proto__"/],
        ["constructor.json", '{"constructor":null}', /forbidden object key "constructor"/],
      ]) {
        const path = join(directory, name);
        await writeFile(path, bytes);
        await assert.rejects(() => readContractsConfigJson(path), pattern);
      }
    });
  });

  it("rejects unsafe, rounded, deeply nested, oversized, and invalid UTF-8 inputs", async () => {
    await withTempDirectory("p42-strict-json-bounds-", async (directory) => {
      const cases = [
        ["unsafe.json", '{"value":9007199254740992}', /outside the safe numeric range/],
        ["rounded.json", '{"value":1.0000000000000001}', /decimal-round-trip stable/],
        ["deep.json", `${"[".repeat(65)}null${"]".repeat(65)}`, /exceeds maxDepth \(64\)/],
      ];
      for (const [name, bytes, pattern] of cases) {
        const path = join(directory, name);
        await writeFile(path, bytes);
        await assert.rejects(() => readContractsConfigJson(path), pattern);
      }

      const oversized = join(directory, "oversized.json");
      await writeFile(oversized, `"${"x".repeat(1024 * 1024)}"`);
      await assert.rejects(() => readContractsConfigJson(oversized), /exceeds maxBytes \(1048576\)/);

      const invalidUtf8 = join(directory, "invalid-utf8.json");
      await writeFile(invalidUtf8, Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]));
      assert.throws(() => readContractsConfigJsonSync(invalidUtf8), /not valid UTF-8/);
    });
  });

  it("uses no-follow regular-file reads and requires one LF on generated artifacts", async () => {
    await withTempDirectory("p42-strict-json-files-", async (directory) => {
      const target = join(directory, "target.json");
      const link = join(directory, "link.json");
      const subdirectory = join(directory, "directory.json");
      await writeFile(target, '{"ok":true}\n');
      await symlink(target, link);
      await mkdir(subdirectory);

      await assert.rejects(() => readContractsArtifactJson(link), (error) =>
        error?.code === "ELOOP" || /symbolic link/i.test(error?.message));
      await assert.rejects(() => readContractsArtifactJson(subdirectory), /regular file/);
      await assert.rejects(
        () => readContractsArtifactJson(join(directory, "missing.json")),
        { code: "ENOENT" },
      );

      await assert.doesNotReject(() => readContractsArtifactJson(target));
      await writeFile(target, '{"ok":true}');
      await assert.rejects(() => readContractsArtifactJson(target), /exactly one LF trailing newline/);
      await writeFile(target, '{"ok":true}\n\n');
      await assert.rejects(() => readContractsArtifactJson(target), /exactly one LF trailing newline/);
    });
  });

  it("applies strict artifact policy through reconciliation and reservation loaders", async () => {
    await withTempDirectory("p42-strict-json-loaders-", async (directory) => {
      const manifest = join(directory, "manifest.json");
      await writeFile(manifest, '{"schema":"first","schema":"second"}\n');
      await assert.rejects(
        () => loadManifestFromPath(manifest),
        /Unable to read deployment manifest.*duplicate object key "schema"/,
      );

      const output = join(directory, "deployment.json");
      const reservation = `${output}.deployment-reservation.json`;
      await writeFile(reservation, '{"schema":"p42-prizes/deployment-reservation/v1"}');
      await assert.rejects(
        () => readManifestOutputReservation(output),
        /Could not read deployment reservation.*exactly one LF trailing newline/,
      );
    });
  });
});
