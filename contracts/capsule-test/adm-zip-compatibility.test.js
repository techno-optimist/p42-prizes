import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import AdmZip from "adm-zip";

const FIXED_COMPILER_ARCHIVE = Buffer.from(
  "UEsDBBQAAAgIAEyW8VwWQdWEGQAAABcAAAAiAAAAc29sanNvbi12MC44LjI0K2NvbW1pdC5lMTFiOWVkOS5qc0vLrEhNUUjOzy3IzEktUkjLrCgpLUrlAgBQSwECFAMUAAAICABMlvFcFkHVhBkAAAAXAAAAIgAAAAAAAAAAAAAApIEAAAAAc29sanNvbi12MC44LjI0K2NvbW1pdC5lMTFiOWVkOS5qc1BLBQYAAAAAAQABAFAAAABZAAAAAAA=",
  "base64",
);

test("the patched adm-zip remains compatible with Hardhat's compiler extraction API", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "p42-adm-zip-"));
  const archivePath = path.join(root, "compiler.zip");
  const targetDir = path.join(root, "compiler");

  try {
    await writeFile(archivePath, FIXED_COMPILER_ARCHIVE, { flag: "wx", mode: 0o600 });
    await mkdir(targetDir, { mode: 0o700 });

    new AdmZip(archivePath).extractAllTo(targetDir);

    assert.equal(
      await readFile(path.join(targetDir, "soljson-v0.8.24+commit.e11b9ed9.js"), "utf8"),
      "fixed compiler fixture\n",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
