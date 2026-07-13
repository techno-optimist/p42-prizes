#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const UPSTREAM_REPOSITORY = "https://github.com/techno-optimist/erdos-frontier-atlas";
export const UPSTREAM_COMMIT = "f2db29d0c47b61caad80b1a70e68e9702260f5e0";
export const UPSTREAM_PATH = "atlas/problems.json";
export const UPSTREAM_SHA256 = "a0a7236cde326d57251209f1c8c0e2fb91a18c29747e408a73d2737a506e15c6";
export const UPSTREAM_RAW_URL = `https://raw.githubusercontent.com/techno-optimist/erdos-frontier-atlas/${UPSTREAM_COMMIT}/${UPSTREAM_PATH}`;

const outputPath = fileURLToPath(
  new URL("../web/src/data/erdos-frontier-atlas.v1.json", import.meta.url),
);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function buildSnapshot(sourceBytes) {
  const digest = sha256(sourceBytes);
  if (digest !== UPSTREAM_SHA256) {
    throw new Error(`upstream SHA-256 mismatch: expected ${UPSTREAM_SHA256}, received ${digest}`);
  }

  const source = JSON.parse(sourceBytes.toString("utf8"));
  if (!Array.isArray(source.problems) || source.problems.length !== 51) {
    throw new Error(`expected exactly 51 atlas entries, received ${source.problems?.length ?? "invalid"}`);
  }
  if (new Set(source.problems.map((problem) => problem.id)).size !== source.problems.length) {
    throw new Error("atlas contains duplicate Erdős ids");
  }
  if (source.counts?.total !== source.problems.length) {
    throw new Error("upstream declared count does not match its entries");
  }

  return {
    snapshot_schema: "p42-erdos-frontier-atlas-v1",
    provenance: {
      repository: UPSTREAM_REPOSITORY,
      commit: UPSTREAM_COMMIT,
      source_path: UPSTREAM_PATH,
      source_sha256: UPSTREAM_SHA256,
      license: "MIT",
      attribution: "Copyright (c) 2026 Kevin Russell",
    },
    ...source,
  };
}

async function loadSource() {
  const sourceFlag = process.argv.indexOf("--source");
  if (sourceFlag !== -1) {
    const filename = process.argv[sourceFlag + 1];
    if (!filename) throw new Error("--source requires a file path");
    return readFile(path.resolve(filename));
  }

  const response = await fetch(UPSTREAM_RAW_URL, { redirect: "error" });
  if (!response.ok) throw new Error(`upstream fetch failed with HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const snapshot = buildSnapshot(await loadSource());
  await writeFile(outputPath, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
  console.log(`wrote ${snapshot.problems.length} entries to ${outputPath}`);
}
