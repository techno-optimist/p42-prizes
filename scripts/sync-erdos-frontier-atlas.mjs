#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const UPSTREAM_REPOSITORY = "https://github.com/techno-optimist/erdos-frontier-atlas";
export const UPSTREAM_COMMIT = "49e70f25e4bab48969293059cb9c95674de2aec0";
export const UPSTREAM_PATH = "atlas/problems.json";
export const UPSTREAM_SHA256 = "ed1148db84bf33d9d3beb0f5cba24e9a84dfd30314527fc800a57bc291d08e80";
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
  if (source.atlas_version !== "0.2.0" || source.generated !== "2026-07-13") {
    throw new Error("upstream Atlas release identity changed without review");
  }
  const erdos552 = source.problems.find((problem) => problem.id === 552);
  if (erdos552?.evidence?.digest !== "sha256:6fad85db5cc5925f5a5894446c56720433065652fecb284a1340262a70a914d3") {
    throw new Error("Erdős 552 certificate digest is missing or changed");
  }
  const coverage = erdos552?.compute?.coverage;
  if (erdos552?.compute?.schema !== "p42-atlas-compute-v1" || !Array.isArray(coverage)
      || !coverage.some((record) => record.axis === "n" && record.start === 12 && record.end === 16 && record.status === "CERTIFIED")
      || !coverage.some((record) => record.axis === "m" && record.start === 21 && record.end === 21
        && record.status === "CERTIFIED" && record.where?.n === 17)
      || !coverage.some((record) => record.axis === "m" && record.start === 22 && record.end === 22
        && record.status === "EXCLUDED" && record.where?.n === 17)
      || erdos552?.p42_slug !== "c4-star-ramsey-a17") {
    throw new Error("Erdős 552 structured compute coverage is missing or changed");
  }
  const erdos86 = source.problems.find((problem) => problem.id === 86);
  if (erdos86?.p42_slug !== "hypercube-q7-c4-free") {
    throw new Error("Erdős 86 P42 package join is missing or changed");
  }
  for (const problem of source.problems) {
    const records = problem.compute?.coverage;
    if (!Array.isArray(records)) continue;
    const byAxis = new Map();
    for (const record of records) {
      if (typeof record?.axis !== "string" || !Number.isSafeInteger(record.start)
          || !Number.isSafeInteger(record.end) || record.start > record.end) {
        throw new Error(`Erdős ${problem.id} has malformed compute coverage`);
      }
      if (record.where !== undefined && (typeof record.where !== "object" || record.where === null
          || Array.isArray(record.where) || Object.keys(record.where).length === 0
          || Object.values(record.where).some((value) => value !== null && typeof value !== "string"
            && typeof value !== "boolean" && !Number.isSafeInteger(value)))) {
        throw new Error(`Erdős ${problem.id} has malformed compute coverage constraints`);
      }
      const axisRecords = byAxis.get(record.axis) ?? [];
      axisRecords.push(record);
      byAxis.set(record.axis, axisRecords);
    }
    for (const [axis, axisRecords] of byAxis) {
      axisRecords.sort((left, right) => left.start - right.start || left.end - right.end);
      for (let index = 1; index < axisRecords.length; index += 1) {
        if (axisRecords[index].start <= axisRecords[index - 1].end) {
          throw new Error(`Erdős ${problem.id} has overlapping compute coverage on ${axis}`);
        }
      }
    }
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
