#!/usr/bin/env node

import { fstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateMultiBoardCheckpoint } from "./indexer.mjs";
import { parseStrictJsonBytes } from "./strict-json.mjs";

const MAX_CHECKPOINT_BYTES = 32 * 1024 * 1024;

export function validateCheckpointDescriptor(descriptor) {
  if (!Number.isSafeInteger(descriptor) || descriptor < 0) throw new Error("checkpoint descriptor is invalid");
  const metadata = fstatSync(descriptor);
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_CHECKPOINT_BYTES) {
    throw new Error("checkpoint descriptor must be a bounded regular file");
  }
  const checkpoint = parseStrictJsonBytes(readFileSync(descriptor), {
    maxBytes: MAX_CHECKPOINT_BYTES,
    maxDepth: 96,
  });
  if (checkpoint.schema !== "p42-prizes/indexer-checkpoint/v3") {
    throw new Error("independent portal replay requires checkpoint v3");
  }
  validateMultiBoardCheckpoint(checkpoint);
  return { ok: true, schema: checkpoint.schema, boards: checkpoint.boards.length };
}

if (fileURLToPath(import.meta.url) === resolve(process.argv[1] ?? "")) {
  try {
    const result = validateCheckpointDescriptor(Number(process.argv[2]));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
