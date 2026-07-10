import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canonicalJson, canonicalRational, hashVerdictReport, serializeVerdictReport, verdictReport } from "./p42-v1.mjs";

const corpus = JSON.parse(readFileSync(new URL("./p42-v1-corpus.json", import.meta.url), "utf8"));
const output = corpus.cases.map(({ name, report }) => ({ name, canonical: serializeVerdictReport(report), hash: hashVerdictReport(report) }));
for (const fixture of corpus.fixtures) {
  const report = JSON.parse(readFileSync(new URL(`../${fixture}`, import.meta.url), "utf8"));
  output.push({ name: `fixture:${fixture}`, canonical: serializeVerdictReport(report), hash: hashVerdictReport(report) });
}
for (const literal of corpus.reject_rationals) assert.throws(() => canonicalRational(literal));

const base = corpus.cases[0].report;
for (const { kind } of corpus.reject_reports) {
  const candidate = structuredClone(base);
  if (kind === "extra-field") candidate.unregistered = true;
  if (kind === "missing-field") delete candidate.reason;
  if (kind === "bad-hash") candidate.solution_hash = "sha256:ABC";
  if (kind === "numeric-valid") candidate.valid = 1;
  assert.throws(() => verdictReport(candidate));
}
assert.throws(() => canonicalJson({ unsafe: Number.MAX_SAFE_INTEGER + 1 }));
assert.throws(() => canonicalJson({ nonfinite: Infinity }));
assert.throws(() => canonicalJson({ absent: undefined }));

process.stdout.write(`${JSON.stringify(output)}\n`);
