#!/usr/bin/env node
import { fstatSync, readFileSync } from "node:fs";
import { parseStrictJsonBytes } from "../../agent/strict-json.mjs";
import { validateExplorerVerificationDossier } from "./explorer-verification-helper.js";

const [manifestFd, capsuleFd, dossierFd, operatorsJson, validationTime] = process.argv.slice(2);
if (![manifestFd, capsuleFd, dossierFd, operatorsJson, validationTime].every(Boolean)) {
  throw new Error("usage: validate-launch-explorer-evidence manifest-fd capsule-fd dossier-fd operators-json validation-time-ms");
}
function readInheritedJson(descriptorText, label) {
  const descriptor = Number(descriptorText);
  if (!Number.isSafeInteger(descriptor) || descriptor < 3) throw new Error(`${label} descriptor is invalid`);
  const stat = fstatSync(descriptor);
  if (!stat.isFile() || stat.size > 128 * 1024 * 1024) throw new Error(`${label} snapshot must be a bounded regular file`);
  const bytes = readFileSync(descriptor);
  if (bytes.length !== stat.size) throw new Error(`${label} snapshot was not read exactly`);
  return parseStrictJsonBytes(bytes, { maxBytes: 128 * 1024 * 1024, maxDepth: 256, trailingNewline: "allow" });
}
const manifest = readInheritedJson(manifestFd, "manifest");
const capsule = readInheritedJson(capsuleFd, "capsule");
const dossier = readInheritedJson(dossierFd, "dossier");
const trustedOperators = JSON.parse(operatorsJson);
validateExplorerVerificationDossier(dossier, {
  manifest,
  capsule,
  trustedOperators,
  now: Number(validationTime),
  futureSkewMs: 0,
});
process.stdout.write("OK\n");
