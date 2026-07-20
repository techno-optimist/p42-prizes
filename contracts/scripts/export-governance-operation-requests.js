import { resolve } from "node:path";

import { readContractsArtifactJson } from "./strict-json-helper.js";
import { readGovernanceOperationJournalExact } from "./governance-operation-journal.js";
import { buildGovernanceOperationRequestsFromJournal, writeGovernanceOperationRequests } from "./governance-operation-requests.js";

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const journalPath = resolve(required("P42_GOVERNANCE_OPERATION_JOURNAL"));
const outputRoot = resolve(required("P42_GOVERNANCE_REQUEST_OUTPUT_ROOT"));
const outputPath = resolve(required("P42_GOVERNANCE_REQUEST_OUTPUT"));
const journal = readGovernanceOperationJournalExact(journalPath, required("P42_GOVERNANCE_OPERATION_JOURNAL_SHA256"));
const manifest = process.env.P42_DEPLOYMENT_MANIFEST?.trim()
  ? await readContractsArtifactJson(resolve(process.env.P42_DEPLOYMENT_MANIFEST.trim()))
  : null;
const requests = buildGovernanceOperationRequestsFromJournal(journal, { manifest });
const written = writeGovernanceOperationRequests(outputPath, outputRoot, requests);
console.log(JSON.stringify({ schema: requests.schema, requestDigest: requests.requestDigest, operationCount: requests.operationCount, output: written }));
