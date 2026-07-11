#!/usr/bin/env node
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ethers } from "ethers";

import {
  collectCanonicalOpenWitnessLaunchEvidence,
  collectMultiBoardFinalizedReconciliation,
  instantiateBoardContracts,
  loadContractArtifacts,
  manifestProblemForRegistryId,
  stableStringify,
  validateManifestEvidence,
  writeFileAtomicSync,
} from "./indexer.mjs";
import {
  canonicalSha256,
  collectPinnedProviderQuorum,
  invariant,
  requireDigest,
  requireProviderSet,
  requireRawLaunchEvidence,
  signCollectorQuorum,
} from "./open-witness-authority-core.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

export * from "./open-witness-authority-core.mjs";

export const PRODUCTION_POLICY_PATH = "/etc/p42/open-witness-collector-policy.json";
export const PRODUCTION_POLICY_ROOT = "/etc/p42/open-witness-collector-policy.sha256";
export const PRODUCTION_SIGNING_KEY_PATH = "/etc/p42/open-witness-collector-key.pem";
const JSON_LIMITS = { maxBytes: 4 * 1024 * 1024, maxDepth: 128, canonical: false, trailingNewline: "allow-one" };

function readProtectedFile(path, { maxBytes, ascii = false }) {
  invariant(typeof constants.O_NOFOLLOW === "number" && constants.O_NOFOLLOW !== 0, "protected files require O_NOFOLLOW support");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    invariant(before.isFile(), `protected file ${path} must be regular`);
    invariant(before.uid === 0, `protected file ${path} must be root-owned`);
    invariant((before.mode & 0o222) === 0, `protected file ${path} must not be writable`);
    invariant(before.size <= maxBytes, `protected file ${path} is oversized`);
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    invariant(bytes.length === before.size && before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeMs === after.mtimeMs, `protected file ${path} changed while reading`);
    if (ascii) invariant(bytes.every((byte) => byte <= 0x7f), `protected file ${path} must be ASCII`);
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function readProductionPolicy() {
  const policy = readStrictJsonFileSync(PRODUCTION_POLICY_PATH, JSON_LIMITS);
  invariant(policy.environment === "production", "fixed collector policy must be production");
  requireProviderSet(policy, policy.rpc_endpoints.map((entry) => ({ provider_id: entry.identity })));
  const expected = readProtectedFile(PRODUCTION_POLICY_ROOT, { maxBytes: 256, ascii: true }).toString("ascii").trim();
  requireDigest(expected, "protected policy root");
  invariant(canonicalSha256(policy) === expected, "collector policy does not match protected root");
  return { policy, policyDigest: expected };
}

function digestToBytes32(value, label) {
  const digest = requireDigest(value, label);
  return `0x${digest.slice(7)}`;
}

export async function runProductionOpenWitnessCollection({ reportPath, outPath }) {
  invariant(reportPath && outPath, "required: --report <raw-launch-evidence.json> --out <collector.json>");
  const { policy, policyDigest } = readProductionPolicy();
  const manifest = readStrictJsonFileSync(policy.release_binding.manifest_path, JSON_LIMITS);
  validateManifestEvidence(manifest);
  const manifestDigest = canonicalSha256(manifest);
  invariant(manifestDigest === policy.release_binding.manifest_sha256, "deployment manifest digest does not match collector policy");
  invariant(manifest.deploymentCommit === policy.release_binding.git_commit, "deployment commit does not match collector policy");
  invariant(manifest.deploymentConfigHash === policy.release_binding.deployment_config_hash, "deployment config hash does not match collector policy");
  invariant(manifest.network.chainId === policy.network.chain_id, "deployment network does not match collector policy");
  invariant(policy.finality_confirmations >= manifest.indexer.finalityPolicy.confirmations, "collector finality cannot weaken deployment finality");

  const report = readStrictJsonFileSync(resolve(reportPath), JSON_LIMITS);
  const launchEvidenceHash = requireRawLaunchEvidence(report);
  const registryProblemId = String(report.board?.registry_problem_id ?? "");
  const submissionId = String(report.witness?.submission_id ?? "");
  const problem = manifestProblemForRegistryId(manifest, registryProblemId);
  invariant(problem.problemSlug === report.board?.slug, "collector report board does not match manifest");
  const artifacts = loadContractArtifacts();

  const quorum = await collectPinnedProviderQuorum({
    policy, policyDigest, manifestDigest, launchEvidenceHash,
    providerFactory: async (endpoint) => new ethers.JsonRpcProvider(endpoint.url, policy.network.chain_id, { staticNetwork: true }),
    collectEvidence: async ({ provider, finalityAnchorBlockNumber }) => {
      const contractsByProblem = manifest.problems.map((entry) => ({
        problem: entry, contracts: instantiateBoardContracts(provider, manifest, entry, artifacts),
      }));
      const { boards } = await collectMultiBoardFinalizedReconciliation({
        provider, contractsByProblem, artifacts, manifest,
        fromBlock: manifest.indexer.startBlock, toBlock: finalityAnchorBlockNumber,
        policy: manifest.indexer.finalityPolicy,
      });
      const board = boards.find((entry) => String(entry.problem.problemId) === registryProblemId);
      invariant(board, "collector reconciliation omitted selected board");
      return collectCanonicalOpenWitnessLaunchEvidence({
        replay: board.replay, manifest, problemId: registryProblemId, submissionId,
        transcriptHash: digestToBytes32(report.witness.transcript_hash, "report witness transcript hash"),
        reportHash: digestToBytes32(report.witness.report_hash, "report witness report hash"),
        provider, finalityAnchorBlockNumber,
      });
    },
  });

  const privateKeyBytes = readProtectedFile(PRODUCTION_SIGNING_KEY_PATH, { maxBytes: 16 * 1024 });
  const authorityEnvelope = signCollectorQuorum({
    quorum, policy, keyId: policy.authority_key_ids[0], privateKey: privateKeyBytes,
    signedAtUtc: new Date().toISOString(),
  });
  const output = { quorum, authority_envelope: authorityEnvelope };
  writeFileAtomicSync(resolve(outPath), `${stableStringify(output)}\n`);
  return output;
}

function parseArg(argv, name) {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? undefined : argv[index + 1];
}

export async function cli(argv = process.argv) {
  return runProductionOpenWitnessCollection({ reportPath: parseArg(argv, "report"), outPath: parseArg(argv, "out") });
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  cli().catch((error) => {
    console.error(`FAILED: ${error.shortMessage ?? error.message}`);
    process.exitCode = 1;
  });
}
