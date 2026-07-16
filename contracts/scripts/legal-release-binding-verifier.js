import { readFileSync } from "node:fs";

import { parseStrictJsonBytes } from "../../agent/strict-json.mjs";
import {
  immutableValuesFromConstructor,
  reconstructExpectedRuntime,
  validateReleaseCapsule,
} from "./release-capsule-helper.js";

const MAX_CAPSULE_BYTES = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_PROJECTION_BYTES = 16 * 1024 * 1024;
const SHARED = [
  ["timelock", "P42MultisigTimelock"],
  ["registry", "P42ProblemRegistry"],
  ["rolloverVault", "P42RolloverVault"],
  ["submissionManagerFactory", "P42SubmissionManagerFactory"],
  ["challengeManagerFactory", "P42ChallengeManagerFactory"],
  ["objectiveVerifier", "P42SP1VerifierGateway"],
  ["resolverQuorum", "P42ResolverQuorum"],
];
const PER_BOARD = [
  ["pool", "P42BountyPool"],
  ["ledger", "P42PayoutLedger"],
  ["submissions", "P42SubmissionManager"],
  ["challenges", "P42ChallengeManager"],
];

function readJsonFd(value, maxBytes, label) {
  if (!/^[0-9]+$/.test(value ?? "")) throw new Error(`${label} descriptor is invalid`);
  const bytes = readFileSync(Number(value));
  return parseStrictJsonBytes(bytes, { maxBytes, maxDepth: 256, trailingNewline: "allow" });
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const missing = keys.filter((key) => !Object.hasOwn(value, key));
  const extra = Object.keys(value).filter((key) => !keys.includes(key));
  if (missing.length || extra.length) throw new Error(`${label} keys mismatch`);
}

function descriptors(manifest) {
  const result = SHARED.map(([key, name]) => ({ path: `shared.${key}`, name, entry: manifest.contracts?.[key] }));
  if (!Array.isArray(manifest.problems) || manifest.problems.length !== 10) throw new Error("manifest must contain exact-ten boards");
  manifest.problems.forEach((problem, index) => {
    if (String(problem?.problemId) !== String(index + 1)) throw new Error(`manifest board ${index + 1} is out of canonical order`);
    for (const [key, name] of PER_BOARD) result.push({ path: `board.${index + 1}.${key}`, name, entry: problem.contracts?.[key] });
  });
  return result;
}

function main() {
  const capsule = readJsonFd(process.argv[2], MAX_CAPSULE_BYTES, "capsule");
  const manifest = readJsonFd(process.argv[3], MAX_MANIFEST_BYTES, "manifest");
  const projection = readJsonFd(process.argv[4], MAX_PROJECTION_BYTES, "projection");
  exactKeys(projection, ["deploymentCommit", "contracts"], "projection");
  validateReleaseCapsule(capsule);
  if (capsule.gitCommit !== projection.deploymentCommit || manifest.deploymentCommit !== projection.deploymentCommit) throw new Error("capsule and manifest gitCommit binding mismatch");
  if (manifest.releaseEvidence?.capsuleDigest !== capsule.capsuleDigest) throw new Error("manifest releaseEvidence.capsuleDigest mismatch");
  if (!Array.isArray(projection.contracts) || projection.contracts.length !== 47) throw new Error("projection must contain exactly 47 contracts");

  const artifacts = new Map(capsule.contracts.map((contract) => [contract.name, contract]));
  const buildInfos = new Map(capsule.buildInfos.map((info) => [info.id, info]));
  const projected = new Map(projection.contracts.map((contract) => [contract.topologyKey, contract]));
  if (projected.size !== 47) throw new Error("projection contains duplicate topology keys");
  for (const descriptor of descriptors(manifest)) {
    const row = projected.get(descriptor.path);
    const entry = descriptor.entry;
    const artifact = artifacts.get(descriptor.name);
    const buildInfo = buildInfos.get(artifact?.buildInfoId);
    exactKeys(row, ["topologyKey", "name", "sourceBase64", "runtimeHex", "runtimeKeccak"], descriptor.path);
    if (!entry || entry.name !== descriptor.name || row.name !== descriptor.name) throw new Error(`${descriptor.path} contract name mismatch`);
    if (!artifact || !buildInfo || entry.capsuleArtifactDigest !== artifact.artifactDigest) throw new Error(`${descriptor.path} capsule artifact digest mismatch`);
    const source = buildInfo.input?.input?.sources?.[`project/${artifact.sourceName}`]?.content;
    if (typeof source !== "string" || !Buffer.from(row.sourceBase64, "base64").equals(Buffer.from(source, "utf8"))) throw new Error(`${descriptor.path} source bytes differ from canonical capsule build input`);
    const values = immutableValuesFromConstructor(artifact, entry.constructorArgs, { blockTimestamp: entry.deploymentBlockTimestamp });
    const expectedRuntime = reconstructExpectedRuntime(artifact, values);
    if (row.runtimeHex !== expectedRuntime) throw new Error(`${descriptor.path} deployed runtime differs from capsule reconstruction`);
    for (const field of ["runtimeCodeHash", "deployedCodeHash", "expectedRuntimeCodeHash", "primaryObservedRuntimeCodeHash", "secondaryObservedRuntimeCodeHash"]) {
      if (entry[field]?.toLowerCase() !== row.runtimeKeccak) throw new Error(`${descriptor.path}.${field} differs from chain-verified runtime Keccak`);
    }
  }
  if ([...projected.keys()].some((key) => !descriptors(manifest).some(({ path }) => path === key))) throw new Error("projection contains an unknown topology key");
  process.stdout.write("OK\n");
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error?.message ?? error}\n`);
  process.exitCode = 1;
}
