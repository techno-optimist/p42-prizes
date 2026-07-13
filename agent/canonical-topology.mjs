import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

const EXPECTED_TOPOLOGY_SHA256 = "da65af31893048996fcd89532b1c680fe4e98bbb397dc54210a2660f7b9ede18";
const protocolUrl = new URL("../protocol/canonical-topology-v1.json", import.meta.url);
const packagedUrl = new URL("./canonical-topology-v1.json", import.meta.url);
const sourceUrl = existsSync(protocolUrl) ? protocolUrl : packagedUrl;
const sourceBytes = readFileSync(sourceUrl);
if (createHash("sha256").update(sourceBytes).digest("hex") !== EXPECTED_TOPOLOGY_SHA256) {
  throw new Error("canonical topology authority digest mismatch");
}
const source = JSON.parse(sourceBytes.toString("utf8"));
if (source.schema !== "p42-prizes/canonical-contract-topology/v1") throw new Error("canonical topology schema mismatch");
if (!Number.isInteger(source.boardCount) || source.boardCount <= 0) throw new Error("canonical topology board count is invalid");
for (const [label, rows] of [["shared", source.shared], ["perBoard", source.perBoard]]) {
  if (!Array.isArray(rows) || rows.length === 0) throw new Error(`canonical topology ${label} is empty`);
  if (new Set(rows.map(({ key }) => key)).size !== rows.length || rows.some(({ key, name }) => !key || !name)) {
    throw new Error(`canonical topology ${label} contains duplicate or incomplete descriptors`);
  }
}

export const CANONICAL_TOPOLOGY_SCHEMA = source.schema;
export const CANONICAL_BOARD_COUNT = source.boardCount;
export const CANONICAL_SHARED_CONTRACTS = Object.freeze(source.shared.map(Object.freeze));
export const CANONICAL_BOARD_CONTRACTS = Object.freeze(source.perBoard.map(Object.freeze));
export const CANONICAL_CONTRACT_COUNT = CANONICAL_SHARED_CONTRACTS.length
  + CANONICAL_BOARD_COUNT * CANONICAL_BOARD_CONTRACTS.length;

if (CANONICAL_CONTRACT_COUNT !== 47) throw new Error("canonical topology must contain exactly 47 contracts");

export function canonicalTopologyDescriptors(boardCount = CANONICAL_BOARD_COUNT) {
  if (boardCount !== CANONICAL_BOARD_COUNT) throw new Error(`canonical topology requires exactly ${CANONICAL_BOARD_COUNT} boards`);
  return [
    ...CANONICAL_SHARED_CONTRACTS.map(({ key, name }) => ({ id: key, path: `contracts.${key}`, key, name, scope: "shared" })),
    ...Array.from({ length: boardCount }, (_, index) => index + 1).flatMap((problemId) => (
      CANONICAL_BOARD_CONTRACTS.map(({ key, name }) => ({
        id: `board-${problemId}-${key}`,
        path: `problems[${problemId - 1}].contracts.${key}`,
        key,
        name,
        problemId,
        scope: "board",
      }))
    )),
  ];
}

export function assertCanonicalDeploymentPlan(definitions, boardCount = CANONICAL_BOARD_COUNT) {
  const wanted = canonicalTopologyDescriptors(boardCount);
  const actual = definitions.map(({ id, name }) => ({ id, name }));
  const expected = wanted.map(({ id, name }) => ({ id, name }));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    const actualIds = new Set(actual.map(({ id }) => id));
    const expectedIds = new Set(expected.map(({ id }) => id));
    const missing = expected.filter(({ id }) => !actualIds.has(id)).map(({ id }) => id);
    const unexpected = actual.filter(({ id }) => !expectedIds.has(id)).map(({ id }) => id);
    throw new Error(
      `production deployment plan does not materialize canonical ${CANONICAL_CONTRACT_COUNT}-contract topology; `
      + `missing=${missing.join(",") || "none"}; unexpected=${unexpected.join(",") || "none"}`,
    );
  }
  return wanted;
}

export function assertCanonicalManifestTopology(manifest) {
  const problems = manifest?.problems;
  if (!Array.isArray(problems) || problems.length !== CANONICAL_BOARD_COUNT) {
    throw new Error("canonical manifest topology requires exactly ten boards");
  }
  const sharedKeys = Object.keys(manifest?.contracts ?? {});
  const expectedSharedKeys = CANONICAL_SHARED_CONTRACTS.map(({ key }) => key);
  if (JSON.stringify(sharedKeys) !== JSON.stringify(expectedSharedKeys)) {
    throw new Error("canonical manifest topology requires the exact seven ordered shared contracts");
  }
  const addresses = [];
  for (const [index, problem] of problems.entries()) {
    if (String(problem?.problemId) !== String(index + 1)) throw new Error("canonical manifest topology requires ordered problem ids 1 through 10");
    const boardKeys = Object.keys(problem?.contracts ?? {});
    const expectedBoardKeys = CANONICAL_BOARD_CONTRACTS.map(({ key }) => key);
    if (JSON.stringify(boardKeys) !== JSON.stringify(expectedBoardKeys)) {
      throw new Error(`canonical manifest topology requires exact ordered board contracts for problem ${index + 1}`);
    }
    addresses.push(...boardKeys.map((key) => problem.contracts[key]?.address));
  }
  addresses.unshift(...sharedKeys.map((key) => manifest.contracts[key]?.address));
  if (addresses.some((address) => !/^0x[0-9a-fA-F]{40}$/.test(address ?? ""))
      || new Set(addresses.map((address) => address.toLowerCase())).size !== CANONICAL_CONTRACT_COUNT) {
    throw new Error(`canonical manifest topology requires ${CANONICAL_CONTRACT_COUNT} unique contract addresses`);
  }
  return canonicalTopologyDescriptors();
}
