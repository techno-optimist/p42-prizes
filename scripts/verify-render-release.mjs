#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

const execFileAsync = promisify(execFile);

// Render builds from web/. A commit limited to protocol docs or release tooling
// should not force a no-op portal deployment, but any portal or service-config
// change must be present in the live deployment's ancestry.
export const DEPLOY_RELEVANT_PATHS = Object.freeze(["web", "render.yaml"]);

const DEFAULTS = Object.freeze({
  branch: "main",
  gitRemote: "origin",
  publicOrigin: "https://projectforty2.ai",
  renderOrigin: "https://p42-prizes.onrender.com",
  serviceId: "srv-d96pokeq1p3s73foqk60",
});

const EXPECTED_CAPABILITIES = Object.freeze({
  api_version: "p42-prizes-capabilities-v1",
  mutations: Object.freeze({
    status: "unconfigured",
    available: false,
    authentication: "unavailable",
  }),
});

const BOARD_MANIFEST_SCHEMA = "p42-prizes-release-guard-problems-v1";
const ALLOWED_BOARD_VALUES = Object.freeze({
  status: Object.freeze(["pilot", "locked"]),
  mode: Object.freeze(["construction", "hybrid", "proof"]),
  direction: Object.freeze(["minimize", "maximize"]),
});
const PHASE0_INVARIANTS = Object.freeze({
  donationWallet: Object.freeze({
    chain: "Base Sepolia",
    asset: "ETH",
    address: null,
    status: "not-deployed",
    explorerUrl: null,
  }),
  donationTarget: null,
  chainProvenance: Object.freeze({
    settlementState: "local-only",
    chain: "Base Sepolia",
    chainId: 84532,
    donationWalletAddress: null,
    poolAddress: null,
    poolRuntimeCodeHash: null,
    deploymentTransactionHash: null,
    registryAddress: null,
    problemRegistryId: null,
    verifierImageHash: "sha256:local-dev",
    admissionMatrixHash: null,
    deploymentCommit: null,
    indexedThroughBlock: null,
    reconciliationOk: false,
    source: "static-portal-data",
  }),
});
const BOARD_FIELDS = Object.freeze([
  "id",
  "slug",
  "title",
  "status",
  "mode",
  "direction",
  "scoreName",
  "currentBest",
  "minImprovement",
  "bountyEth",
  "challengeWindowHours",
  "verifierVersion",
]);

export const PROBE_ROUTES = Object.freeze([
  Object.freeze({
    id: "home",
    path: "/prizes",
    kind: "html",
    origins: Object.freeze(["render", "public"]),
    markers: Object.freeze([
      "Machines can now produce frontier mathematics.",
      "It needs a settlement layer for truth.",
      "Phase 0",
    ]),
  }),
  Object.freeze({
    id: "problems",
    path: "/prizes/api/problems",
    kind: "problems-json",
    origins: Object.freeze(["render", "public"]),
  }),
  Object.freeze({
    id: "capabilities",
    path: "/prizes/api/capabilities",
    kind: "capabilities-json",
    origins: Object.freeze(["render", "public"]),
  }),
  Object.freeze({
    id: "standings",
    path: "/prizes/standings",
    kind: "html",
    origins: Object.freeze(["public"]),
    markers: Object.freeze([
      "P42 Prizes",
      "The pilot cohort.",
      "Modeled",
    ]),
  }),
  Object.freeze({
    id: "skill",
    path: "/prizes/skill.md",
    kind: "text",
    origins: Object.freeze(["public"]),
    markers: Object.freeze([
      "name: p42-prizes",
      "# P42 Prizes",
      "## Mutation Capability Gate",
    ]),
  }),
]);

export function parseArgs(argv) {
  const options = { ...DEFAULTS };
  const aliases = new Map([
    ["--branch", "branch"],
    ["--git-remote", "gitRemote"],
    ["--public-origin", "publicOrigin"],
    ["--render-origin", "renderOrigin"],
    ["--service-id", "serviceId"],
  ]);

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") {
      return { ...options, help: true };
    }

    const key = aliases.get(argument);
    if (!key) {
      throw new Error(`Unknown argument: ${argument}`);
    }

    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`${argument} requires a value`);
    }
    options[key] = value;
    index += 1;
  }

  return options;
}

export function findService(payload, serviceId) {
  const services = Array.isArray(payload) ? payload.map((item) => item?.service ?? item) : [];
  const service = services.find((item) => item?.id === serviceId);
  if (!service) {
    throw new Error(`Render service ${serviceId} was not returned by the authenticated CLI.`);
  }
  return service;
}

export function findLiveDeploy(payload) {
  const deployments = Array.isArray(payload) ? payload : [];
  const liveDeployments = deployments.filter((deployment) => deployment?.status === "live");
  if (liveDeployments.length !== 1) {
    throw new Error(`Expected exactly one live Render deployment, found ${liveDeployments.length}.`);
  }

  const deployment = liveDeployments[0];
  const commitId = deployment?.commit?.id;
  if (!/^[0-9a-f]{40}$/i.test(commitId ?? "")) {
    throw new Error("The live Render deployment does not expose a full Git commit ID.");
  }
  return deployment;
}

export function parseRemoteHead(output, branch) {
  const ref = `refs/heads/${branch}`;
  const lines = output.trim().split(/\r?\n/).filter(Boolean);
  const match = lines
    .map((line) => line.split(/\s+/))
    .find((parts) => parts[1] === ref);

  if (!match) {
    throw new Error(`Could not resolve the remote head for ${ref}.`);
  }
  return parseCommitId(match[0], `remote head for ${ref}`);
}

export function parseCommitId(value, description) {
  const commit = value.trim().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error(`${description} must be a full Git commit ID.`);
  }
  return commit;
}

export function runtimeCommitArgs(remoteRef) {
  return [
    "log",
    "--first-parent",
    "-1",
    "--format=%H",
    remoteRef,
    "--",
    ...DEPLOY_RELEVANT_PATHS,
  ];
}

export function probeUrls(renderOrigin, publicOrigin) {
  return configuredProbes(renderOrigin, publicOrigin).map((probe) => probe.url);
}

function configuredProbes(renderOrigin, publicOrigin) {
  const origins = { render: renderOrigin, public: publicOrigin };
  return PROBE_ROUTES.flatMap((route) => route.origins.map((origin) => ({
    route,
    origin,
    url: new URL(route.path, origins[origin]).toString(),
  })));
}

function describe(route, message) {
  throw new Error(`${route.path} ${message}`);
}

function requireObject(value, route, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    describe(route, `must return ${description} as an object.`);
  }
}

function requireString(value, route, description) {
  if (typeof value !== "string" || value.length === 0) {
    describe(route, `must return a non-empty string for ${description}.`);
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function boardManifestFingerprint(manifest) {
  const projection = { phase0: manifest.phase0, boards: manifest.boards };
  return `sha256:${createHash("sha256").update(canonicalJson(projection)).digest("hex")}`;
}

export function validateBoardManifest(manifest) {
  if (manifest?.schema_version !== BOARD_MANIFEST_SCHEMA) {
    throw new Error(`Expected board manifest schema ${BOARD_MANIFEST_SCHEMA}.`);
  }
  if (!isDeepStrictEqual(manifest.phase0, PHASE0_INVARIANTS)) {
    throw new Error("Expected board manifest changed the fixed Phase 0 funding/provenance invariants.");
  }
  if (!Array.isArray(manifest.boards) || manifest.boards.length !== 10) {
    throw new Error("Expected board manifest must contain exactly 10 boards.");
  }
  const actualFingerprint = boardManifestFingerprint(manifest);
  if (manifest.projection_sha256 !== actualFingerprint) {
    throw new Error(
      `Expected board manifest fingerprint mismatch (${manifest.projection_sha256} != ${actualFingerprint}).`,
    );
  }
  return manifest;
}

function loadBoardManifest() {
  const manifestUrl = new URL("./release-guard-problems-v1.json", import.meta.url);
  try {
    return validateBoardManifest(JSON.parse(readFileSync(manifestUrl, "utf8")));
  } catch (error) {
    throw new Error(`Could not load the expected board manifest: ${error.message}`);
  }
}

export const EXPECTED_BOARD_MANIFEST = loadBoardManifest();

function boardProjection(problem) {
  return Object.fromEntries(BOARD_FIELDS.map((field) => [field, problem[field]]));
}

function phase0Projection(problem) {
  return {
    donationWallet: {
      chain: problem.donationWallet?.chain,
      asset: problem.donationWallet?.asset,
      address: problem.donationWallet?.address,
      status: problem.donationWallet?.status,
      explorerUrl: problem.donationWallet?.explorerUrl,
    },
    donationTarget: problem.donationTarget,
    chainProvenance: {
      settlementState: problem.chainProvenance?.settlementState,
      chain: problem.chainProvenance?.chain,
      chainId: problem.chainProvenance?.chainId,
      donationWalletAddress: problem.chainProvenance?.donationWalletAddress,
      poolAddress: problem.chainProvenance?.poolAddress,
      poolRuntimeCodeHash: problem.chainProvenance?.poolRuntimeCodeHash,
      deploymentTransactionHash: problem.chainProvenance?.deploymentTransactionHash,
      registryAddress: problem.chainProvenance?.registryAddress,
      problemRegistryId: problem.chainProvenance?.problemRegistryId,
      verifierImageHash: problem.chainProvenance?.verifierImageHash,
      admissionMatrixHash: problem.chainProvenance?.admissionMatrixHash,
      deploymentCommit: problem.chainProvenance?.deploymentCommit,
      indexedThroughBlock: problem.chainProvenance?.indexedThroughBlock,
      reconciliationOk: problem.chainProvenance?.reconciliationOk,
      source: problem.chainProvenance?.source,
    },
  };
}

function validateProblems(payload, route) {
  const manifest = EXPECTED_BOARD_MANIFEST;
  if (!Array.isArray(payload) || payload.length !== manifest.boards.length) {
    describe(route, `must return exactly ${manifest.boards.length} expected boards.`);
  }

  const ids = new Set();
  const slugs = new Set();
  for (const [index, problem] of payload.entries()) {
    requireObject(problem, route, `problem ${index}`);
    if (!Number.isInteger(problem.id) || problem.id <= 0) {
      describe(route, `must return a positive integer id for problem ${index}.`);
    }
    for (const field of [
      "slug",
      "title",
      "status",
      "mode",
      "direction",
      "scoreName",
      "currentBest",
      "minImprovement",
      "bountyEth",
      "verifierVersion",
    ]) {
      requireString(problem[field], route, `problem ${index}.${field}`);
    }
    for (const field of ["status", "mode", "direction"]) {
      if (!ALLOWED_BOARD_VALUES[field].includes(problem[field])) {
        describe(route, `returned disallowed problem ${index}.${field} ${JSON.stringify(problem[field])}.`);
      }
    }
    for (const field of ["currentBest", "minImprovement"]) {
      if (!/^-?(0|[1-9]\d*)\/[1-9]\d*$/.test(problem[field])) {
        describe(route, `must return a canonical rational for problem ${index}.${field}.`);
      }
    }
    if (!/^(0|[1-9]\d*)\.\d{2}$/.test(problem.bountyEth) || Number(problem.bountyEth) > 100) {
      describe(route, `must return a sane canonical ETH amount for problem ${index}.bountyEth.`);
    }
    if (!Number.isFinite(problem.challengeWindowHours) || problem.challengeWindowHours <= 0) {
      describe(route, `must return a positive challengeWindowHours for problem ${index}.`);
    }
    if (!isDeepStrictEqual(phase0Projection(problem), manifest.phase0)) {
      describe(route, `problem ${index} violates the exact Phase 0 funding/provenance state.`);
    }
    if (ids.has(problem.id) || slugs.has(problem.slug)) {
      describe(route, `must not return duplicate problem ids or slugs (problem ${index}).`);
    }
    ids.add(problem.id);
    slugs.add(problem.slug);
  }

  const liveBoards = payload.map(boardProjection).sort((left, right) => left.id - right.id);
  if (!isDeepStrictEqual(liveBoards, manifest.boards)) {
    describe(
      route,
      `does not match committed board projection ${manifest.projection_sha256}.`,
    );
  }
}

function parseJson(body, route) {
  try {
    return JSON.parse(body);
  } catch (error) {
    describe(route, `returned malformed JSON: ${error.message}`);
  }
}

export function validateProbeBody(routeId, body, contentType) {
  const route = PROBE_ROUTES.find((candidate) => candidate.id === routeId);
  if (!route) {
    throw new Error(`Unknown probe route: ${routeId}`);
  }
  if (typeof body !== "string") {
    describe(route, "returned a non-text response body.");
  }

  if (route.kind.endsWith("-json")) {
    if (!contentType.toLowerCase().includes("application/json")) {
      describe(route, `returned ${JSON.stringify(contentType)} instead of application/json.`);
    }
    const payload = parseJson(body, route);
    if (route.kind === "problems-json") {
      validateProblems(payload, route);
    } else if (!isDeepStrictEqual(payload, EXPECTED_CAPABILITIES)) {
      describe(
        route,
        "must report the fail-closed unconfigured/unavailable mutation capability state.",
      );
    }
    return payload;
  }

  const expectedType = route.kind === "html" ? "text/html" : "text/";
  if (!contentType.toLowerCase().includes(expectedType)) {
    describe(route, `returned ${JSON.stringify(contentType)} instead of ${expectedType}.`);
  }
  for (const marker of route.markers) {
    if (!body.includes(marker)) {
      describe(route, `is missing stable identity marker ${JSON.stringify(marker)}.`);
    }
  }
  return body;
}

export function assertProbeEquivalence(results) {
  for (const route of PROBE_ROUTES.filter((candidate) => candidate.origins.length === 2)) {
    const render = results.find((result) => result.route.id === route.id && result.origin === "render");
    const publicResult = results.find(
      (result) => result.route.id === route.id && result.origin === "public",
    );
    if (!render || !publicResult) {
      describe(route, "is missing a configured Render or public comparison response.");
    }
    const equivalent = route.kind.endsWith("-json")
      ? isDeepStrictEqual(render.semanticBody, publicResult.semanticBody)
      : render.body === publicResult.body;
    if (!equivalent) {
      describe(route, "diverges between the direct Render service and the public proxy.");
    }
  }
}

async function command(file, args) {
  try {
    const { stdout } = await execFileAsync(file, args, { maxBuffer: 1024 * 1024 });
    return stdout;
  } catch (error) {
    const detail = [error.stderr, error.stdout, error.message].filter(Boolean).join("\n").trim();
    throw new Error(`${file} ${args.join(" ")} failed${detail ? `: ${detail}` : "."}`);
  }
}

async function isAncestor(ancestor, descendant) {
  try {
    await execFileAsync("git", ["merge-base", "--is-ancestor", ancestor, descendant], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch (error) {
    if (error?.code === 1) {
      return false;
    }
    const detail = [error.stderr, error.stdout, error.message].filter(Boolean).join("\n").trim();
    throw new Error(`git merge-base --is-ancestor failed${detail ? `: ${detail}` : "."}`);
  }
}

export async function assertReleaseAncestry(
  { runtimeCommit, liveCommit, branchHead, remoteRef },
  ancestorCheck = isAncestor,
) {
  if (!(await ancestorCheck(runtimeCommit, liveCommit))) {
    throw new Error(
      `Render live commit ${liveCommit} does not contain the deploy-relevant ${remoteRef} commit ${runtimeCommit} (${DEPLOY_RELEVANT_PATHS.join(", ")}).`,
    );
  }
  if (!(await ancestorCheck(liveCommit, branchHead))) {
    throw new Error(
      `Render live commit ${liveCommit} is not on the exact fetched ${remoteRef} history ending at ${branchHead}.`,
    );
  }
}

async function commandJson(file, args) {
  const stdout = await command(file, args);
  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error(`${file} returned invalid JSON: ${error.message}`);
  }
}

async function probe(config) {
  let response;
  try {
    response = await fetch(config.url, {
      redirect: "follow",
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new Error(`Probe failed for ${config.url}: ${error.message}`);
  }

  if (!response.ok) {
    throw new Error(`Probe failed for ${config.url}: HTTP ${response.status}.`);
  }
  const body = await response.text();
  const semanticBody = validateProbeBody(
    config.route.id,
    body,
    response.headers.get("content-type") ?? "",
  );
  return { ...config, body, semanticBody };
}

export function usage() {
  return `Usage: node scripts/verify-render-release.mjs [options]

Read-only release guard. It verifies that Render is configured for the expected
branch, its single live deployment is on that exact branch history and contains
the latest portal/config change,
and the Render origin plus the ProjectForty2 proxy return the expected portal,
versioned board projection, fail-closed capabilities, and equivalent paired
responses.

The service builds from web/, so documentation-only and release-tooling-only
commits do not require a no-op Render deploy. The guard treats web/ and
render.yaml as deploy-relevant paths and verifies the live SHA contains the
latest first-parent commit touching either one.

Options:
  --branch <name>             Expected GitHub/Render branch (default: main)
  --git-remote <name>         Git remote used for the branch-head lookup (default: origin)
  --service-id <id>           Render service ID
  --render-origin <url>       Render origin
  --public-origin <url>       Public ProjectForty2 origin
  --help, -h                  Show this help
`;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(usage());
    return;
  }

  const remoteHeadOutput = await command("git", [
    "ls-remote",
    options.gitRemote,
    `refs/heads/${options.branch}`,
  ]);
  const branchHead = parseRemoteHead(remoteHeadOutput, options.branch);
  await command("git", ["fetch", "--quiet", options.gitRemote, options.branch]);
  const remoteRef = `${options.gitRemote}/${options.branch}`;
  const fetchedHead = parseCommitId(
    await command("git", ["rev-parse", "--verify", remoteRef]),
    `fetched ${remoteRef}`,
  );
  if (fetchedHead !== branchHead) {
    throw new Error(
      `${remoteRef} changed while verifying (${branchHead} -> ${fetchedHead}); retry after the branch stabilizes.`,
    );
  }
  const runtimeCommit = parseCommitId(
    await command("git", runtimeCommitArgs(remoteRef)),
    `latest deploy-relevant commit on ${remoteRef}`,
  );

  const [services, deployments] = await Promise.all([
    commandJson("render", ["services", "--output", "json"]),
    commandJson("render", ["deploys", "list", options.serviceId, "--output", "json"]),
  ]);
  const service = findService(services, options.serviceId);
  if (service.branch !== options.branch) {
    throw new Error(
      `Render service ${options.serviceId} deploys ${JSON.stringify(service.branch)}, expected ${JSON.stringify(options.branch)}.`,
    );
  }

  const liveDeploy = findLiveDeploy(deployments);
  const liveCommit = liveDeploy.commit.id.toLowerCase();
  await assertReleaseAncestry({ runtimeCommit, liveCommit, branchHead, remoteRef });

  const configured = configuredProbes(options.renderOrigin, options.publicOrigin);
  const probeResults = await Promise.all(configured.map(probe));
  assertProbeEquivalence(probeResults);
  const urls = configured.map((probeConfig) => probeConfig.url);

  process.stdout.write(
    [
      "Render release verified.",
      `  branch: ${options.branch}`,
      `  branch head: ${branchHead}`,
      `  runtime commit: ${runtimeCommit}`,
      `  live commit: ${liveCommit}`,
      `  board projection: ${EXPECTED_BOARD_MANIFEST.projection_sha256}`,
      `  routes: ${urls.length}/${urls.length} healthy`,
    ].join("\n") + "\n",
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Render release verification failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
