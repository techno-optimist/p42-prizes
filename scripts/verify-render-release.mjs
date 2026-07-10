#!/usr/bin/env node

import { execFile } from "node:child_process";
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
  return [
    new URL("/prizes", renderOrigin).toString(),
    new URL("/prizes/api/problems", renderOrigin).toString(),
    new URL("/prizes", publicOrigin).toString(),
    new URL("/prizes/api/problems", publicOrigin).toString(),
    new URL("/prizes/standings", publicOrigin).toString(),
    new URL("/prizes/skill.md", publicOrigin).toString(),
  ];
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

async function commandJson(file, args) {
  const stdout = await command(file, args);
  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error(`${file} returned invalid JSON: ${error.message}`);
  }
}

async function probe(url) {
  let response;
  try {
    response = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(30_000) });
  } catch (error) {
    throw new Error(`Probe failed for ${url}: ${error.message}`);
  }

  if (!response.ok) {
    throw new Error(`Probe failed for ${url}: HTTP ${response.status}.`);
  }
}

export function usage() {
  return `Usage: node scripts/verify-render-release.mjs [options]

Read-only release guard. It verifies that Render is configured for the expected
branch, its single live deployment contains the latest portal/config change,
and the Render origin plus the ProjectForty2 proxy respond successfully.

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
  if (!(await isAncestor(runtimeCommit, liveCommit))) {
    throw new Error(
      `Render live commit ${liveCommit} does not contain the deploy-relevant ${remoteRef} commit ${runtimeCommit} (${DEPLOY_RELEVANT_PATHS.join(", ")}).`,
    );
  }

  const urls = probeUrls(options.renderOrigin, options.publicOrigin);
  await Promise.all(urls.map(probe));

  process.stdout.write(
    [
      "Render release verified.",
      `  branch: ${options.branch}`,
      `  branch head: ${branchHead}`,
      `  runtime commit: ${runtimeCommit}`,
      `  live commit: ${liveCommit}`,
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
