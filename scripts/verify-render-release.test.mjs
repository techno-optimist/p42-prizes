import assert from "node:assert/strict";
import test from "node:test";

import {
  DEPLOY_RELEVANT_PATHS,
  findLiveDeploy,
  findService,
  parseArgs,
  parseCommitId,
  parseRemoteHead,
  probeUrls,
  runtimeCommitArgs,
} from "./verify-render-release.mjs";

test("findService unwraps Render CLI service records", () => {
  const service = findService(
    [{ service: { id: "srv-prizes", branch: "main" } }],
    "srv-prizes",
  );
  assert.equal(service.branch, "main");
});

test("findLiveDeploy requires exactly one SHA-pinned live deploy", () => {
  const deploy = findLiveDeploy([
    { status: "inactive", commit: { id: "b".repeat(40) } },
    { status: "live", commit: { id: "a".repeat(40) } },
  ]);
  assert.equal(deploy.commit.id, "a".repeat(40));

  assert.throws(() => findLiveDeploy([]), /exactly one live/);
  assert.throws(
    () => findLiveDeploy([{ status: "live", commit: { id: "short" } }]),
    /full Git commit ID/,
  );
});

test("parseRemoteHead selects the exact expected branch", () => {
  const main = "c".repeat(40);
  const feature = "d".repeat(40);
  assert.equal(
    parseRemoteHead(`${feature}\trefs/heads/feature\n${main}\trefs/heads/main\n`, "main"),
    main,
  );
  assert.throws(() => parseRemoteHead(`${main}\trefs/heads/main\n`, "missing"), /Could not resolve/);
});

test("runtime commit lookup follows the first-parent portal/config history", () => {
  assert.deepEqual(DEPLOY_RELEVANT_PATHS, ["web", "render.yaml"]);
  assert.deepEqual(runtimeCommitArgs("origin/main"), [
    "log",
    "--first-parent",
    "-1",
    "--format=%H",
    "origin/main",
    "--",
    "web",
    "render.yaml",
  ]);
  assert.equal(parseCommitId("A".repeat(40), "fixture"), "a".repeat(40));
  assert.throws(() => parseCommitId("short", "fixture"), /full Git commit ID/);
});

test("probeUrls retains the standalone and proxied prize paths", () => {
  assert.deepEqual(probeUrls("https://render.example/", "https://public.example/"), [
    "https://render.example/prizes",
    "https://render.example/prizes/api/problems",
    "https://public.example/prizes",
    "https://public.example/prizes/api/problems",
    "https://public.example/prizes/standings",
    "https://public.example/prizes/skill.md",
  ]);
});

test("parseArgs keeps main as the default and rejects unknown input", () => {
  assert.equal(parseArgs([]).branch, "main");
  assert.equal(parseArgs(["--git-remote", "github"]).gitRemote, "github");
  assert.throws(() => parseArgs(["--nope"]), /Unknown argument/);
});
