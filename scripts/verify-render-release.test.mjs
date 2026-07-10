import assert from "node:assert/strict";
import test from "node:test";

import {
  DEPLOY_RELEVANT_PATHS,
  assertProbeEquivalence,
  findLiveDeploy,
  findService,
  parseArgs,
  parseCommitId,
  parseRemoteHead,
  probeUrls,
  runtimeCommitArgs,
  validateProbeBody,
} from "./verify-render-release.mjs";

const contentTypes = {
  html: "text/html; charset=utf-8",
  json: "application/json; charset=utf-8",
  text: "text/markdown; charset=utf-8",
};

function validProblem(overrides = {}) {
  return {
    id: 1,
    slug: "hadamard-mini",
    title: "Hadamard Mini",
    status: "pilot",
    mode: "construction",
    direction: "minimize",
    scoreName: "defect",
    currentBest: "0/1",
    minImprovement: "1/6",
    bountyEth: "0.00",
    donationWallet: {},
    donationTarget: null,
    chainProvenance: { settlementState: "local-only", reconciliationOk: false },
    challengeWindowHours: 72,
    verifierVersion: "0.1.1",
    ...overrides,
  };
}

function result(routeId, origin, body, semanticBody = body) {
  return { route: { id: routeId }, origin, body, semanticBody };
}

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
    "https://public.example/prizes",
    "https://render.example/prizes/api/problems",
    "https://public.example/prizes/api/problems",
    "https://render.example/prizes/api/capabilities",
    "https://public.example/prizes/api/capabilities",
    "https://public.example/prizes/standings",
    "https://public.example/prizes/skill.md",
  ]);
});

test("page probes require stable identity markers", () => {
  const home = "<html><title>Register of Records</title><h1>The machine went first.</h1><p>Phase 0</p></html>";
  assert.equal(validateProbeBody("home", home, contentTypes.html), home);
  assert.throws(
    () => validateProbeBody("home", "<html><h1>Unrelated healthy page</h1></html>", contentTypes.html),
    /missing stable identity marker/,
  );

  const standings = "<html><b>P42 Prizes</b><h1>The pilot cohort.</h1><p>Modeled</p></html>";
  assert.equal(validateProbeBody("standings", standings, contentTypes.html), standings);
  const skill = "---\nname: p42-prizes\n---\n# P42 Prizes\n## Mutation Capability Gate\n";
  assert.equal(validateProbeBody("skill", skill, contentTypes.text), skill);
});

test("API probes reject malformed JSON and wrong response shapes", () => {
  assert.throws(
    () => validateProbeBody("problems", "{", contentTypes.json),
    /malformed JSON/,
  );
  assert.throws(
    () => validateProbeBody("problems", JSON.stringify({ ok: true }), contentTypes.json),
    /non-empty array/,
  );
  assert.throws(
    () => validateProbeBody("problems", JSON.stringify([validProblem({ slug: "" })]), contentTypes.json),
    /problem 0\.slug/,
  );
  assert.deepEqual(
    validateProbeBody("problems", JSON.stringify([validProblem()]), contentTypes.json),
    [validProblem()],
  );
});

test("capabilities probe requires the secret-free fail-closed production state", () => {
  const expected = {
    api_version: "p42-prizes-capabilities-v1",
    mutations: {
      status: "unconfigured",
      available: false,
      authentication: "unavailable",
    },
  };
  assert.deepEqual(
    validateProbeBody("capabilities", JSON.stringify(expected), contentTypes.json),
    expected,
  );
  assert.throws(
    () => validateProbeBody("capabilities", JSON.stringify({ ...expected, mutations: {
      status: "configured",
      available: true,
      authentication: "api-key",
    } }), contentTypes.json),
    /fail-closed/,
  );
});

test("paired direct and proxy probes reject body and semantic divergence", () => {
  const sameProblems = [validProblem()];
  const sameCapabilities = {
    api_version: "p42-prizes-capabilities-v1",
    mutations: { status: "unconfigured", available: false, authentication: "unavailable" },
  };
  const matching = [
    result("home", "render", "same home"),
    result("home", "public", "same home"),
    result("problems", "render", "render json", sameProblems),
    result("problems", "public", "public json", structuredClone(sameProblems)),
    result("capabilities", "render", "render json", sameCapabilities),
    result("capabilities", "public", "public json", structuredClone(sameCapabilities)),
  ];
  assert.doesNotThrow(() => assertProbeEquivalence(matching));
  assert.throws(
    () => assertProbeEquivalence(matching.map((probe) => (
      probe.route.id === "home" && probe.origin === "public"
        ? { ...probe, body: "stale proxy home" }
        : probe
    ))),
    /diverges between the direct Render service and the public proxy/,
  );
  assert.throws(
    () => assertProbeEquivalence(matching.map((probe) => (
      probe.route.id === "problems" && probe.origin === "public"
        ? { ...probe, semanticBody: [validProblem({ id: 2 })] }
        : probe
    ))),
    /diverges between the direct Render service and the public proxy/,
  );
});

test("parseArgs keeps main as the default and rejects unknown input", () => {
  assert.equal(parseArgs([]).branch, "main");
  assert.equal(parseArgs(["--git-remote", "github"]).gitRemote, "github");
  assert.throws(() => parseArgs(["--nope"]), /Unknown argument/);
});
