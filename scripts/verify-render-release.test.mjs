import assert from "node:assert/strict";
import test from "node:test";

import {
  DEPLOY_RELEVANT_PATHS,
  EXPECTED_BOARD_MANIFEST,
  assertProbeEquivalence,
  assertReleaseAncestry,
  findLiveDeploy,
  findService,
  parseArgs,
  parseCommitId,
  parseRemoteHead,
  probeUrls,
  runtimeCommitArgs,
  validateBoardManifest,
  validateProbeBody,
} from "./verify-render-release.mjs";

const contentTypes = {
  html: "text/html; charset=utf-8",
  json: "application/json; charset=utf-8",
  text: "text/markdown; charset=utf-8",
};

function validProblems() {
  return EXPECTED_BOARD_MANIFEST.boards.map((board) => ({
    ...structuredClone(board),
    donationWallet: {
      ...structuredClone(EXPECTED_BOARD_MANIFEST.phase0.donationWallet),
      note: "Non-material human-readable funding note.",
    },
    donationTarget: null,
    chainProvenance: {
      ...structuredClone(EXPECTED_BOARD_MANIFEST.phase0.chainProvenance),
      note: "Non-material human-readable provenance note.",
    },
  }));
}

function validProblem(overrides = {}) {
  return { ...validProblems()[0], ...overrides };
}

function result(routeId, origin, body, semanticBody = body) {
  return { route: { id: routeId }, origin, body, semanticBody };
}

function ancestry(...pairs) {
  const relations = new Set(pairs.map(([ancestor, descendant]) => `${ancestor}:${descendant}`));
  return async (ancestor, descendant) => (
    ancestor === descendant || relations.has(`${ancestor}:${descendant}`)
  );
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

test("release ancestry rejects an off-branch live descendant", async () => {
  await assert.rejects(
    () => assertReleaseAncestry(
      {
        runtimeCommit: "runtime",
        liveCommit: "off-branch-live",
        branchHead: "branch-head",
        remoteRef: "origin/main",
      },
      ancestry(["runtime", "off-branch-live"], ["runtime", "branch-head"]),
    ),
    /not on the exact fetched origin\/main history/,
  );
});

test("release ancestry rejects force-push and rollback divergence", async () => {
  const rewrittenHistory = ancestry(
    ["shared-base", "old-live"],
    ["shared-base", "runtime"],
    ["runtime", "new-head"],
  );
  await assert.rejects(
    () => assertReleaseAncestry(
      {
        runtimeCommit: "runtime",
        liveCommit: "old-live",
        branchHead: "new-head",
        remoteRef: "origin/main",
      },
      rewrittenHistory,
    ),
    /does not contain the deploy-relevant origin\/main commit runtime/,
  );

  await assert.rejects(
    () => assertReleaseAncestry(
      {
        runtimeCommit: "runtime",
        liveCommit: "shared-base",
        branchHead: "new-head",
        remoteRef: "origin/main",
      },
      rewrittenHistory,
    ),
    /does not contain the deploy-relevant origin\/main commit runtime/,
  );
});

test("release ancestry accepts an older live commit on the exact branch", async () => {
  await assert.doesNotReject(() => assertReleaseAncestry(
    {
      runtimeCommit: "runtime",
      liveCommit: "live",
      branchHead: "docs-only-head",
      remoteRef: "origin/main",
    },
    ancestry(["runtime", "live"], ["live", "docs-only-head"]),
  ));
});

test("release ancestry accepts the exact branch head as live", async () => {
  await assert.doesNotReject(() => assertReleaseAncestry(
    {
      runtimeCommit: "runtime",
      liveCommit: "branch-head",
      branchHead: "branch-head",
      remoteRef: "origin/main",
    },
    ancestry(["runtime", "branch-head"]),
  ));
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
    /exactly 10 expected boards/,
  );
  const wrongSlug = validProblems();
  wrongSlug[0].slug = "";
  assert.throws(
    () => validateProbeBody("problems", JSON.stringify(wrongSlug), contentTypes.json),
    /problem 0\.slug/,
  );
  const expected = validProblems();
  assert.deepEqual(
    validateProbeBody("problems", JSON.stringify(expected), contentTypes.json),
    expected,
  );
});

test("problems probe rejects forged board identity and material state", () => {
  const forgeries = [
    ["board count", (problems) => problems.pop(), /exactly 10 expected boards/],
    ["board id", (problems) => { problems[0].id = 42; }, /committed board projection/],
    ["open status", (problems) => { problems[0].status = "open"; }, /disallowed problem 0\.status/],
    ["huge bounty", (problems) => { problems[0].bountyEth = "999999.00"; }, /sane canonical ETH/],
    ["live provenance", (problems) => {
      problems[0].chainProvenance.settlementState = "mainnet-indexed";
    }, /exact Phase 0 funding\/provenance state/],
    ["donation address", (problems) => {
      problems[0].donationWallet.address = "0xdead";
    }, /exact Phase 0 funding\/provenance state/],
    ["reconciled chain", (problems) => {
      problems[0].chainProvenance.reconciliationOk = true;
    }, /exact Phase 0 funding\/provenance state/],
  ];

  for (const [description, forge, expectedError] of forgeries) {
    const problems = validProblems();
    forge(problems);
    assert.throws(
      () => validateProbeBody("problems", JSON.stringify(problems), contentTypes.json),
      expectedError,
      description,
    );
  }
});

test("expected board manifest rejects projection tampering", () => {
  const tampered = structuredClone(EXPECTED_BOARD_MANIFEST);
  tampered.boards[0].bountyEth = "1000000.00";
  assert.throws(() => validateBoardManifest(tampered), /fingerprint mismatch/);
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
