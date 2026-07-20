import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Wallet } from "ethers";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GET as capabilitiesGet } from "@/app/api/capabilities/route";
import { POST as challengePost } from "@/app/api/challenges/route";
import { GET as eventsGet } from "@/app/api/events/route";
import { GET as problemGet } from "@/app/api/problems/[slug]/route";
import { POST as coinbaseSessionPost } from "@/app/api/problems/[slug]/funding/coinbase-session/route";
import { GET as problemsGet } from "@/app/api/problems/route";
import { POST as solutionsPost } from "@/app/api/solutions/route";
import { POST as commitPost } from "@/app/api/submissions/commit/route";
import { POST as revealPost } from "@/app/api/submissions/reveal/route";
import { mutationApiCredentialPolicyForTests, mutationApiKeyHashForTests } from "@/lib/api-auth";
import { commitAuthorizationMessage, commitHash, sha256SolutionCid } from "@/lib/portal-state";
import { readPortalState, resetPortalStateForTests } from "@/lib/portal-store";
import { resetRateLimitsForTests } from "@/lib/rate-limit";

const solverWallet = new Wallet("0x59c6995e998f97a5a0044966f0945387f6d6616d07a16c6fbfcaeab4f7fca6e5");
const solverAddress = solverWallet.address;
const solutionRaw = '{"n":4,"rows":["++++","+-+-","++--","+--+"]}';
let stateDir: string;

function jsonRequest(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`http://localhost${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

async function signedCommitFields(problemId = 1) {
  const solutionCid = sha256SolutionCid(solutionRaw);
  const hash = commitHash({ solutionCid, solverAddress, salt: "right-salt" });
  const solverSignature = await solverWallet.signMessage(
    commitAuthorizationMessage({
      problemId,
      solverAddress,
      solutionCid,
      commitHash: hash,
    }),
  );
  return { solutionCid, commitHash: hash, solverSignature };
}

describe("mutable API routes", () => {
  beforeEach(() => {
    delete process.env.P42_MUTATION_API_KEY_SHA256S;
    delete process.env.P42_MUTATION_API_CREDENTIALS_JSON;
    stateDir = mkdtempSync(path.join(tmpdir(), "p42-api-state-"));
    process.env.P42_PORTAL_STATE_PATH = path.join(stateDir, "state.json");
    resetPortalStateForTests();
    resetRateLimitsForTests();
    process.env.P42_ALLOW_UNAUTHENTICATED_MUTATIONS = "1";
  });

  afterEach(() => {
    resetPortalStateForTests();
    resetRateLimitsForTests();
    delete process.env.P42_PORTAL_STATE_PATH;
    delete process.env.P42_MUTATION_API_KEY_SHA256S;
    delete process.env.P42_MUTATION_API_CREDENTIALS_JSON;
    delete process.env.P42_ALLOW_UNAUTHENTICATED_MUTATIONS;
    delete process.env.P42_RATE_LIMIT_COMMIT_LIMIT;
    delete process.env.P42_RATE_LIMIT_COMMIT_WINDOW_MS;
    rmSync(stateDir, { recursive: true, force: true });
  });

  it("reports unconfigured mutation authentication as unavailable in production", async () => {
    delete process.env.P42_MUTATION_API_KEY_SHA256S;
    vi.stubEnv("NODE_ENV", "production");
    try {
      const response = await capabilitiesGet();

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        api_version: "p42-prizes-capabilities-v1",
        mutations: {
          status: "unconfigured",
          available: false,
          authentication: "unavailable",
        },
      });
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("reports misconfigured mutation authentication without exposing its value", async () => {
    const invalidConfiguration = "not-a-valid-sha256-hash";
    process.env.P42_MUTATION_API_CREDENTIALS_JSON = invalidConfiguration;

    const response = await capabilitiesGet();
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toEqual({
      api_version: "p42-prizes-capabilities-v1",
      mutations: {
        status: "misconfigured",
        available: false,
        authentication: "unavailable",
      },
    });
    expect(JSON.stringify(body)).not.toContain(invalidConfiguration);
  });

  it("reports configured mutation authentication without exposing keys or hashes", async () => {
    const apiKey = "agent-capability-test-key";
    const apiKeyHash = mutationApiKeyHashForTests(apiKey);
    process.env.P42_MUTATION_API_CREDENTIALS_JSON = JSON.stringify([{
      hash: apiKeyHash,
      scopes: ["submissions.commit"],
    }]);

    const response = await capabilitiesGet();
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toEqual({
      api_version: "p42-prizes-capabilities-v1",
      mutations: {
        status: "configured",
        available: true,
        authentication: "api-key",
      },
    });
    expect(JSON.stringify(body)).not.toContain(apiKey);
    expect(JSON.stringify(body)).not.toContain(apiKeyHash);
  });

  it("returns controlled 400s for malformed JSON", async () => {
    const response = await commitPost(
      new Request("http://localhost/api/submissions/commit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{",
      }),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: "malformed JSON body" });
  });

  it("rate-limits mutable routes before JSON parsing work", async () => {
    process.env.P42_RATE_LIMIT_COMMIT_LIMIT = "1";
    process.env.P42_RATE_LIMIT_COMMIT_WINDOW_MS = "60000";
    resetRateLimitsForTests();

    const first = await commitPost(
      new Request("http://localhost/api/submissions/commit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{",
      }),
    );
    expect(first.status).toBe(400);

    const second = await commitPost(
      new Request("http://localhost/api/submissions/commit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{",
      }),
    );

    expect(second.status).toBe(429);
    expect(second.headers.get("Retry-After")).toBeTruthy();
    expect(second.headers.get("X-RateLimit-Limit")).toBe("1");
    await expect(second.json()).resolves.toMatchObject({ error: "rate limit exceeded" });
  });

  it("can require a hashed mutation API key for production mutation routes", async () => {
    process.env.P42_MUTATION_API_CREDENTIALS_JSON = mutationApiCredentialPolicyForTests([{
      key: "agent-session-key",
      scopes: ["submissions.commit"],
    }]);
    const signed = await signedCommitFields();
    const body = {
      problem_id: 1,
      agent_name: "RouteAgent",
      solver_address: solverAddress,
      solution_cid: signed.solutionCid,
      commit_hash: signed.commitHash,
      solver_signature: signed.solverSignature,
    };

    const missing = await commitPost(jsonRequest("/api/submissions/commit", body));
    expect(missing.status).toBe(401);
    expect(missing.headers.get("WWW-Authenticate")).toContain("missing_api_key");

    const wrong = await commitPost(
      jsonRequest("/api/submissions/commit", body, { "x-p42-api-key": "wrong-session-key" }),
    );
    expect(wrong.status).toBe(403);
    await expect(wrong.json()).resolves.toMatchObject({ error: "invalid P42 mutation API key" });

    const accepted = await commitPost(
      jsonRequest("/api/submissions/commit", body, { authorization: "Bearer agent-session-key" }),
    );
    expect(accepted.status).toBe(201);
  });

  it("binds a credential to its exact route scopes", async () => {
    process.env.P42_MUTATION_API_CREDENTIALS_JSON = mutationApiCredentialPolicyForTests([{
      key: "commit-only-key",
      scopes: ["submissions.commit"],
    }]);
    const signed = await signedCommitFields();
    const commit = await commitPost(jsonRequest("/api/submissions/commit", {
      problem_id: 1,
      agent_name: "ScopedAgent",
      solver_address: solverAddress,
      solution_cid: signed.solutionCid,
      commit_hash: signed.commitHash,
      solver_signature: signed.solverSignature,
    }, { authorization: "Bearer commit-only-key" }));
    expect(commit.status).toBe(201);

    const deniedRequests = [
      revealPost(new Request("http://localhost/api/submissions/reveal", {
        method: "POST", headers: { authorization: "Bearer commit-only-key" }, body: "{",
      })),
      solutionsPost(new Request("http://localhost/api/solutions", {
        method: "POST", headers: { authorization: "Bearer commit-only-key" }, body: "{",
      })),
      challengePost(new Request("http://localhost/api/challenges", {
        method: "POST", headers: { authorization: "Bearer commit-only-key" }, body: "{",
      })),
    ];
    for (const response of await Promise.all(deniedRequests)) {
      expect(response.status).toBe(403);
      expect(response.headers.get("WWW-Authenticate")).toContain("insufficient_scope");
      await expect(response.json()).resolves.toMatchObject({
        error: "P42 mutation API key has insufficient scope",
      });
    }
  });

  it("supports overlapping rotation without merging credential scopes", async () => {
    process.env.P42_MUTATION_API_CREDENTIALS_JSON = mutationApiCredentialPolicyForTests([
      { key: "old-commit-key", scopes: ["submissions.commit"] },
      { key: "new-verifier-key", scopes: ["solutions.verify", "challenges.open"] },
    ]);
    const malformed = (path: string, key: string, route: (request: Request) => Promise<Response>) => route(
      new Request(`http://localhost${path}`, {
        method: "POST", headers: { authorization: `Bearer ${key}` }, body: "{",
      }),
    );

    expect((await malformed("/api/submissions/commit", "old-commit-key", commitPost)).status).toBe(400);
    expect((await malformed("/api/solutions", "old-commit-key", solutionsPost)).status).toBe(403);
    expect((await malformed("/api/solutions", "new-verifier-key", solutionsPost)).status).toBe(400);
    expect((await malformed("/api/challenges", "new-verifier-key", challengePost)).status).toBe(400);
    expect((await malformed("/api/submissions/commit", "new-verifier-key", commitPost)).status).toBe(403);
  });

  it("rejects expired credentials before parsing request bodies", async () => {
    process.env.P42_MUTATION_API_CREDENTIALS_JSON = mutationApiCredentialPolicyForTests([{
      key: "expired-key",
      scopes: ["solutions.verify"],
      expiresAt: "2000-01-01T00:00:00.000Z",
    }]);
    const response = await solutionsPost(new Request("http://localhost/api/solutions", {
      method: "POST", headers: { authorization: "Bearer expired-key" }, body: "{",
    }));
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ error: "invalid P42 mutation API key" });

    const capabilities = await capabilitiesGet();
    await expect(capabilities.json()).resolves.toMatchObject({
      mutations: { status: "configured", available: false, authentication: "unavailable" },
    });
  });

  it("makes every malformed or legacy credential policy unavailable", async () => {
    const hash = mutationApiKeyHashForTests("policy-key");
    const invalidPolicies = [
      "[]",
      JSON.stringify([{ hash, scopes: [] }]),
      JSON.stringify([{ hash, scopes: ["unknown.scope"] }]),
      JSON.stringify([{ hash, scopes: ["submissions.commit", "submissions.commit"] }]),
      JSON.stringify([{ hash, scopes: ["submissions.commit"], extra: true }]),
      JSON.stringify([{ hash, scopes: ["submissions.commit"], expiresAt: "tomorrow" }]),
      JSON.stringify([{ hash, scopes: ["submissions.commit"] }, { hash, scopes: ["solutions.verify"] }]),
      `[{"hash":"${hash}","hash":"${"f".repeat(71)}","scopes":["submissions.commit"]}]`,
      `[{"hash":"${hash}","scopes":["submissions.commit"],"scopes":["solutions.verify"]}]`,
      `[{"hash":"${hash}","scopes":["submissions.commit"],"expiresAt":"2099-01-01T00:00:00.000Z","expiresAt":"2098-01-01T00:00:00.000Z"}]`,
    ];
    for (const policy of invalidPolicies) {
      process.env.P42_MUTATION_API_CREDENTIALS_JSON = policy;
      const response = await commitPost(new Request("http://localhost/api/submissions/commit", {
        method: "POST", headers: { authorization: "Bearer policy-key" }, body: "{",
      }));
      expect(response.status, policy).toBe(503);
      await expect(response.json()).resolves.toMatchObject({ error: "mutation API credential policy is invalid" });
    }

    delete process.env.P42_MUTATION_API_CREDENTIALS_JSON;
    process.env.P42_MUTATION_API_KEY_SHA256S = hash;
    const legacy = await commitPost(new Request("http://localhost/api/submissions/commit", {
      method: "POST", headers: { authorization: "Bearer policy-key" }, body: "{",
    }));
    expect(legacy.status).toBe(503);
  });

  it("fails closed in production before parsing and ignores the local opt-out", async () => {
    vi.stubEnv("NODE_ENV", "production");
    try {
      const unconfigured = await commitPost(
        new Request("http://localhost/api/submissions/commit", { method: "POST", body: "{" }),
      );
      expect(unconfigured.status).toBe(503);
      await expect(unconfigured.json()).resolves.toMatchObject({
        error: "mutation API authentication is not configured",
      });

      process.env.P42_MUTATION_API_CREDENTIALS_JSON = mutationApiCredentialPolicyForTests([{
        key: "production-agent-key",
        scopes: ["submissions.commit"],
      }]);
      const unauthenticated = await commitPost(
        new Request("http://localhost/api/submissions/commit", { method: "POST", body: "{" }),
      );
      expect(unauthenticated.status).toBe(401);
      expect(unauthenticated.headers.get("WWW-Authenticate")).toContain("missing_api_key");
    } finally {
      vi.unstubAllEnvs();
      delete process.env.P42_MUTATION_API_KEY_SHA256S;
      delete process.env.P42_MUTATION_API_CREDENTIALS_JSON;
    }
  });

  it("rate-limits authenticated API keys in separate principal buckets", async () => {
    process.env.P42_MUTATION_API_CREDENTIALS_JSON = mutationApiCredentialPolicyForTests([
      { key: "first-agent-key", scopes: ["submissions.commit"] },
      { key: "second-agent-key", scopes: ["submissions.commit"] },
    ]);
    process.env.P42_RATE_LIMIT_COMMIT_LIMIT = "1";
    process.env.P42_RATE_LIMIT_COMMIT_WINDOW_MS = "60000";
    resetRateLimitsForTests();

    const malformed = (key: string) => commitPost(new Request("http://localhost/api/submissions/commit", {
      method: "POST",
      headers: { authorization: `Bearer ${key}` },
      body: "{",
    }));
    expect((await malformed("first-agent-key")).status).toBe(400);
    expect((await malformed("second-agent-key")).status).toBe(400);
    expect((await malformed("first-agent-key")).status).toBe(429);
  });

  it("fails closed when mutation API key enforcement is enabled without valid key hashes", async () => {
    process.env.P42_MUTATION_API_CREDENTIALS_JSON = "agent-session-key";

    const response = await solutionsPost(
      jsonRequest("/api/solutions", {
        problem_id: 1,
        agent_name: "RouteAgent",
        solution_raw: solutionRaw,
      }, { "x-p42-api-key": "agent-session-key" }),
    );

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: "mutation API credential policy is invalid",
    });
  });

  it("rejects commits for locked or non-runnable boards", async () => {
    const response = await commitPost(
      jsonRequest("/api/submissions/commit", {
        problem_id: 3,
        agent_name: "RouteAgent",
        solver_address: solverAddress,
        solution_cid: sha256SolutionCid(solutionRaw),
        dev_salt: "local-only",
      }),
    );

    expect(response.status).toBe(409);
  });

  it("requires a solver signature for non-local commits", async () => {
    const solutionCid = sha256SolutionCid(solutionRaw);
    const response = await commitPost(
      jsonRequest("/api/submissions/commit", {
        problem_id: 1,
        agent_name: "RouteAgent",
        solver_address: solverAddress,
        solution_cid: solutionCid,
        commit_hash: commitHash({ solutionCid, solverAddress, salt: "right-salt" }),
      }),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: "solver_signature is required for non-local commit flow",
    });
  });

  it("rejects a commit_hash that does not match the local dev_salt shortcut", async () => {
    const solutionCid = sha256SolutionCid(solutionRaw);
    const response = await commitPost(
      jsonRequest("/api/submissions/commit", {
        problem_id: 1,
        agent_name: "RouteAgent",
        solver_address: solverAddress,
        solution_cid: solutionCid,
        commit_hash: commitHash({ solutionCid, solverAddress, salt: "different-salt" }),
        dev_salt: "right-salt",
      }),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: "commit_hash does not match dev_salt preimage",
    });
  });

  it("replays idempotent commits and rejects key reuse with a changed body", async () => {
    const signed = await signedCommitFields();
    const body = {
      problem_id: 1,
      agent_name: "RouteAgent",
      solver_address: solverAddress,
      solution_cid: signed.solutionCid,
      commit_hash: signed.commitHash,
      solver_signature: signed.solverSignature,
    };

    const first = await commitPost(
      jsonRequest("/api/submissions/commit", body, { "Idempotency-Key": "commit-retry-1" }),
    );
    const firstBody = await first.json();
    expect(first.status).toBe(201);
    expect(first.headers.get("Idempotency-Status")).toBe("stored");

    const replay = await commitPost(
      jsonRequest("/api/submissions/commit", body, { "Idempotency-Key": "commit-retry-1" }),
    );
    const replayBody = await replay.json();
    expect(replay.status).toBe(201);
    expect(replay.headers.get("Idempotency-Status")).toBe("replayed");
    expect(replayBody.commit.id).toBe(firstBody.commit.id);

    const conflict = await commitPost(
      jsonRequest(
        "/api/submissions/commit",
        { ...body, agent_name: "DifferentAgent" },
        { "Idempotency-Key": "commit-retry-1" },
      ),
    );
    expect(conflict.status).toBe(409);
    await expect(conflict.json()).resolves.toMatchObject({
      error: "Idempotency-Key was already used for a different request body",
    });
    expect(readPortalState().events.map((event) => event.type)).toEqual([
      "commit.created",
      "idempotency.stored",
      "idempotency.replayed",
      "idempotency.conflict",
    ]);

    const eventsResponse = await eventsGet(
      new NextRequest("http://localhost/api/events?problem_id=1&type=commit.created"),
    );
    const eventsBody = await eventsResponse.json();
    expect(eventsResponse.status).toBe(200);
    expect(eventsBody).toMatchObject({ count: 1, total: 4, chainComplete: false });
    expect(eventsBody.events[0]).toMatchObject({
      type: "commit.created",
      subjectId: firstBody.commit.id,
      problemId: 1,
      actor: solverAddress.toLowerCase(),
    });

    const firstPage = await eventsGet(new NextRequest("http://localhost/api/events?limit=2"));
    const firstPageBody = await firstPage.json();
    expect(firstPageBody).toMatchObject({ count: 2, total: 4, hasMore: true, chainComplete: false });
    const secondPage = await eventsGet(
      new NextRequest(`http://localhost/api/events?limit=2&after=${firstPageBody.nextAfter}`),
    );
    await expect(secondPage.json()).resolves.toMatchObject({ count: 2, total: 4, hasMore: false });
  });

  it("does not fake-open bonded challenges", async () => {
    const response = await challengePost(
      jsonRequest("/api/challenges", {
        submission_id: "sub_001",
        reason_hash: "0x" + "1".repeat(64),
      }),
    );

    expect(response.status).toBe(501);
    await expect(response.json()).resolves.toMatchObject({
      error: "Bonded challenges are not implemented in the Phase 0 portal",
    });
  });

  it("hard-disables Coinbase Onramp for v1", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const response = await coinbaseSessionPost();

    expect(response.status).toBe(503);
    expect(fetchSpy).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual({
      error: "Coinbase Onramp is disabled for P42 Prizes v1",
      capability: "disabled",
      status_detail: "No Onramp session or reviewed funding flow is available.",
    });
  });

  it("never publishes donation targets from general problem APIs", async () => {
    const listResponse = await problemsGet();
    const list = await listResponse.json();
    expect(listResponse.status).toBe(200);
    expect(list).toHaveLength(10);
    for (const entry of list) {
      expect(entry).not.toHaveProperty("donationTarget");
      expect(entry).not.toHaveProperty("donationWallet");
      expect(Object.keys(entry.chainProvenance).sort()).toEqual([
        "fundingTargetDeployed", "note", "reconciliationOk", "settlementState", "source",
      ]);
    }

    const detailResponse = await problemGet(
      new Request("http://localhost/api/problems/hadamard-mini"),
      { params: Promise.resolve({ slug: "hadamard-mini" }) },
    );
    const detail = await detailResponse.json();
    expect(detailResponse.status).toBe(200);
    expect(detail).not.toHaveProperty("poolAddress");
    expect(detail).not.toHaveProperty("donationWallet");
    expect(detail).not.toHaveProperty("donationTarget");
  });

  it("runs the canonical verifier for the developer shortcut", async () => {
    const response = await solutionsPost(
      jsonRequest("/api/solutions", {
        problem_id: 1,
        agent_name: "RouteAgent",
        solution_raw: solutionRaw,
      }),
    );
    const body = await response.json();

    expect(response.status).toBe(201);
    expect(body.verdict).toMatchObject({
      valid: true,
      solution_hash: sha256SolutionCid(solutionRaw),
      verifier_version: "0.1.1",
    });
    expect(readPortalState().events).toMatchObject([
      {
        type: "verification.completed",
        subjectId: sha256SolutionCid(solutionRaw),
        problemId: 1,
        payload: {
          agentName: "RouteAgent",
          solutionHash: sha256SolutionCid(solutionRaw),
          verifierVersion: "0.1.1",
        },
      },
    ]);
  });

  it("reveals only raw bytes matching the committed content hash", async () => {
    const signed = await signedCommitFields();
    const commitResponse = await commitPost(
      jsonRequest("/api/submissions/commit", {
        problem_id: 1,
        agent_name: "RouteAgent",
        solver_address: solverAddress,
        solution_cid: signed.solutionCid,
        commit_hash: signed.commitHash,
        solver_signature: signed.solverSignature,
      }),
    );
    const commit = await commitResponse.json();
    expect(commitResponse.status).toBe(201);

    const response = await revealPost(
      jsonRequest("/api/submissions/reveal", {
        problem_id: 1,
        commit_id: commit.commit.id,
        solver_address: solverAddress,
        salt: "right-salt",
        solution_raw: '{"n":4,"rows":["++++","++++","++++","++++"]}',
      }),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: "revealed solution bytes do not match committed solution_cid",
    });
  });

  it("replays idempotent reveals instead of mutating an already opened commit twice", async () => {
    const signed = await signedCommitFields();
    const commitResponse = await commitPost(
      jsonRequest("/api/submissions/commit", {
        problem_id: 1,
        agent_name: "RouteAgent",
        solver_address: solverAddress,
        solution_cid: signed.solutionCid,
        commit_hash: signed.commitHash,
        solver_signature: signed.solverSignature,
      }),
    );
    const commit = await commitResponse.json();
    expect(commitResponse.status).toBe(201);

    const body = {
      problem_id: 1,
      commit_id: commit.commit.id,
      solver_address: solverAddress,
      salt: "right-salt",
      solution_raw: solutionRaw,
    };
    const first = await revealPost(
      jsonRequest("/api/submissions/reveal", body, { "Idempotency-Key": "reveal-retry-1" }),
    );
    const firstBody = await first.json();
    expect(first.status).toBe(422);
    expect(first.headers.get("Idempotency-Status")).toBe("stored");

    const replay = await revealPost(
      jsonRequest("/api/submissions/reveal", body, { "Idempotency-Key": "reveal-retry-1" }),
    );
    const replayBody = await replay.json();
    expect(replay.status).toBe(422);
    expect(replay.headers.get("Idempotency-Status")).toBe("replayed");
    expect(replayBody.submission.id).toBe(firstBody.submission.id);
    expect(readPortalState().events.map((event) => event.type)).toEqual([
      "commit.created",
      "submission.rejected",
      "idempotency.stored",
      "idempotency.replayed",
    ]);
  });
});
