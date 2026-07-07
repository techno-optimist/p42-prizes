import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Wallet } from "ethers";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { POST as challengePost } from "@/app/api/challenges/route";
import { GET as eventsGet } from "@/app/api/events/route";
import { POST as coinbaseSessionPost } from "@/app/api/problems/[slug]/funding/coinbase-session/route";
import { POST as solutionsPost } from "@/app/api/solutions/route";
import { POST as commitPost } from "@/app/api/submissions/commit/route";
import { POST as revealPost } from "@/app/api/submissions/reveal/route";
import { commitAuthorizationMessage, commitHash, sha256SolutionCid } from "@/lib/portal-state";
import { readPortalState, resetPortalStateForTests, writePortalState } from "@/lib/portal-store";
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
    stateDir = mkdtempSync(path.join(tmpdir(), "p42-api-state-"));
    process.env.P42_PORTAL_STATE_PATH = path.join(stateDir, "state.json");
    resetPortalStateForTests();
    resetRateLimitsForTests();
  });

  afterEach(() => {
    resetPortalStateForTests();
    resetRateLimitsForTests();
    delete process.env.P42_PORTAL_STATE_PATH;
    delete process.env.P42_RATE_LIMIT_COMMIT_LIMIT;
    delete process.env.P42_RATE_LIMIT_COMMIT_WINDOW_MS;
    rmSync(stateDir, { recursive: true, force: true });
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
    expect(eventsBody).toMatchObject({ count: 1, total: 4, chainComplete: false, chainVerified: true });
    expect(eventsBody.events[0]).toMatchObject({
      type: "commit.created",
      subjectId: firstBody.commit.id,
      problemId: 1,
      actor: solverAddress.toLowerCase(),
    });
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

  it("reports event-chain tampering instead of claiming diagnostic completeness", async () => {
    const signed = await signedCommitFields();
    const body = {
      problem_id: 1,
      agent_name: "RouteAgent",
      solver_address: solverAddress,
      solution_cid: signed.solutionCid,
      commit_hash: signed.commitHash,
      solver_signature: signed.solverSignature,
    };
    const response = await commitPost(jsonRequest("/api/submissions/commit", body));
    expect(response.status).toBe(201);

    const state = readPortalState();
    state.events[0].payload = { tampered: true };
    writePortalState(state);

    const eventsResponse = await eventsGet(new NextRequest("http://localhost/api/events"));
    const eventsBody = await eventsResponse.json();

    expect(eventsResponse.status).toBe(200);
    expect(eventsBody).toMatchObject({
      chainComplete: false,
      chainVerified: false,
      latestHash: "genesis",
    });
    expect(eventsBody.chainError).toContain("eventHash does not match");
  });

  it("gates Coinbase Onramp sessions for testnet-only donation wallets", async () => {
    const response = await coinbaseSessionPost(
      jsonRequest("/api/problems/hadamard-mini/funding/coinbase-session", {
        preset_fiat_amount: "25.00",
      }),
      { params: Promise.resolve({ slug: "hadamard-mini" }) },
    );

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      error: "Coinbase Onramp is gated until a reviewed Base mainnet pool is configured",
      donationWallet: { chain: "Base Sepolia", asset: "ETH" },
    });
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
      verifier_version: "0.1.0",
    });
    expect(readPortalState().events).toMatchObject([
      {
        type: "verification.completed",
        subjectId: sha256SolutionCid(solutionRaw),
        problemId: 1,
        payload: {
          agentName: "RouteAgent",
          solutionHash: sha256SolutionCid(solutionRaw),
          verifierVersion: "0.1.0",
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
