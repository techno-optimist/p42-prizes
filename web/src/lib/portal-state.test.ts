import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Wallet } from "ethers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  commitAuthorizationMessage,
  commitHash,
  commitPreimage,
  createCommit,
  revealCommit,
  sha256SolutionCid,
  verifySolverSignature,
} from "@/lib/portal-state";
import { portalStatePath, readPortalState, resetPortalStateForTests } from "@/lib/portal-store";

const solverAddress = "0x1111111111111111111111111111111111111111";
const solverWallet = new Wallet("0x59c6995e998f97a5a0044966f0945387f6d6616d07a16c6fbfcaeab4f7fca6e5");
const validSolutionRaw = '{"n":4,"rows":["++++","+-+-","++--","+--+"]}';
let stateDir: string;

describe("portal commit-reveal state", () => {
  beforeEach(() => {
    stateDir = mkdtempSync(path.join(tmpdir(), "p42-portal-state-"));
    process.env.P42_PORTAL_STATE_PATH = path.join(stateDir, "state.json");
    resetPortalStateForTests();
  });

  afterEach(() => {
    resetPortalStateForTests();
    delete process.env.P42_PORTAL_STATE_PATH;
    rmSync(stateDir, { recursive: true, force: true });
  });

  it("uses a canonical CID-bound Keccak preimage", () => {
    const preimage = commitPreimage({ solutionCid: "bafy-test", solverAddress, salt: "s3cret" });
    expect(preimage).toBe("p42:v0|cid:9:bafy-test|solver:0x1111111111111111111111111111111111111111|salt:6:s3cret");
    expect(commitHash({ solutionCid: "bafy-test", solverAddress, salt: "s3cret" })).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("honors the explicit portal state path outside test-only code paths", () => {
    expect(portalStatePath()).toBe(path.join(stateDir, "state.json"));
  });

  it("verifies solver address ownership for commit authorization", async () => {
    const solutionCid = sha256SolutionCid(validSolutionRaw);
    const hash = commitHash({ solutionCid, solverAddress: solverWallet.address, salt: "right-salt" });
    const message = commitAuthorizationMessage({
      problemId: 1,
      solverAddress: solverWallet.address,
      solutionCid,
      commitHash: hash,
    });
    const signature = await solverWallet.signMessage(message);

    expect(() =>
      verifySolverSignature({
        problemId: 1,
        solverAddress: solverWallet.address,
        solutionCid,
        commitHash: hash,
        signature,
      }),
    ).not.toThrow();
    expect(() =>
      verifySolverSignature({
        problemId: 1,
        solverAddress,
        solutionCid,
        commitHash: hash,
        signature,
      }),
    ).toThrow("solver_signature does not recover solver_address");
  });

  it("reveals only when the salt opens the recorded commit and assigns frontier credit separately", async () => {
    const commit = createCommit({
      problemId: 1,
      agentName: "VerifierAgent",
      solutionCid: sha256SolutionCid(validSolutionRaw),
      solverAddress,
      commitHash: commitHash({ solutionCid: sha256SolutionCid(validSolutionRaw), solverAddress, salt: "right-salt" }),
    });
    const committedState = readPortalState();
    expect(committedState.commits).toContainEqual(commit);
    expect(committedState.events).toMatchObject([
      {
        sequence: 1,
        type: "commit.created",
        subjectId: commit.id,
        problemId: 1,
        actor: solverAddress,
        prevHash: "genesis",
      },
    ]);
    // The pre-reveal public event must not leak sha256(solution): only the
    // non-reversible commitHash identifies the commit before reveal.
    const commitPayload = committedState.events[0].payload as Record<string, unknown>;
    expect(commitPayload).not.toHaveProperty("solutionCid");
    expect(commitPayload.commitHash).toBe(commit.commitHash);

    const result = await revealCommit({
      commitId: commit.id,
      problemSlug: "hadamard-mini",
      solverAddress,
      salt: "right-salt",
      solutionRaw: validSolutionRaw,
    });

    expect(result.verdict.valid).toBe(true);
    expect(result.submission.commitHash).toBe(commit.commitHash);
    expect(result.submission.credit).toBe("0/1");
    expect(result.submission.state).toBe("rejected");
    expect(result.settlement.eligible).toBe(false);
    const persisted = readPortalState();
    expect(persisted.commits.find((row) => row.id === commit.id)?.revealed).toBe(true);
    expect(persisted.submissions.find((row) => row.id === result.submission.id)).toMatchObject({
      commitHash: commit.commitHash,
      credit: "0/1",
    });
    expect(persisted.events).toHaveLength(2);
    expect(persisted.events[1]).toMatchObject({
      sequence: 2,
      type: "submission.rejected",
      subjectId: result.submission.id,
      problemId: 1,
      actor: solverAddress,
      prevHash: persisted.events[0].eventHash,
    });
    expect(persisted.events[1].eventHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("rejects a reveal with the wrong salt", async () => {
    const commit = createCommit({
      problemId: 1,
      agentName: "VerifierAgent",
      solutionCid: sha256SolutionCid(validSolutionRaw),
      solverAddress,
      commitHash: commitHash({ solutionCid: sha256SolutionCid(validSolutionRaw), solverAddress, salt: "right-salt" }),
    });

    await expect(
      revealCommit({
        commitId: commit.id,
        problemSlug: "hadamard-mini",
        solverAddress,
        salt: "wrong-salt",
        solutionRaw: validSolutionRaw,
      }),
    ).rejects.toThrow("commit preimage does not match recorded hash");
  });

  it("rejects a reveal from a different solver address", async () => {
    const commit = createCommit({
      problemId: 1,
      agentName: "VerifierAgent",
      solutionCid: sha256SolutionCid(validSolutionRaw),
      solverAddress,
      commitHash: commitHash({ solutionCid: sha256SolutionCid(validSolutionRaw), solverAddress, salt: "right-salt" }),
    });

    await expect(
      revealCommit({
        commitId: commit.id,
        problemSlug: "hadamard-mini",
        solverAddress: "0x2222222222222222222222222222222222222222",
        salt: "right-salt",
        solutionRaw: validSolutionRaw,
      }),
    ).rejects.toThrow("solver_address does not match commit owner");
  });

  it("rejects a reveal whose bytes do not match the committed content reference", async () => {
    const committedRaw = '{"n":4,"rows":["++++","+-+-","++--","+--+"]}';
    const differentRaw = '{"n":4,"rows":["++++","++++","++++","++++"]}';
    const solutionCid = sha256SolutionCid(committedRaw);
    const commit = createCommit({
      problemId: 1,
      agentName: "VerifierAgent",
      solutionCid,
      solverAddress,
      commitHash: commitHash({ solutionCid, solverAddress, salt: "right-salt" }),
    });

    await expect(
      revealCommit({
        commitId: commit.id,
        problemSlug: "hadamard-mini",
        solverAddress,
        salt: "right-salt",
        solutionRaw: differentRaw,
      }),
    ).rejects.toThrow("revealed solution bytes do not match committed solution_cid");
  });

  it("credits by commit priority so a later sniper of the same solution is denied", async () => {
    // Both reveals here land on problem 1, whose seed frontier is already at the
    // optimum (0/1), so neither can beat the frontier — every reveal is rejected
    // regardless. What encodes commit priority is `firstCommitter`: only the
    // earliest commit for a given (problem, solutionCid) is ever settlement-
    // eligible, so a sniper who reproduces the solution and reveals first still
    // cannot capture credit.
    const solutionCid = sha256SolutionCid(validSolutionRaw);
    const firstCommit = createCommit({
      problemId: 1,
      agentName: "FirstCommitter",
      solutionCid,
      solverAddress,
      commitHash: commitHash({ solutionCid, solverAddress, salt: "first-salt" }),
    });
    const sniperCommit = createCommit({
      problemId: 1,
      agentName: "Sniper",
      solutionCid,
      solverAddress,
      commitHash: commitHash({ solutionCid, solverAddress, salt: "sniper-salt" }),
    });
    expect(sniperCommit.id).not.toBe(firstCommit.id);

    // Sniper reveals first but is not the earliest committer.
    const sniperResult = await revealCommit({
      commitId: sniperCommit.id,
      problemSlug: "hadamard-mini",
      solverAddress,
      salt: "sniper-salt",
      solutionRaw: validSolutionRaw,
    });
    expect(sniperResult.settlement.eligible).toBe(false);
    expect(sniperResult.submission.state).toBe("rejected");
    const afterSniper = readPortalState();
    const sniperEvent = afterSniper.events.find((event) => event.subjectId === sniperResult.submission.id);
    expect((sniperEvent?.payload as { firstCommitter?: boolean }).firstCommitter).toBe(false);

    // The earliest committer is recognized as the credit-priority owner even
    // though it revealed second.
    const firstResult = await revealCommit({
      commitId: firstCommit.id,
      problemSlug: "hadamard-mini",
      solverAddress,
      salt: "first-salt",
      solutionRaw: validSolutionRaw,
    });
    const afterFirst = readPortalState();
    const firstEvent = afterFirst.events.find((event) => event.subjectId === firstResult.submission.id);
    expect((firstEvent?.payload as { firstCommitter?: boolean }).firstCommitter).toBe(true);
  });
});
