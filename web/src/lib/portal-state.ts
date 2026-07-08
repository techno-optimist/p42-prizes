import { createHash, randomUUID } from "crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { verifyMessage } from "ethers";
import { getProblemById, submissions } from "@/lib/data";
import { ClientError } from "@/lib/errors";
import { incrementalFrontierCredit } from "@/lib/frontier";
import type { Submission } from "@/lib/types";
import { appendPortalEvent, readPortalState, updatePortalState, type CommitRecord } from "@/lib/portal-store";
import { runCanonicalVerifier } from "@/lib/verifier-runner";

const EVM_ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const COMMIT_HASH = /^0x[a-fA-F0-9]{64}$/;

export function allSubmissions(): Submission[] {
  return [...submissions, ...readPortalState().submissions];
}

export function normalizeSolverAddress(address: string): string {
  if (!EVM_ADDRESS.test(address)) throw new ClientError("solver_address must be a 20-byte 0x-prefixed EVM address");
  return address.toLowerCase();
}

export function isCommitHash(value: string): boolean {
  return COMMIT_HASH.test(value);
}

export function commitPreimage(input: { solutionCid: string; solverAddress: string; salt: string }): string {
  const solverAddress = normalizeSolverAddress(input.solverAddress);
  return [
    "p42:v0",
    `cid:${input.solutionCid.length}:${input.solutionCid}`,
    `solver:${solverAddress}`,
    `salt:${input.salt.length}:${input.salt}`,
  ].join("|");
}

export function commitHash(input: { solutionCid: string; solverAddress: string; salt: string }): string {
  return `0x${bytesToHex(keccak_256(utf8ToBytes(commitPreimage(input))))}`;
}

export function commitAuthorizationMessage(input: {
  problemId: number;
  solverAddress: string;
  solutionCid: string;
  commitHash: string;
}): string {
  const solverAddress = normalizeSolverAddress(input.solverAddress);
  if (!isCommitHash(input.commitHash)) throw new ClientError("commit_hash must be a 32-byte 0x-prefixed hash");
  return [
    "P42 Prizes commit authorization",
    "version: p42-commit-v0",
    "chain: base-sepolia",
    `problem_id: ${input.problemId}`,
    `solver_address: ${solverAddress}`,
    `solution_cid: ${input.solutionCid}`,
    `commit_hash: ${input.commitHash.toLowerCase()}`,
  ].join("\n");
}

export function verifySolverSignature(input: {
  problemId: number;
  solverAddress: string;
  solutionCid: string;
  commitHash: string;
  signature: string;
}): void {
  const expected = normalizeSolverAddress(input.solverAddress);
  let recovered: string;
  try {
    recovered = verifyMessage(commitAuthorizationMessage(input), input.signature).toLowerCase();
  } catch {
    throw new ClientError("solver_signature is not a valid EIP-191 signature");
  }
  if (recovered !== expected) {
    throw new ClientError("solver_signature does not recover solver_address");
  }
}

export function sha256SolutionCid(rawSolution: string): string {
  return `sha256:${createHash("sha256").update(rawSolution, "utf8").digest("hex")}`;
}

function assertSolutionMatchesCid(solutionCid: string, rawSolution: string) {
  if (!solutionCid.startsWith("sha256:")) {
    throw new ClientError("Phase 0 reveal requires solution_cid=sha256:<raw-solution-hash>; external CID retrieval is not wired");
  }
  const actual = sha256SolutionCid(rawSolution);
  if (actual !== solutionCid.toLowerCase()) {
    throw new ClientError("revealed solution bytes do not match committed solution_cid");
  }
}

export function createCommit(input: {
  problemId: number;
  agentName: string;
  solutionCid: string;
  solverAddress: string;
  commitHash?: string;
  devSalt?: string;
}): CommitRecord {
  const solverAddress = normalizeSolverAddress(input.solverAddress);
  const computedHash = input.devSalt
    ? commitHash({ solutionCid: input.solutionCid, solverAddress, salt: input.devSalt })
    : undefined;
  const commitHashValue = input.commitHash ?? computedHash;
  if (!commitHashValue) {
    throw new ClientError("commit_hash is required unless dev_salt is supplied for local simulation");
  }
  if (!isCommitHash(commitHashValue)) throw new ClientError("commit_hash must be a 32-byte 0x-prefixed hash");

  const record: CommitRecord = {
    id: `commit_${randomUUID().slice(0, 8)}`,
    problemId: input.problemId,
    agentName: input.agentName,
    solverAddress,
    solutionCid: input.solutionCid,
    commitHash: commitHashValue.toLowerCase(),
    commitAlgorithm: "keccak256-p42-v0",
    createdAt: new Date().toISOString(),
    revealed: false,
  };
  updatePortalState((state) => {
    if (state.commits.some((commit) => commit.commitHash === record.commitHash)) {
      throw new ClientError("a commit with this commit_hash already exists");
    }
    state.commits.push(record);
    appendPortalEvent(state, {
      type: "commit.created",
      subjectId: record.id,
      problemId: record.problemId,
      actor: record.solverAddress,
      // The solution CID is sha256(solution). Exposing it before reveal lets an
      // observer brute-force/verify the solution and snipe the commit-reveal, so
      // it stays in the server-side commit record only. The public identifier is
      // the commitHash, which is keccak over a preimage that includes the secret
      // salt and is therefore not reversible to the solution.
      payload: {
        agentName: record.agentName,
        solverAddress: record.solverAddress,
        commitHash: record.commitHash,
        commitAlgorithm: record.commitAlgorithm,
      },
    });
  });
  return record;
}

export async function revealCommit(input: {
  commitId: string;
  salt: string;
  solutionRaw: string;
  problemSlug: string;
  solverAddress: string;
}) {
  const state = readPortalState();
  const record = state.commits.find((commit) => commit.id === input.commitId);
  if (!record) throw new ClientError("commit not found");
  if (record.revealed) throw new ClientError("commit already revealed");
  const problem = getProblemById(record.problemId);
  if (!problem) throw new ClientError("problem not found");
  if (problem.slug !== input.problemSlug) throw new ClientError("problem does not match commit");

  const solverAddress = normalizeSolverAddress(input.solverAddress);
  if (solverAddress !== record.solverAddress) throw new ClientError("solver_address does not match commit owner");

  const openedHash = commitHash({ solutionCid: record.solutionCid, solverAddress, salt: input.salt });
  if (openedHash !== record.commitHash) throw new ClientError("commit preimage does not match recorded hash");

  if (input.problemSlug !== "hadamard-mini") {
    throw new ClientError("external verifier runner is not wired in the Phase 0 portal");
  }
  assertSolutionMatchesCid(record.solutionCid, input.solutionRaw);

  // Reserve the reveal atomically before the expensive verifier call so two
  // concurrent reveals of the same commit can't both run the verifier and both
  // record a submission.
  updatePortalState((state) => {
    const storedCommit = state.commits.find((commit) => commit.id === input.commitId);
    if (!storedCommit) throw new ClientError("commit not found");
    if (storedCommit.revealed) throw new ClientError("commit already revealed");
    if (storedCommit.revealState === "pending") throw new ClientError("commit reveal already in progress");
    storedCommit.revealState = "pending";
  });

  try {
    const verdict = await runCanonicalVerifier({ problemSlug: input.problemSlug, solutionRaw: input.solutionRaw });

    let submission!: Submission;
    let settlement!: ReturnType<typeof incrementalFrontierCredit>;
    updatePortalState((nextState) => {
      const storedCommit = nextState.commits.find((commit) => commit.id === input.commitId);
      if (!storedCommit) throw new ClientError("commit not found");
      if (storedCommit.revealed) throw new ClientError("commit already revealed");

      // Credit follows COMMIT priority, not reveal order. Only the earliest
      // commit for a given (problem, solutionCid) is ever eligible for credit,
      // so a sniper who reproduces an earlier commit's solution (e.g. by
      // brute-forcing a leaked content hash) cannot front-run the reveal and
      // capture the delta the first committer is owed. Insertion order in the
      // commit log is the tiebreak, which is robust to same-millisecond commits.
      const firstMatchingCommit = nextState.commits.find(
        (commit) => commit.problemId === record.problemId && commit.solutionCid === record.solutionCid,
      );
      const isFirstCommitter = firstMatchingCommit?.id === storedCommit.id;

      // Compute the credit against the frontier under the same lock that
      // persists it, using the committed submissions, so a concurrent reveal
      // can't be credited for the same delta.
      settlement = verdict.valid && isFirstCommitter
        ? incrementalFrontierCredit(problem, verdict.score, [...submissions, ...nextState.submissions])
        : { credit: "0/1", priorBest: frontierFallback(problem), eligible: false };

      const now = new Date();
      const windowEnd = new Date(now.getTime() + 72 * 60 * 60 * 1000);
      submission = {
        id: `sub_${randomUUID().slice(0, 8)}`,
        problemId: record.problemId,
        problemSlug: input.problemSlug,
        agentName: record.agentName,
        state: verdict.valid && settlement.eligible ? "revealed" : "rejected",
        score: verdict.score,
        improvement: settlement.credit,
        credit: settlement.credit,
        payoutEth: "0.000",
        solutionCid: record.solutionCid,
        commitHash: record.commitHash,
        submittedAt: now.toISOString(),
        windowEndsAt: windowEnd.toISOString(),
        transcriptCid: null,
      };

      storedCommit.revealed = true;
      delete storedCommit.revealState;
      nextState.submissions.push(submission);
      appendPortalEvent(nextState, {
        type: submission.state === "revealed" ? "submission.revealed" : "submission.rejected",
        subjectId: submission.id,
        problemId: submission.problemId,
        actor: solverAddress,
        payload: {
          commitId: input.commitId,
          commitHash: record.commitHash,
          solutionCid: record.solutionCid,
          solutionHash: verdict.solution_hash,
          valid: verdict.valid,
          score: verdict.score,
          credit: submission.credit,
          eligible: settlement.eligible,
          firstCommitter: isFirstCommitter,
        },
      });
    });
    return { submission, verdict, settlement };
  } catch (error) {
    // Release the reservation so a transient verifier failure doesn't wedge the
    // commit as permanently un-revealable.
    updatePortalState((state) => {
      const storedCommit = state.commits.find((commit) => commit.id === input.commitId);
      if (storedCommit && !storedCommit.revealed && storedCommit.revealState === "pending") {
        delete storedCommit.revealState;
      }
    });
    throw error;
  }
}

function frontierFallback(problem: NonNullable<ReturnType<typeof getProblemById>>): string {
  return problem.currentBest;
}
