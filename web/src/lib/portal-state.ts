import { createHash, randomUUID } from "crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { verifyMessage } from "ethers";
import { ApiError } from "@/lib/api";
import { getProblemById, submissions } from "@/lib/data";
import { incrementalFrontierCredit } from "@/lib/frontier";
import type { Submission } from "@/lib/types";
import { appendPortalEvent, readPortalState, updatePortalState, type CommitRecord } from "@/lib/portal-store";
import { runCanonicalVerifier } from "@/lib/verifier-runner";

const EVM_ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const COMMIT_HASH = /^0x[a-fA-F0-9]{64}$/;
const LOCAL_SOLUTION_CID = /^sha256:[a-f0-9]{64}$/;

export function allSubmissions(): Submission[] {
  return [...submissions, ...readPortalState().submissions];
}

export function normalizeSolverAddress(address: string): string {
  if (!EVM_ADDRESS.test(address)) {
    throw new ApiError("solver_address must be a 20-byte 0x-prefixed EVM address", 400);
  }
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
  if (!isCommitHash(input.commitHash)) throw new ApiError("commit_hash must be a 32-byte 0x-prefixed hash", 400);
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
    throw new ApiError("solver_signature is not a valid EIP-191 signature", 400);
  }
  if (recovered !== expected) {
    throw new ApiError("solver_signature does not recover solver_address", 400);
  }
}

export function sha256SolutionCid(rawSolution: string): string {
  return `sha256:${createHash("sha256").update(rawSolution, "utf8").digest("hex")}`;
}

export function isLocalSolutionCid(solutionCid: string): boolean {
  return LOCAL_SOLUTION_CID.test(solutionCid);
}

function assertLocalSolutionCid(solutionCid: string) {
  if (!isLocalSolutionCid(solutionCid)) {
    throw new ApiError(
      "Phase 0 commit requires solution_cid=sha256:<raw-solution-hash>; DA-backed external CIDs are gated until commit-time availability is implemented",
      409,
    );
  }
}

function assertSolutionMatchesCid(solutionCid: string, rawSolution: string) {
  if (!isLocalSolutionCid(solutionCid)) {
    throw new ApiError(
      "Phase 0 reveal requires solution_cid=sha256:<raw-solution-hash>; external CID retrieval is not wired",
      409,
    );
  }
  const actual = sha256SolutionCid(rawSolution);
  if (actual !== solutionCid) {
    throw new ApiError("revealed solution bytes do not match committed solution_cid", 400);
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
  assertLocalSolutionCid(input.solutionCid);
  const computedHash = input.devSalt
    ? commitHash({ solutionCid: input.solutionCid, solverAddress, salt: input.devSalt })
    : undefined;
  const commitHashValue = input.commitHash ?? computedHash;
  if (!commitHashValue) {
    throw new ApiError("commit_hash is required unless dev_salt is supplied for local simulation", 400);
  }
  if (!isCommitHash(commitHashValue)) throw new ApiError("commit_hash must be a 32-byte 0x-prefixed hash", 400);

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
    const duplicate = state.commits.find((commit) => (
      commit.problemId === record.problemId &&
      commit.solverAddress === record.solverAddress &&
      commit.commitHash === record.commitHash
    ));
    if (duplicate) throw new ApiError("commit_hash already exists for this problem and solver", 409);
    state.commits.push(record);
    appendPortalEvent(state, {
      type: "commit.created",
      subjectId: record.id,
      problemId: record.problemId,
      actor: record.solverAddress,
      payload: {
        agentName: record.agentName,
        solverAddress: record.solverAddress,
        solutionCid: record.solutionCid,
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
  if (!record) throw new ApiError("commit not found", 404);
  if (record.revealed) throw new ApiError("commit already revealed", 409);
  const problem = getProblemById(record.problemId);
  if (!problem) throw new ApiError("problem not found", 404);
  if (problem.slug !== input.problemSlug) throw new ApiError("problem does not match commit", 400);

  const solverAddress = normalizeSolverAddress(input.solverAddress);
  if (solverAddress !== record.solverAddress) throw new ApiError("solver_address does not match commit owner", 400);

  const openedHash = commitHash({ solutionCid: record.solutionCid, solverAddress, salt: input.salt });
  if (openedHash !== record.commitHash) throw new ApiError("commit preimage does not match recorded hash", 400);

  if (input.problemSlug !== "hadamard-mini") {
    throw new ApiError("external verifier runner is not wired in the Phase 0 portal", 409);
  }
  assertSolutionMatchesCid(record.solutionCid, input.solutionRaw);

  const verdict = await runCanonicalVerifier({ problemSlug: input.problemSlug, solutionRaw: input.solutionRaw });
  const settlement = verdict.valid
    ? incrementalFrontierCredit(problem, verdict.score, allSubmissions())
    : { credit: "0/1", priorBest: frontierFallback(problem), eligible: false };

  const now = new Date();
  const windowEnd = new Date(now.getTime() + 72 * 60 * 60 * 1000);
  const submission: Submission = {
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
  updatePortalState((nextState) => {
    const storedCommit = nextState.commits.find((commit) => commit.id === input.commitId);
    if (!storedCommit) throw new ApiError("commit not found", 404);
    if (storedCommit.revealed) throw new ApiError("commit already revealed", 409);
    storedCommit.revealed = true;
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
      },
    });
  });
  return { submission, verdict, settlement };
}

function frontierFallback(problem: NonNullable<ReturnType<typeof getProblemById>>): string {
  return problem.currentBest;
}
