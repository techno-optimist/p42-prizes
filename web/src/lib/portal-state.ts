import { createHash, randomUUID } from "crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { verifyMessage } from "ethers";
import { getProblemById, submissions } from "@/lib/data";
import { ClientError } from "@/lib/errors";
import { incrementalFrontierCredit } from "@/lib/frontier";
import { completeIdempotentOperation, type IdempotencyReservation } from "@/lib/idempotency";
import type { Submission, VerdictReport } from "@/lib/types";
import {
  appendPortalEvent,
  assertPortalCapacity,
  commitIsExpired,
  leaseIsActive,
  portalLifecyclePolicy,
  readPortalState,
  updatePortalState,
  type CommitRecord,
  type PortalStateSnapshot,
} from "@/lib/portal-store";
import { runCanonicalVerifier } from "@/lib/verifier-runner";

const EVM_ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const COMMIT_HASH = /^0x[a-fA-F0-9]{64}$/;

interface LocalRevealResult {
  submission: Submission;
  verdict: VerdictReport;
  settlement: {
    state: "local-phase-0-unsettled";
    credit: "0/1";
    provisionalCredit: string;
    priorBest: string;
    eligible: false;
    provisionalEligible: boolean;
  };
}

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
  const record = prepareCommit(input);
  updatePortalState((state) => persistCommit(state, record));
  return record;
}

export function prepareCommit(input: {
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

  const createdAt = new Date();
  return {
    id: `commit_${randomUUID().slice(0, 8)}`,
    problemId: input.problemId,
    agentName: input.agentName,
    solverAddress,
    solutionCid: input.solutionCid,
    commitHash: commitHashValue.toLowerCase(),
    commitAlgorithm: "keccak256-p42-local-v0",
    createdAt: createdAt.toISOString(),
    expiresAt: new Date(createdAt.getTime() + portalLifecyclePolicy().commitTtlMs).toISOString(),
    revealed: false,
  };
}

export function persistCommit(state: PortalStateSnapshot, record: CommitRecord): void {
  if (state.commits.some((commit) => commit.commitHash === record.commitHash)) {
    throw new ClientError("a commit with this commit_hash already exists");
  }
  assertPortalCapacity(state, "commits");
  state.commits.push(record);
  appendPortalEvent(state, {
    type: "commit.created",
    subjectId: record.id,
    problemId: record.problemId,
    actor: record.solverAddress,
    // The content hash stays server-side before reveal; the salted commit hash
    // is the only public identifier in this local Phase-0 event.
    payload: {
      agentName: record.agentName,
      solverAddress: record.solverAddress,
      commitHash: record.commitHash,
      commitAlgorithm: record.commitAlgorithm,
      commitDomain: "local-phase-0",
      chainCompatible: false,
    },
  });
}

export async function revealCommit(input: {
  commitId: string;
  salt: string;
  solutionRaw: string;
  problemSlug: string;
  solverAddress: string;
}, idempotency?: IdempotencyReservation) {
  const state = readPortalState();
  const record = state.commits.find((commit) => commit.id === input.commitId);
  if (!record) throw new ClientError("commit not found");
  if (record.revealed) throw new ClientError("commit already revealed");
  if (commitIsExpired(record)) throw new ClientError("commit expired before reveal");
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
  const revealLeaseId = randomUUID();
  updatePortalState((state) => {
    const storedCommit = state.commits.find((commit) => commit.id === input.commitId);
    if (!storedCommit) throw new ClientError("commit not found");
    if (storedCommit.revealed) throw new ClientError("commit already revealed");
    if (commitIsExpired(storedCommit)) throw new ClientError("commit expired before reveal");
    if (leaseIsActive(storedCommit.revealLease)) throw new ClientError("commit reveal already in progress");
    storedCommit.revealLease = {
      id: revealLeaseId,
      expiresAt: new Date(Date.now() + portalLifecyclePolicy().revealLeaseMs).toISOString(),
    };
  });

  try {
    const verdict = await runCanonicalVerifier({ problemSlug: input.problemSlug, solutionRaw: input.solutionRaw });

    const completed = completeIdempotentOperation<LocalRevealResult>(
      idempotency,
      (result) => result.submission.state === "revealed" ? 201 : 422,
      (nextState) => {
      const storedCommit = nextState.commits.find((commit) => commit.id === input.commitId);
      if (!storedCommit) throw new ClientError("commit not found");
      if (storedCommit.revealed) throw new ClientError("commit already revealed");
      if (storedCommit.revealLease?.id !== revealLeaseId) {
        throw new ClientError("reveal lease expired; retry the reveal");
      }

      // Credit follows COMMIT priority, not reveal order. Only the earliest
      // commit for a given (problem, solutionCid) is ever eligible for credit,
      // so a sniper who reproduces an earlier commit's solution (e.g. by
      // brute-forcing a leaked content hash) cannot front-run the reveal and
      // capture the delta the first committer is owed. Insertion order in the
      // commit log is the tiebreak, which is robust to same-millisecond commits.
      const firstMatchingCommit = nextState.commits.find(
        (commit) => commit.problemId === record.problemId
          && commit.solutionCid === record.solutionCid
          && !commit.abandonedAt
          && (commit.revealed || commit.revealLease !== undefined || !commitIsExpired(commit)),
      );
      const isFirstCommitter = firstMatchingCommit?.id === storedCommit.id;

      // Compute the credit against the frontier under the same lock that
      // persists it, using the committed submissions, so a concurrent reveal
      // can't be credited for the same delta.
      const settlement = verdict.valid && isFirstCommitter
        ? incrementalFrontierCredit(problem, verdict.score, [...submissions, ...nextState.submissions])
        : { credit: "0/1", priorBest: frontierFallback(problem), eligible: false };

      const now = new Date();
      const windowEnd = new Date(now.getTime() + 72 * 60 * 60 * 1000);
      const submission: Submission = {
        id: `sub_${randomUUID().slice(0, 8)}`,
        problemId: record.problemId,
        problemSlug: input.problemSlug,
        agentName: record.agentName,
        source: "local-phase-0",
        settlementState: verdict.valid && settlement.eligible ? "unsettled" : "ineligible",
        state: verdict.valid && settlement.eligible ? "revealed" : "rejected",
        score: verdict.score,
        improvement: "0/1",
        provisionalImprovement: settlement.credit,
        credit: "0/1",
        payoutEth: "0.000",
        solutionCid: record.solutionCid,
        commitHash: record.commitHash,
        submittedAt: now.toISOString(),
        windowEndsAt: windowEnd.toISOString(),
        transcriptCid: null,
      };

      assertPortalCapacity(nextState, "submissions");
      storedCommit.revealed = true;
      delete storedCommit.revealLease;
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
          credit: "0/1",
          provisionalImprovement: submission.provisionalImprovement,
          provisionalEligible: settlement.eligible,
          firstCommitter: isFirstCommitter,
          settlementState: "local-phase-0-unsettled",
        },
      });
      return {
        submission,
        verdict,
        settlement: {
          state: "local-phase-0-unsettled" as const,
          credit: "0/1",
          provisionalCredit: settlement.credit,
          priorBest: settlement.priorBest,
          eligible: false,
          provisionalEligible: settlement.eligible,
        },
      };
    });
    return { ...completed.response, idempotencyHeaders: completed.headers, status: completed.status };
  } catch (error) {
    // Release the reservation so a transient verifier failure doesn't wedge the
    // commit as permanently un-revealable.
    updatePortalState((state) => {
      const storedCommit = state.commits.find((commit) => commit.id === input.commitId);
      if (storedCommit && !storedCommit.revealed && storedCommit.revealLease?.id === revealLeaseId) {
        delete storedCommit.revealLease;
      }
    });
    throw error;
  }
}

function frontierFallback(problem: NonNullable<ReturnType<typeof getProblemById>>): string {
  return problem.currentBest;
}
