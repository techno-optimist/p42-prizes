import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { enforceMutationApiKey } from "@/lib/api-auth";
import { getProblemById } from "@/lib/data";
import {
  beginIdempotentRequest,
  completeIdempotentOperation,
  releaseIdempotencyReservation,
  type IdempotencyReservation,
} from "@/lib/idempotency";
import { commitHash, persistCommit, prepareCommit, verifySolverSignature } from "@/lib/portal-state";
import { enforceRateLimit, rateLimitPolicy } from "@/lib/rate-limit";

const commitSchema = z.object({
  problem_id: z.coerce.number().int().positive(),
  agent_name: z.string().trim().min(1).max(64),
  solver_address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  solution_cid: z.string().trim().min(1).max(256),
  commit_hash: z.string().regex(/^0x[a-fA-F0-9]{64}$/).optional(),
  solver_signature: z.string().trim().min(1).max(256).optional(),
  dev_salt: z.string().min(1).max(256).optional(),
});

export async function POST(req: Request) {
  let idempotency: IdempotencyReservation | undefined;
  try {
    const principal = enforceMutationApiKey(req, "submissions.commit");
    enforceRateLimit(req, rateLimitPolicy("commit", { limit: 30, windowMs: 60_000 }), principal.rateLimitSubject);
    const body = await readJson(req, commitSchema);

    const problemId = body.problem_id;
    const problem = getProblemById(problemId);
    if (!problem) return json({ error: "Problem not found" }, { status: 404 });
    if (problem.status === "locked" || problem.status === "resolved" || problem.slug !== "hadamard-mini") {
      return json({ error: "Submissions are enabled only for runnable Phase 0 pilot problems" }, { status: 409 });
    }
    if (body.dev_salt && process.env.NODE_ENV === "production" && process.env.P42_ALLOW_DEV_SALT !== "1") {
      return json({ error: "dev_salt is disabled outside local development" }, { status: 400 });
    }
    if (!body.commit_hash && !body.dev_salt) {
      return json({ error: "commit_hash is required unless dev_salt is supplied for local simulation" }, { status: 400 });
    }
    const devCommitHash = body.dev_salt ? commitHash({
      solutionCid: body.solution_cid,
      solverAddress: body.solver_address,
      salt: body.dev_salt,
    }) : undefined;
    if (body.commit_hash && devCommitHash && body.commit_hash.toLowerCase() !== devCommitHash) {
      return json({ error: "commit_hash does not match dev_salt preimage" }, { status: 400 });
    }
    const commitHashValue = body.commit_hash ?? devCommitHash;
    if (!commitHashValue) {
      return json({ error: "commit_hash is required unless dev_salt is supplied for local simulation" }, { status: 400 });
    }
    if (!body.dev_salt && !body.solver_signature) {
      return json({ error: "solver_signature is required for non-local commit flow" }, { status: 400 });
    }
    if (body.solver_signature) {
      verifySolverSignature({
        problemId,
        solverAddress: body.solver_address,
        solutionCid: body.solution_cid,
        commitHash: commitHashValue,
        signature: body.solver_signature,
      });
    }

    const attempt = beginIdempotentRequest(req, "submissions.commit", body);
    if (attempt.replay) return attempt.replay;
    idempotency = attempt.reservation;

    const commit = prepareCommit({
      problemId,
      agentName: body.agent_name,
      solutionCid: body.solution_cid,
      solverAddress: body.solver_address,
      commitHash: commitHashValue,
      devSalt: body.dev_salt,
    });

    const responseBody = {
      commit,
      reveal_after: commit.createdAt,
      expires_at: commit.expiresAt,
      commit_domain: "local-phase-0",
      chain_commit_version: "p42:v1",
      chain_compatible: false,
      note: body.dev_salt
        ? "Local Phase 0 computed p42:v0 from dev_salt. This non-settlement commitment is not a chain p42:v1 commitment."
        : "Local Phase 0 p42:v0 commit accepted with solver authorization. It is not a chain p42:v1 commitment.",
    };
    const completed = completeIdempotentOperation(idempotency, 201, (state) => {
      persistCommit(state, commit);
      return responseBody;
    });

    return json(completed.response, { status: completed.status, headers: completed.headers });
  } catch (error) {
    releaseIdempotencyReservation(idempotency);
    return apiError(error);
  }
}
