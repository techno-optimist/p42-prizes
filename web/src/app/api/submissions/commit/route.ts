import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { getProblemById } from "@/lib/data";
import { rememberIdempotentResponse, replayIdempotentResponse } from "@/lib/idempotency";
import { commitHash, createCommit, verifySolverSignature } from "@/lib/portal-state";
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
  try {
    enforceRateLimit(req, rateLimitPolicy("commit", { limit: 30, windowMs: 60_000 }));
    const body = await readJson(req, commitSchema);
    const replay = replayIdempotentResponse(req, "submissions.commit", body);
    if (replay) return replay;

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

    const commit = createCommit({
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
      note: body.dev_salt
        ? "Phase 0 portal computed the commit from dev_salt; production clients must precompute commit_hash and sign the authorization message off-server."
        : "Commit accepted with solver signature over the P42 authorization message.",
    };

    return json(responseBody, {
      status: 201,
      headers: rememberIdempotentResponse(req, "submissions.commit", body, responseBody, 201),
    });
  } catch (error) {
    return apiError(error);
  }
}
