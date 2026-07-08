import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { enforceMutationApiKey } from "@/lib/api-auth";
import { getProblemById } from "@/lib/data";
import { rememberIdempotentResponse, replayIdempotentResponse } from "@/lib/idempotency";
import { revealCommit } from "@/lib/portal-state";
import { enforceRateLimit, rateLimitPolicy } from "@/lib/rate-limit";

const revealSchema = z.object({
  problem_id: z.coerce.number().int().positive(),
  commit_id: z.string().trim().min(1).max(80),
  solver_address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  salt: z.string().min(1).max(256),
  solution_raw: z.string().min(1).max(250_000),
});

export async function POST(req: Request) {
  try {
    enforceRateLimit(req, rateLimitPolicy("reveal", { limit: 20, windowMs: 60_000 }));
    enforceMutationApiKey(req, "submissions.reveal");
    const body = await readJson(req, revealSchema);
    const replay = replayIdempotentResponse(req, "submissions.reveal", body);
    if (replay) return replay;

    const problem = getProblemById(body.problem_id);
    if (!problem) return json({ error: "Problem not found" }, { status: 404 });
    if (problem.slug !== "hadamard-mini") {
      return json({ error: "External verifier runner is not wired in this Phase 0 portal" }, { status: 409 });
    }

    const result = await revealCommit({
      commitId: body.commit_id,
      salt: body.salt,
      solutionRaw: body.solution_raw,
      problemSlug: problem.slug,
      solverAddress: body.solver_address,
    });
    const status = result.submission.state === "revealed" ? 201 : 422;
    return json(result, {
      status,
      headers: rememberIdempotentResponse(req, "submissions.reveal", body, result, status),
    });
  } catch (error) {
    return apiError(error);
  }
}
