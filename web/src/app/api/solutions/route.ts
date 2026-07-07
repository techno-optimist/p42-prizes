import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { getProblemById } from "@/lib/data";
import { rememberIdempotentResponse, replayIdempotentResponse } from "@/lib/idempotency";
import { appendPortalEvent, updatePortalState } from "@/lib/portal-store";
import { enforceRateLimit, rateLimitPolicy } from "@/lib/rate-limit";
import { runCanonicalVerifier } from "@/lib/verifier-runner";

const solutionSchema = z.object({
  problem_id: z.coerce.number().int().positive(),
  agent_name: z.string().trim().min(1).max(64).optional(),
  solution_raw: z.string().min(1).max(250_000),
});

export async function POST(req: Request) {
  try {
    enforceRateLimit(req, rateLimitPolicy("solutions", { limit: 15, windowMs: 60_000 }));
    const body = await readJson(req, solutionSchema);
    const replay = replayIdempotentResponse(req, "solutions.verify", body);
    if (replay) return replay;

    const problem = getProblemById(body.problem_id);
    if (!problem) return json({ error: "Problem not found" }, { status: 404 });
    if (problem.slug !== "hadamard-mini") {
      return json(
        { error: "Only hadamard-mini has a canonical verifier runner in this portal slice" },
        { status: 409 },
      );
    }

    const verdict = await runCanonicalVerifier({ problemSlug: problem.slug, solutionRaw: body.solution_raw });
    updatePortalState((state) => {
      appendPortalEvent(state, {
        type: "verification.completed",
        subjectId: verdict.solution_hash,
        problemId: problem.id,
        payload: {
          agentName: body.agent_name ?? null,
          problemSlug: problem.slug,
          valid: verdict.valid,
          score: verdict.score,
          solutionHash: verdict.solution_hash,
          verifierVersion: verdict.verifier_version,
          verifierImage: verdict.verifier_image,
        },
      });
    });
    const status = verdict.valid ? 201 : 422;
    const responseBody = { status: verdict.valid ? "accepted" : "rejected", verdict };
    return json(responseBody, {
      status,
      headers: rememberIdempotentResponse(req, "solutions.verify", body, responseBody, status),
    });
  } catch (error) {
    return apiError(error);
  }
}
