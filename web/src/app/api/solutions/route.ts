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
import { appendPortalEvent } from "@/lib/portal-store";
import { enforceRateLimitShared, rateLimitPolicy } from "@/lib/rate-limit";
import { runCanonicalVerifier } from "@/lib/verifier-runner";

const solutionSchema = z.object({
  problem_id: z.coerce.number().int().positive(),
  agent_name: z.string().trim().min(1).max(64).optional(),
  solution_raw: z.string().min(1).max(250_000),
});

export async function POST(req: Request) {
  let idempotency: IdempotencyReservation | undefined;
  try {
    const principal = enforceMutationApiKey(req, "solutions.verify");
    await enforceRateLimitShared(req, rateLimitPolicy("solutions", { limit: 15, windowMs: 60_000 }), principal.rateLimitSubject);
    const body = await readJson(req, solutionSchema);

    const problem = getProblemById(body.problem_id);
    if (!problem) return json({ error: "Problem not found" }, { status: 404 });
    if (problem.slug !== "hadamard-mini") {
      return json(
        { error: "Only hadamard-mini has a canonical verifier runner in this portal slice" },
        { status: 409 },
      );
    }

    const attempt = await beginIdempotentRequest(req, "solutions.verify", body);
    if (attempt.replay) return attempt.replay;
    idempotency = attempt.reservation;

    const verdict = await runCanonicalVerifier({ problemSlug: problem.slug, solutionRaw: body.solution_raw });
    const status = verdict.valid ? 201 : 422;
    const responseBody = { status: verdict.valid ? "accepted" : "rejected", verdict };
    const completed = await completeIdempotentOperation(idempotency, status, (state) => {
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
          settlementState: "local-phase-0-unsettled",
        },
      });
      return responseBody;
    });
    return json(completed.response, { status: completed.status, headers: completed.headers });
  } catch (error) {
    await releaseIdempotencyReservation(idempotency).catch(() => {});
    return apiError(error);
  }
}
