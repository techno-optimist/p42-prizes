import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { enforceMutationApiKey } from "@/lib/api-auth";
import { getProblemById } from "@/lib/data";
import {
  beginIdempotentRequest,
  releaseIdempotencyReservation,
  type IdempotencyReservation,
} from "@/lib/idempotency";
import { revealCommit } from "@/lib/portal-state";
import { enforceRateLimitShared, rateLimitPolicy } from "@/lib/rate-limit";

const revealSchema = z.object({
  problem_id: z.coerce.number().int().positive(),
  commit_id: z.string().trim().min(1).max(80),
  solver_address: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  salt: z.string().min(1).max(256),
  solution_raw: z.string().min(1).max(250_000),
});

export async function POST(req: Request) {
  let idempotency: IdempotencyReservation | undefined;
  try {
    const principal = enforceMutationApiKey(req, "submissions.reveal");
    await enforceRateLimitShared(req, rateLimitPolicy("reveal", { limit: 20, windowMs: 60_000 }), principal.rateLimitSubject);
    const body = await readJson(req, revealSchema);

    const problem = getProblemById(body.problem_id);
    if (!problem) return json({ error: "Problem not found" }, { status: 404 });
    if (problem.slug !== "hadamard-mini") {
      return json({ error: "External verifier runner is not wired in this Phase 0 portal" }, { status: 409 });
    }

    const attempt = await beginIdempotentRequest(req, "submissions.reveal", body);
    if (attempt.replay) return attempt.replay;
    idempotency = attempt.reservation;

    const result = await revealCommit({
      commitId: body.commit_id,
      salt: body.salt,
      solutionRaw: body.solution_raw,
      problemSlug: problem.slug,
      solverAddress: body.solver_address,
    }, idempotency);
    const { idempotencyHeaders, status, ...responseBody } = result;
    return json(responseBody, { status, headers: idempotencyHeaders });
  } catch (error) {
    await releaseIdempotencyReservation(idempotency).catch(() => {});
    return apiError(error);
  }
}
