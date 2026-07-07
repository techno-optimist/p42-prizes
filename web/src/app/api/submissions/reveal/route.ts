import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { getProblemById } from "@/lib/data";
import {
  cancelIdempotentReservation,
  rememberIdempotentResponse,
  replayIdempotentResponse,
  reserveIdempotentRequest,
} from "@/lib/idempotency";
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
  let idempotencyReservation: { route: string; body: unknown } | undefined;
  let sideEffectCommitted = false;
  try {
    enforceRateLimit(req, rateLimitPolicy("reveal", { limit: 20, windowMs: 60_000 }));
    const body = await readJson(req, revealSchema);
    const replay = replayIdempotentResponse(req, "submissions.reveal", body);
    if (replay) return replay;

    const problem = getProblemById(body.problem_id);
    if (!problem) return json({ error: "Problem not found" }, { status: 404 });
    if (problem.slug !== "hadamard-mini") {
      return json({ error: "External verifier runner is not wired in this Phase 0 portal" }, { status: 409 });
    }

    const reservedReplay = reserveIdempotentRequest(req, "submissions.reveal", body);
    if (reservedReplay) return reservedReplay;
    if (req.headers.get("Idempotency-Key")) {
      idempotencyReservation = { route: "submissions.reveal", body };
    }

    const result = await revealCommit({
      commitId: body.commit_id,
      salt: body.salt,
      solutionRaw: body.solution_raw,
      problemSlug: problem.slug,
      solverAddress: body.solver_address,
    });
    sideEffectCommitted = true;
    const status = result.submission.state === "revealed" ? 201 : 422;
    const headers = rememberIdempotentResponse(req, "submissions.reveal", body, result, status);
    idempotencyReservation = undefined;
    return json(result, {
      status,
      headers,
    });
  } catch (error) {
    if (idempotencyReservation && !sideEffectCommitted) {
      try {
        cancelIdempotentReservation(req, idempotencyReservation.route, idempotencyReservation.body, "side-effect-not-committed");
      } catch {
        // Preserve the original route error; a failed cancellation leaves the key pending fail-closed.
      }
    }
    return apiError(error);
  }
}
