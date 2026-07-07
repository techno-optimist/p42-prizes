import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { enforceRateLimit, rateLimitPolicy } from "@/lib/rate-limit";

export async function POST(req: Request) {
  try {
    enforceRateLimit(req, rateLimitPolicy("challenges", { limit: 30, windowMs: 60_000 }));
    await readJson(
      req,
      z.object({
        submission_id: z.string().trim().min(1).max(80),
        reason_hash: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
      }),
    );
    return json(
      {
        error: "Bonded challenges are not implemented in the Phase 0 portal",
        required_next: "persisted submission lookup, bond escrow, resolver transcript, and slashing rules",
      },
      { status: 501 },
    );
  } catch (error) {
    return apiError(error);
  }
}
