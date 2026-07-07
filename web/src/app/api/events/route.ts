import { NextRequest } from "next/server";
import { json } from "@/lib/api";
import { readPortalState, verifyEventChain, type PortalEventType } from "@/lib/portal-store";

const EVENT_TYPES: PortalEventType[] = [
  "commit.created",
  "submission.revealed",
  "submission.rejected",
  "verification.completed",
  "idempotency.reserved",
  "idempotency.cancelled",
  "idempotency.stored",
  "idempotency.replayed",
  "idempotency.conflict",
];

export async function GET(req: NextRequest) {
  const problemIdParam = req.nextUrl.searchParams.get("problem_id");
  const typeParam = req.nextUrl.searchParams.get("type");

  let problemId: number | undefined;
  if (problemIdParam) {
    problemId = Number(problemIdParam);
    if (!Number.isInteger(problemId) || problemId <= 0) {
      return json({ error: "problem_id must be a positive integer" }, { status: 400 });
    }
  }

  if (typeParam && !EVENT_TYPES.includes(typeParam as PortalEventType)) {
    return json({ error: "type is not a recognized portal event" }, { status: 400 });
  }

  const allEvents = readPortalState().events;
  const chain = verifyEventChain(allEvents);
  const events = allEvents.filter((event) => (
    (problemId === undefined || event.problemId === problemId) &&
    (!typeParam || event.type === typeParam)
  ));

  return json({
    count: events.length,
    total: allEvents.length,
    chainComplete: problemId === undefined && !typeParam && chain.ok,
    chainVerified: chain.ok,
    ...(chain.error ? { chainError: chain.error } : {}),
    latestHash: chain.latestHash,
    events,
  });
}
