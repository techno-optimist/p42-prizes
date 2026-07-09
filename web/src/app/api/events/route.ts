import { NextRequest } from "next/server";
import { json } from "@/lib/api";
import { readPortalState, type PortalEventType } from "@/lib/portal-store";

const EVENT_TYPES: PortalEventType[] = [
  "commit.created",
  "submission.revealed",
  "submission.rejected",
  "verification.completed",
  "idempotency.stored",
  "idempotency.replayed",
  "idempotency.conflict",
];

export async function GET(req: NextRequest) {
  const problemIdParam = req.nextUrl.searchParams.get("problem_id");
  const typeParam = req.nextUrl.searchParams.get("type");
  const afterParam = req.nextUrl.searchParams.get("after");
  const limitParam = req.nextUrl.searchParams.get("limit");

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

  const after = afterParam === null ? 0 : Number(afterParam);
  if (!Number.isInteger(after) || after < 0) {
    return json({ error: "after must be a non-negative event sequence" }, { status: 400 });
  }
  const limit = limitParam === null ? 100 : Number(limitParam);
  if (!Number.isInteger(limit) || limit < 1 || limit > 250) {
    return json({ error: "limit must be an integer from 1 to 250" }, { status: 400 });
  }

  const state = readPortalState();
  const allEvents = state.events;
  const matching = allEvents.filter((event) => (
    event.sequence > after &&
    (problemId === undefined || event.problemId === problemId) &&
    (!typeParam || event.type === typeParam)
  ));
  const hasMore = matching.length > limit;
  const events = matching.slice(0, limit);

  return json({
    count: events.length,
    total: state.eventOffset + allEvents.length,
    retained: allEvents.length,
    retainedFromSequence: allEvents[0]?.sequence ?? state.eventOffset + 1,
    chainComplete: state.eventOffset === 0 && problemId === undefined && !typeParam && after === 0 && !hasMore,
    latestHash: allEvents.at(-1)?.eventHash ?? state.eventAnchorHash,
    hasMore,
    nextAfter: events.at(-1)?.sequence ?? after,
    events,
  });
}
