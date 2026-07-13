import { NextRequest } from "next/server";
import { json } from "@/lib/api";
import { sortLeaderboardRows } from "@/lib/data";
import { allSubmissionsShared } from "@/lib/portal-state";

export async function GET(req: NextRequest) {
  const problemId = Number(req.nextUrl.searchParams.get("problem_id"));
  if (!Number.isInteger(problemId) || problemId <= 0) {
    return json({ error: "problem_id is required" }, { status: 400 });
  }

  const rows = sortLeaderboardRows(problemId, await allSubmissionsShared());
  return json(rows.slice(0, 200));
}
