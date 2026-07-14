import { NextRequest } from "next/server";
import { json } from "@/lib/api";
import { sortLeaderboardRows } from "@/lib/data";
import { loadPortalReadModel } from "@/lib/indexer-read-model";

export async function GET(req: NextRequest) {
  const problemId = Number(req.nextUrl.searchParams.get("problem_id"));
  if (!Number.isInteger(problemId) || problemId <= 0) {
    return json({ error: "problem_id is required" }, { status: 400 });
  }

  const model = await loadPortalReadModel();
  const rows = sortLeaderboardRows(problemId, [...model.submissions]);
  return json(rows.slice(0, 200), {
    headers: {
      "X-P42-Data-Source": model.source,
      "X-P42-Checkpoint-Block": model.provenance.checkpointBlock?.toString() ?? "local-only",
    },
  });
}
