import { json } from "@/lib/api";
import { loadPortalReadModel } from "@/lib/indexer-read-model";
import { publicChainProvenance, publicPoolSummary } from "@/lib/public-problem";

export async function GET() {
  const model = await loadPortalReadModel();
  return json(
    model.problems.map((problem) => {
      return {
        id: problem.id,
        slug: problem.slug,
        title: problem.title,
        status: problem.status,
        mode: problem.mode,
        direction: problem.direction,
        scoreName: problem.scoreName,
        currentBest: problem.currentBest,
        minImprovement: problem.minImprovement,
        bountyEth: problem.bountyEth,
        source: problem.source,
        pool: publicPoolSummary(problem.pool),
        chainProvenance: publicChainProvenance(problem.chainProvenance),
        challengeWindowHours: problem.challengeWindowHours,
        verifierVersion: problem.verifierVersion,
      };
    }),
    { headers: { "X-P42-Data-Source": model.source } },
  );
}
