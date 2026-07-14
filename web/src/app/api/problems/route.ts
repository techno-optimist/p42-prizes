import { json } from "@/lib/api";
import {
  publicDonationWallet,
  publishedDonationTarget,
} from "@/lib/chain-provenance";
import { loadPortalReadModel } from "@/lib/indexer-read-model";

export async function GET() {
  const model = await loadPortalReadModel();
  return json(
    model.problems.map((problem) => {
      const chainProvenance = problem.chainProvenance;
      const donationTarget = publishedDonationTarget(problem.donationWallet, chainProvenance);
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
        pool: problem.pool,
        donationWallet: publicDonationWallet(problem.donationWallet, chainProvenance),
        donationTarget,
        chainProvenance,
        challengeWindowHours: problem.challengeWindowHours,
        verifierVersion: problem.verifierVersion,
      };
    }),
    { headers: { "X-P42-Data-Source": model.source } },
  );
}
