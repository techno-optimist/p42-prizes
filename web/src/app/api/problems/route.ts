import { json } from "@/lib/api";
import {
  chainProvenanceForProblem,
  publicDonationWallet,
  publishedDonationTarget,
} from "@/lib/chain-provenance";
import { launchProblems } from "@/lib/data";
import { loadIndexerProvenanceSnapshot } from "@/lib/indexer-provenance";

export async function GET() {
  const provenanceSnapshot = loadIndexerProvenanceSnapshot(launchProblems);
  return json(
    launchProblems.map((problem) => {
      const chainProvenance = provenanceSnapshot.get(problem.slug) ?? chainProvenanceForProblem(problem);
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
        donationWallet: publicDonationWallet(problem.donationWallet, chainProvenance),
        donationTarget,
        chainProvenance,
        challengeWindowHours: problem.challengeWindowHours,
        verifierVersion: problem.verifierVersion,
      };
    }),
  );
}
