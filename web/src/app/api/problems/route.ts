import { json } from "@/lib/api";
import {
  chainProvenanceForProblem,
  publicDonationWallet,
  publishedDonationTarget,
} from "@/lib/chain-provenance";
import { problems } from "@/lib/data";

export async function GET() {
  return json(
    problems.map((problem) => {
      const chainProvenance = chainProvenanceForProblem(problem);
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
