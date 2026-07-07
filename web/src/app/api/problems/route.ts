import { json } from "@/lib/api";
import { problems } from "@/lib/data";

export async function GET() {
  return json(
    problems.map((problem) => ({
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
      donationWallet: problem.donationWallet,
      baselineAgent: problem.baselineAgent,
      baselineSource: problem.baselineSource,
      baselineArtifact: problem.baselineArtifact,
      challengeWindowHours: problem.challengeWindowHours,
      verifierVersion: problem.verifierVersion,
    })),
  );
}
