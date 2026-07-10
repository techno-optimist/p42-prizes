import { json } from "@/lib/api";
import {
  chainProvenanceForProblem,
  publicDonationWallet,
  publishedDonationTarget,
} from "@/lib/chain-provenance";
import { getProblemBySlug } from "@/lib/data";

export async function GET(_req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const problem = getProblemBySlug(slug);
  if (!problem) return json({ error: "Problem not found" }, { status: 404 });
  const chainProvenance = chainProvenanceForProblem(problem);
  const donationTarget = publishedDonationTarget(problem.donationWallet, chainProvenance);
  return json({
    ...problem,
    poolAddress: donationTarget?.address ?? null,
    donationWallet: publicDonationWallet(problem.donationWallet, chainProvenance),
    donationTarget,
    chainProvenance,
  });
}
