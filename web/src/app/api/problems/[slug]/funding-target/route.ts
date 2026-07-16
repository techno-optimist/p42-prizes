import { json } from "@/lib/api";
import { publishedDonationTarget } from "@/lib/chain-provenance";
import { loadPortalReadModel } from "@/lib/indexer-read-model";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const SCHEMA = "p42-prizes/funding-target/v1";

function validIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

export async function GET(_request: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  try {
    const model = await loadPortalReadModel();
    const problem = model.problems.find((entry) => entry.slug === slug);
    const funding = problem?.funding;
    if (!problem || !funding || !validIsoTimestamp(funding.fundingDeadline)
      || !validIsoTimestamp(funding.publicationObservedAt)) {
      return json({ schema: SCHEMA, slug, fundingDeadline: null, serverObservedAt: null, target: null });
    }
    const deadlineTimestamp = Date.parse(funding.fundingDeadline);
    const effectiveTimestamp = Math.max(Date.parse(funding.publicationObservedAt), Date.now());
    const serverObservedAt = new Date(effectiveTimestamp).toISOString();
    const target = funding.canFund && effectiveTimestamp < deadlineTimestamp
      ? publishedDonationTarget(problem.donationWallet, problem.chainProvenance)
      : null;
    return json({
      schema: SCHEMA,
      slug,
      fundingDeadline: funding.fundingDeadline,
      serverObservedAt,
      target: target && {
        address: target.address,
        asset: target.asset,
        chain: target.chain,
        chainId: target.chainId,
        explorerUrl: target.explorerUrl,
        walletUri: target.walletUri,
      },
    });
  } catch {
    return json(
      { schema: SCHEMA, slug, fundingDeadline: null, serverObservedAt: null, target: null },
      { status: 503 },
    );
  }
}
