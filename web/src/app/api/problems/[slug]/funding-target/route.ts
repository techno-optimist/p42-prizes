import { json } from "@/lib/api";
import { publishedDonationTarget } from "@/lib/chain-provenance";
import { loadPortalReadModel } from "@/lib/indexer-read-model";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const SCHEMA = "p42-prizes/funding-target/v2";

function validIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function validUint(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}

function unavailable(slug: string) {
  return {
    schema: SCHEMA,
    slug,
    authorizationExpiresAt: null,
    finalizedObservedAt: null,
    fundingDeadline: null,
    remainingCapWei: null,
    serverObservedAt: null,
    target: null,
  };
}

export async function GET(_request: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  try {
    const model = await loadPortalReadModel();
    const problem = model.problems.find((entry) => entry.slug === slug);
    const funding = problem?.funding;
    const pool = problem?.pool;
    if (!problem || !funding || !pool || !validIsoTimestamp(funding.authorizationExpiresAt)
      || !validIsoTimestamp(funding.finalizedObservedAt) || !validIsoTimestamp(funding.fundingDeadline)
      || !validIsoTimestamp(funding.publicationObservedAt) || !validUint(funding.fundingCapWei)
      || !validUint(funding.remainingFundingCapWei) || !validUint(pool.accountedBalanceWei)
      || funding.finalizedObservedAt !== model.provenance.checkpointTimestamp) {
      return json(unavailable(slug));
    }
    const cap = BigInt(funding.fundingCapWei);
    const accountedBalance = BigInt(pool.accountedBalanceWei);
    if (accountedBalance > cap || funding.remainingFundingCapWei !== (cap - accountedBalance).toString()) {
      return json(unavailable(slug));
    }
    const authorizationTimestamp = Date.parse(funding.authorizationExpiresAt);
    const deadlineTimestamp = Date.parse(funding.fundingDeadline);
    const effectiveTimestamp = Math.max(Date.parse(funding.publicationObservedAt), Date.now());
    const serverObservedAt = new Date(effectiveTimestamp).toISOString();
    const authorizationExpired = Math.floor(effectiveTimestamp / 1000) > Math.floor(authorizationTimestamp / 1000);
    const target = funding.canFund && !authorizationExpired && effectiveTimestamp < deadlineTimestamp
      && funding.remainingFundingCapWei !== "0"
      ? publishedDonationTarget(problem.donationWallet, problem.chainProvenance)
      : null;
    return json({
      schema: SCHEMA,
      slug,
      authorizationExpiresAt: funding.authorizationExpiresAt,
      finalizedObservedAt: funding.finalizedObservedAt,
      fundingDeadline: funding.fundingDeadline,
      remainingCapWei: funding.remainingFundingCapWei,
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
      unavailable(slug),
      { status: 503 },
    );
  }
}
