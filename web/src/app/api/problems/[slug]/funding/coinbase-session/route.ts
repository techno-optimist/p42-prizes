import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { enforceMutationApiKey } from "@/lib/api-auth";
import { chainProvenanceForProblem, validatedDonationTarget } from "@/lib/chain-provenance";
import { getProblemBySlug } from "@/lib/data";
import { enforceRateLimit, rateLimitPolicy } from "@/lib/rate-limit";

const onrampSchema = z.object({
  preset_fiat_amount: z.string().regex(/^\d+(\.\d{1,2})?$/).optional(),
  partner_user_ref: z.string().trim().min(1).max(50).optional(),
  redirect_url: z.string().url().optional(),
});

function coinbaseOnrampUrl(token: string, input: z.infer<typeof onrampSchema>) {
  const url = new URL(process.env.COINBASE_ONRAMP_URL ?? "https://pay.coinbase.com/buy/select-asset");
  url.searchParams.set("sessionToken", token);
  url.searchParams.set("defaultNetwork", "base");
  url.searchParams.set("defaultAsset", "ETH");
  url.searchParams.set("defaultExperience", "buy");
  if (input.preset_fiat_amount) url.searchParams.set("presetFiatAmount", input.preset_fiat_amount);
  if (input.partner_user_ref) url.searchParams.set("partnerUserRef", input.partner_user_ref);
  if (input.redirect_url) url.searchParams.set("redirectUrl", input.redirect_url);
  return url.toString();
}

function trustedClientIp(req: Request): string | undefined {
  const header = process.env.P42_TRUSTED_CLIENT_IP_HEADER;
  if (!header) return undefined;
  return req.headers.get(header) ?? undefined;
}

export async function POST(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  try {
    const principal = enforceMutationApiKey(req, "funding.coinbase_session");
    enforceRateLimit(
      req,
      rateLimitPolicy("coinbase_onramp", { limit: 10, windowMs: 60_000 }),
      principal.rateLimitSubject,
    );
    const body = await readJson(req, onrampSchema);
    const { slug } = await params;
    const problem = getProblemBySlug(slug);
    if (!problem) return json({ error: "Problem not found" }, { status: 404 });

    const wallet = problem.donationWallet;
    const donationTarget = validatedDonationTarget(chainProvenanceForProblem(problem));
    if (!donationTarget || donationTarget.chain !== "Base" || wallet.status !== "enabled") {
      return json(
        {
          error: "Coinbase Onramp is gated until a reviewed Base mainnet pool is configured",
          donationWallet: wallet,
          required_next: "Set a real Base pool address, pass audit/legal gates, then mark the wallet enabled.",
        },
        { status: 409 },
      );
    }

    const bearer = process.env.COINBASE_ONRAMP_BEARER_TOKEN;
    if (process.env.P42_ENABLE_COINBASE_ONRAMP !== "1" || !bearer) {
      return json(
        {
          error: "Coinbase Onramp server credentials are not configured",
          required_env: ["P42_ENABLE_COINBASE_ONRAMP=1", "COINBASE_ONRAMP_BEARER_TOKEN"],
        },
        { status: 503 },
      );
    }

    const clientIp = trustedClientIp(req);
    const response = await fetch("https://api.developer.coinbase.com/onramp/v1/token", {
      method: "POST",
      headers: {
        authorization: `Bearer ${bearer}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        addresses: [{ address: donationTarget.address, blockchains: ["base"] }],
        assets: [donationTarget.asset],
        ...(clientIp ? { clientIp } : {}),
      }),
    });

    const payload = await response.json();
    if (!response.ok) {
      return json({ error: "Coinbase Onramp session creation failed", details: payload }, { status: 502 });
    }

    return json({
      channel_id: payload.channel_id,
      token: payload.token,
      onramp_url: coinbaseOnrampUrl(payload.token, body),
      destination: donationTarget,
      note: "Coinbase creates a single-use funding session; on-chain settlement remains governed by the P42 pool.",
    });
  } catch (error) {
    return apiError(error);
  }
}
