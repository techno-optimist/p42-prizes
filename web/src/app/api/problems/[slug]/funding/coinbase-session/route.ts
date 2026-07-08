import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { getProblemBySlug } from "@/lib/data";
import { assertFundingLaunchGate, assertRedirectAllowed } from "@/lib/funding-gates";
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

export async function POST(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  try {
    enforceRateLimit(req, rateLimitPolicy("coinbase_onramp", { limit: 10, windowMs: 60_000 }));
    const body = await readJson(req, onrampSchema);
    assertRedirectAllowed(body.redirect_url);
    const { slug } = await params;
    const problem = getProblemBySlug(slug);
    if (!problem) return json({ error: "Problem not found" }, { status: 404 });

    const wallet = problem.donationWallet;
    const gate = assertFundingLaunchGate(problem, req);
    const response = await fetch("https://api.developer.coinbase.com/onramp/v1/token", {
      method: "POST",
      headers: {
        authorization: `Bearer ${gate.bearerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        addresses: [{ address: wallet.address, blockchains: ["base"] }],
        assets: [wallet.asset],
        clientIp: gate.clientIp,
      }),
    });

    const payload = await response.json();
    if (!response.ok) {
      // Do not echo the upstream Coinbase error body to the client; it can leak integration
      // internals. Log server-side and return a generic failure.
      console.error("Coinbase Onramp session creation failed", { status: response.status, payload });
      return json({ error: "Coinbase Onramp session creation failed" }, { status: 502 });
    }

    return json({
      channel_id: payload.channel_id,
      token: payload.token,
      onramp_url: coinbaseOnrampUrl(payload.token, body),
      destination: wallet,
      note: "Coinbase creates a single-use funding session; on-chain settlement remains governed by the P42 pool.",
    });
  } catch (error) {
    return apiError(error);
  }
}
