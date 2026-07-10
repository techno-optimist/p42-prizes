import { randomUUID } from "node:crypto";
import { verifyMessage } from "ethers";
import { z } from "zod";
import { apiError, json, readJson } from "@/lib/api";
import { enforceMutationApiKey } from "@/lib/api-auth";
import { chainProvenanceForProblem, publishedDonationTarget } from "@/lib/chain-provenance";
import { getProblemBySlug } from "@/lib/data";
import { enforceRateLimit, rateLimitPolicy } from "@/lib/rate-limit";

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const INTENT_TTL_MS = 5 * 60_000;

const intentSchema = z.object({
  phase: z.literal("intent"),
  wallet_address: z.string().regex(ADDRESS),
  redirect_url: z.string().url().optional(),
});
const sessionSchema = z.object({
  phase: z.literal("session"),
  intent_id: z.string().uuid(),
  wallet_signature: z.string().trim().min(1).max(256),
  preset_fiat_amount: z.string().regex(/^\d+(\.\d{1,2})?$/).optional(),
});
const onrampSchema = z.discriminatedUnion("phase", [intentSchema, sessionSchema]);

interface FundingIntent {
  wallet: string;
  pool: string;
  slug: string;
  chainId: number;
  clientIp: string;
  principal: string;
  redirectUrl?: string;
  expiresAt: number;
  used: boolean;
}

const intents = new Map<string, FundingIntent>();

function intentMessage(id: string, intent: FundingIntent) {
  return [
    "P42 Coinbase wallet-first funding intent",
    `intentId: ${id}`,
    `wallet: ${intent.wallet}`,
    `pool: ${intent.pool}`,
    `problem: ${intent.slug}`,
    `chainId: ${intent.chainId}`,
    `expiresAt: ${intent.expiresAt}`,
  ].join("\n");
}

function allowedRedirect(value?: string) {
  if (!value) return undefined;
  const allowed = (process.env.P42_ONRAMP_REDIRECT_ALLOWLIST ?? "")
    .split(",").map((entry) => entry.trim()).filter(Boolean);
  if (!allowed.includes(value)) throw new Error("redirect_url is not on the fixed Onramp allowlist");
  return value;
}

export function assertWalletFirstDestination(wallet: string, pool: string) {
  if (wallet.toLowerCase() === pool.toLowerCase()) {
    throw new Error("Coinbase Onramp destination must be a user wallet, never a P42 pool");
  }
}

function trustedClientIp(req: Request): string {
  const header = process.env.P42_TRUSTED_CLIENT_IP_HEADER;
  if (!header) throw new Error("trusted client IP forwarding is not configured");
  const value = req.headers.get(header)?.trim();
  if (!value) throw new Error("trusted client IP is unavailable");
  return value;
}

function coinbaseOnrampUrl(token: string, amount?: string, redirectUrl?: string) {
  const url = new URL(process.env.COINBASE_ONRAMP_URL ?? "https://pay.coinbase.com/buy/select-asset");
  url.searchParams.set("sessionToken", token);
  url.searchParams.set("defaultNetwork", "base");
  url.searchParams.set("defaultAsset", "ETH");
  url.searchParams.set("defaultExperience", "buy");
  if (amount) url.searchParams.set("presetFiatAmount", amount);
  if (redirectUrl) url.searchParams.set("redirectUrl", redirectUrl);
  return url.toString();
}

export async function POST(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  try {
    const principal = enforceMutationApiKey(req, "funding.coinbase_session");
    if (!principal.authenticated || !principal.rateLimitSubject) {
      return json({ error: "Coinbase Onramp requires authenticated funding access" }, { status: 401 });
    }
    enforceRateLimit(req, rateLimitPolicy("coinbase_onramp", { limit: 10, windowMs: 60_000 }), principal.rateLimitSubject);
    const body = await readJson(req, onrampSchema);
    const { slug } = await params;
    const problem = getProblemBySlug(slug);
    if (!problem) return json({ error: "Problem not found" }, { status: 404 });
    const target = publishedDonationTarget(problem.donationWallet, chainProvenanceForProblem(problem));
    if (!target || target.chain !== "Base" || target.chainId !== 8453) {
      return json({ error: "Coinbase Onramp is gated until a freshly reconciled Base mainnet pool is configured" }, { status: 409 });
    }
    const clientIp = trustedClientIp(req);

    if (body.phase === "intent") {
      assertWalletFirstDestination(body.wallet_address, target.address);
      const id = randomUUID();
      const intent: FundingIntent = {
        wallet: body.wallet_address.toLowerCase(), pool: target.address.toLowerCase(), slug,
        chainId: target.chainId, clientIp, principal: principal.rateLimitSubject,
        redirectUrl: allowedRedirect(body.redirect_url), expiresAt: Date.now() + INTENT_TTL_MS, used: false,
      };
      intents.set(id, intent);
      return json({ intent_id: id, expires_at: new Date(intent.expiresAt).toISOString(), message: intentMessage(id, intent), state: "wallet-signature-required" });
    }

    const intent = intents.get(body.intent_id);
    if (!intent || intent.used || intent.expiresAt < Date.now()) return json({ error: "Funding intent is missing, used, or expired" }, { status: 409 });
    if (intent.slug !== slug || intent.pool !== target.address.toLowerCase() || intent.chainId !== target.chainId
      || intent.clientIp !== clientIp || intent.principal !== principal.rateLimitSubject) {
      return json({ error: "Funding intent binding no longer matches" }, { status: 409 });
    }
    if (verifyMessage(intentMessage(body.intent_id, intent), body.wallet_signature).toLowerCase() !== intent.wallet) {
      return json({ error: "wallet_signature does not authorize this funding intent" }, { status: 403 });
    }
    const bearer = process.env.COINBASE_ONRAMP_BEARER_TOKEN;
    if (process.env.P42_ENABLE_COINBASE_ONRAMP !== "1" || !bearer) {
      return json({ error: "Coinbase Onramp server credentials are not configured" }, { status: 503 });
    }
    intent.used = true;
    const response = await fetch("https://api.developer.coinbase.com/onramp/v1/token", {
      method: "POST",
      headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json" },
      body: JSON.stringify({ addresses: [{ address: intent.wallet, blockchains: ["base"] }], assets: ["ETH"], clientIp }),
    });
    const payload = await response.json();
    if (!response.ok || typeof payload.token !== "string") {
      intent.used = false;
      return json({ error: "Coinbase Onramp session creation failed" }, { status: 502 });
    }
    return json({
      channel_id: payload.channel_id,
      onramp_url: coinbaseOnrampUrl(payload.token, body.preset_fiat_amount, intent.redirectUrl),
      destination: { address: intent.wallet, chain: "Base", chainId: 8453, asset: "ETH" },
      pool: intent.pool,
      state: "wallet-first-onramp; wallet must separately sign pool.fund()",
    });
  } catch (error) {
    return apiError(error);
  }
}
