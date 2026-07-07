import { ApiError } from "@/lib/api";
import type { DonationWallet, Problem } from "@/lib/types";

const EVM_ADDRESS = /^0x[a-fA-F0-9]{40}$/;

export interface FundingLaunchGate {
  bearerToken: string;
  clientIp: string;
}

function parsePoolAddress(poolAddress: string | null): { chain: string; address: string } | null {
  if (!poolAddress) return null;
  const [chain, address] = poolAddress.split(":");
  if (!chain || !address) return null;
  return { chain, address };
}

export function trustedClientIp(req: Request): string | undefined {
  const header = process.env.P42_TRUSTED_CLIENT_IP_HEADER;
  if (!header) return undefined;
  return req.headers.get(header)?.split(",")[0]?.trim() || undefined;
}

export function assertRedirectAllowed(redirectUrl: string | undefined): void {
  if (!redirectUrl) return;
  const allowed = (process.env.P42_COINBASE_ALLOWED_REDIRECT_ORIGINS ?? "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  const origin = new URL(redirectUrl).origin;
  if (!allowed.includes(origin)) {
    throw new ApiError("redirect_url origin is not allowlisted for Coinbase Onramp", 400);
  }
}

export function assertFundingLaunchGate(problem: Problem, req: Request): FundingLaunchGate {
  const wallet: DonationWallet = problem.donationWallet;
  const pool = parsePoolAddress(problem.poolAddress);
  if (
    wallet.chain !== "Base" ||
    wallet.status !== "enabled" ||
    !EVM_ADDRESS.test(wallet.address) ||
    !pool ||
    pool.chain !== "base" ||
    pool.address.toLowerCase() !== wallet.address.toLowerCase()
  ) {
    throw new ApiError("Coinbase Onramp is gated until a reviewed Base mainnet pool is configured", 409, {}, {
      donationWallet: wallet,
      required_next: "Set a real Base pool address, pass audit/legal gates, then mark the wallet enabled.",
    });
  }

  if (process.env.P42_REAL_ETH_GATE_APPROVED !== "1") {
    throw new ApiError(
      "Coinbase Onramp is gated until audit, legal, and mainnet pool evidence is approved",
      503,
      {},
      { required_env: ["P42_REAL_ETH_GATE_APPROVED=1"] },
    );
  }

  const bearerToken = process.env.COINBASE_ONRAMP_BEARER_TOKEN;
  if (process.env.P42_ENABLE_COINBASE_ONRAMP !== "1" || !bearerToken) {
    throw new ApiError("Coinbase Onramp server credentials are not configured", 503, {}, {
      required_env: ["P42_ENABLE_COINBASE_ONRAMP=1", "COINBASE_ONRAMP_BEARER_TOKEN"],
    });
  }

  const clientIp = trustedClientIp(req);
  if (!clientIp) {
    throw new ApiError("Coinbase Onramp requires a trusted deployment client IP header", 503, {}, {
      required_env: ["P42_TRUSTED_CLIENT_IP_HEADER=<platform-controlled-header>"],
    });
  }

  return { bearerToken, clientIp };
}
