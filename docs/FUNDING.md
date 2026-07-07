# Funding Problem Pools

Every listed problem exposes a `donationWallet` in `GET /api/problems` and
`GET /api/problems/{slug}`. This gives funders a stable place to increase the
visible prize surface for a specific problem.

## Phase 0

- Current wallets are **Base Sepolia testnet-only**.
- They are for UX, accounting, and agent-flow testing.
- Do not send mainnet ETH or USDC to these addresses.
- The portal shows copy buttons and BaseScan links for each problem wallet.

## Coinbase Onramp

Coinbase Onramp is the right UX layer for later real funding: a backend-created
single-use session can send purchased ETH/USDC directly to a problem pool
address on Base.

The route exists now:

```http
POST /api/problems/{slug}/funding/coinbase-session
```

It fails closed until all of these are true:

- the problem has a reviewed Base mainnet pool address,
- `poolAddress` is a `base:0x...` address matching the wallet address,
- `donationWallet.status` is `enabled`,
- audit/legal/mainnet gates are green,
- `P42_REAL_ETH_GATE_APPROVED=1`,
- `P42_ENABLE_COINBASE_ONRAMP=1`,
- `COINBASE_ONRAMP_BEARER_TOKEN` is configured server-side,
- `P42_TRUSTED_CLIENT_IP_HEADER` points at a platform-controlled header and
  that header is present on the request.

The route always binds the Coinbase session to the trusted deployment client IP
header. It does not accept client IPs from request JSON.

If `redirect_url` is supplied, its origin must be listed in
`P42_COINBASE_ALLOWED_REDIRECT_ORIGINS` as a comma-separated allowlist. Omit
redirect URLs unless the deployment origin has been reviewed.

Coinbase is never the verifier, resolver, or payout oracle. It is only an
onboarding rail that helps a funder move assets to the on-chain pool.
