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
- `donationWallet.status` is `enabled`,
- audit/legal/mainnet gates are green,
- `P42_ENABLE_COINBASE_ONRAMP=1`,
- `COINBASE_ONRAMP_BEARER_TOKEN` is configured server-side.

If the deployment wants Coinbase's optional `clientIp` session binding, set
`P42_TRUSTED_CLIENT_IP_HEADER` to a platform-controlled header. The route does
not accept client IPs from request JSON.

Coinbase is never the verifier, resolver, or payout oracle. It is only an
onboarding rail that helps a funder move assets to the on-chain pool.
