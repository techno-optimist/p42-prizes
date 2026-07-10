# Funding Problem Pools

Every listed problem exposes a `donationWallet` state in `GET /api/problems`
and `GET /api/problems/{slug}`. A transferable target is published only after
the problem has a reconciled, bytecode-backed pool on the declared chain.

## Phase 0

- All current wallets are **`not-deployed`**: no address, copy control,
  wallet URI, or BaseScan link is published for any board.
- Do not send testnet or mainnet ETH or USDC for a P42 Prize today. There is
  no deployed pool to receive it.
- A future Base Sepolia or Base target must pass the portal's chain,
  reconciliation, runtime-bytecode, registry, and deployment-commit checks
  before a donation action is exposed.

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
