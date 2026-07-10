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

Coinbase Onramp is wallet-first only. A backend-created single-use session may
send purchased ETH to an authenticated user's Base wallet. That wallet must
then separately sign `pool.fund()`, making the wallet the on-chain sponsor and
zero-credit refund owner. Coinbase must never be configured with a pool as the
session destination.

The v1 route exists only as a hard-disabled capability endpoint:

```http
POST /api/problems/{slug}/funding/coinbase-session
```

It unconditionally returns `503` and never calls Coinbase, creates a session,
or stores an intent. Any future implementation must onramp only to an
authenticated user-controlled wallet; the user must then separately sign the
pool's plain `fund()` call. Direct Coinbase-to-pool settlement remains
prohibited because Coinbase does not bind pool calldata or sponsor attribution.

Coinbase is never the verifier, resolver, or payout oracle. It is only an
onboarding rail that helps a funder move assets to the on-chain pool.
