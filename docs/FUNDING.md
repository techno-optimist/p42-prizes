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
- An otherwise valid target remains fully suppressed unless
  `P42_FUNDING_RELEASE_ARTIFACTS` is an exact JSON bundle containing release-
  bound `terms`, `privacy`, `risk`, and `eligibility` HTTPS artifact URIs and
  nonzero `sha256:<64 lowercase hex>` digests. Missing, extra, or malformed
  artifact data fails closed.
- When a target is available, the portal displays all four links and exact
  digests. The wallet action and address-copy control remain disabled until the
  funder explicitly acknowledges those release artifacts and the target's
  authorization, activation, and checkpoint bindings.

## Coinbase Onramp

Coinbase Onramp is not available in this release. No reviewed session flow or
funding destination is configured, and the portal must not present an Onramp
control as actionable.

The v1 route exists only as a hard-disabled capability endpoint:

```http
POST /api/problems/{slug}/funding/coinbase-session
```

It unconditionally returns `503` and never calls Coinbase, creates a session,
or stores an intent. Any future flow requires a new reviewed design and must be
bound to the same release artifacts before it can become actionable. No future
architecture or approval should be inferred from this disabled endpoint.

Coinbase is not a verifier, resolver, payout oracle, or enabled funding rail in
the current release.
