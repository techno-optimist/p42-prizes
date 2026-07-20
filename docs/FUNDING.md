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
- The current signed `p42-production-launch-authorization/v1` artifact does not
  bind the exact bytes of `terms`, `privacy`, `risk`, and `eligibility`
  documents. Environment assertions cannot add that authority. Consequently,
  the funding endpoint remains fail-closed until a new authorization version
  signs those artifact references and the activation/reconciliation validators
  bind the same authorization bytes and digest.
- When a target is available, the portal displays all four links and exact
  digests. The wallet action and address-copy control remain disabled until the
  funder explicitly acknowledges those release artifacts and the target's
  authorization, activation, and checkpoint bindings.
- Phase 0 and every unavailable response retain the exact
  `p42-prizes/funding-target/v3` envelope with `target: null`. Expanded active
  targets use the distinct `p42-prizes/funding-target/v4` schema. General
  problem list/detail APIs never publish an address, wallet URI, explorer
  action, or donation target; funding instructions come only from this gated
  endpoint.

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
