# Funding Problem Pools

General problem list/detail APIs expose only an allowlisted, non-actionable
provenance summary. They omit donation wallets, contract and registry
identifiers, deployment and event transaction hashes, destination pools,
explorer actions, and transfer URIs.

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
- No current GET or client parser can return or accept an actionable target.
  A future protocol must make acknowledgement a signed server-verified request
  before the server releases any address, wallet URI, explorer URL, or agent-
  consumable network response. Client-only acknowledgement is insufficient.
- Phase 0 and every unavailable response retain the exact
  `p42-prizes/funding-target/v3` envelope with `target: null`. Expanded active
  targets reserve the distinct `p42-prizes/funding-target/v4` schema, which
  requires `p42-production-launch-authorization/v2` and a nonzero signed legal-
  artifact-set digest. No v2 validator or acknowledgement protocol exists, so
  v4 is deliberately dormant.

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
