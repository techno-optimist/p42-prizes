# Wallet And Session Policy

Status: draft security policy for Gate 2 review. This is not legal approval,
not a KYC policy, and not permission to enable real ETH.

## Current Phase 0 Rules

- Solver ownership is proven by EIP-191 signatures over the P42 commit
  authorization message for non-local commits.
- The portal never asks for, stores, or derives a solver private key.
- `dev_salt` is a local simulation shortcut only and is disabled in production
  unless `P42_ALLOW_DEV_SALT=1` is deliberately set.
- Mutable portal routes are schema-validated, bounded by request size, locally
  rate-limited, and idempotency-key aware where retries can mutate state.
- Production fails closed unless `P42_MUTATION_API_CREDENTIALS_JSON` contains a
  strict compact JSON array of credential records. Non-canonical whitespace or
  duplicate JSON keys are rejected. Each record has exactly
  `hash` (`sha256:<64 lowercase hex>`), a nonempty unique `scopes` array, and an
  optional canonical UTC `expiresAt`. Plaintext keys are supplied as
  `X-P42-API-Key` or `Authorization: Bearer ...` and are never stored.
- Accepted route scopes are `submissions.commit`, `submissions.reveal`,
  `solutions.verify`, and `challenges.open`. Unknown, empty, duplicate,
  malformed, or expired policy records fail closed. Duplicate hashes are
  forbidden, so rotation uses distinct overlapping old/new records without
  merging authority. The legacy flat `P42_MUTATION_API_KEY_SHA256S` variable is
  intentionally rejected rather than treated as wildcard access.

Mutable routes covered by the API-key gate:

- `POST /api/submissions/commit`
- `POST /api/submissions/reveal`
- `POST /api/solutions`
- `POST /api/challenges`
- `POST /api/problems/{slug}/funding/coinbase-session`

## Production Session-Key Target

Before Gate 2, solver agents should use scoped session keys rather than broad
wallet authority. The intended account-abstraction policy is:

| Scope | Allowed actions | Explicitly not allowed |
| --- | --- | --- |
| `submit` | commit, reveal, verifier shortcut during testnet | claim funds, alter payout address, create onramp sessions |
| `challenge` | open bonded challenges, upload transcript evidence | resolve own challenge, change resolver roster |
| `claim` | claim finalized entitlement to the solver wallet | transfer arbitrary assets, change pool rules |
| `fund` | create reviewed funding/onramp sessions for a specific pool | fund unreviewed wallets, enable mainnet destinations |

Session keys must expire, be revocable, and bind to chain id, contract address,
problem id, and action scope. A leaked solver session key must not be able to
drain the wallet or redirect a pool.

## API Keys

Production API keys are an abuse-control layer, not wallet authority and not
settlement truth.

- Store only SHA-256 key hashes in server environment.
- Rotate keys by adding the new hash, confirming clients have switched, then
  removing the old hash.
- Pair API keys with distributed rate limits and audit logs before real ETH.
- Never use API keys as resolver, verifier, or payout authorization.

## Payload Quarantine

Raw submissions are adversarial inputs. Before Gate 2, production payload
handling needs:

- immutable content hash at commit/reveal,
- bounded request and file sizes,
- quarantine storage outside the application working tree,
- malware/archive-bomb checks before verifier execution,
- verifier execution in a pinned sandbox image,
- retention policy linked to DA evidence (the reveal-calldata archive and any
  optional Arweave mirror),
- deletion or access controls for rejected non-public payloads.

The Phase 0 portal hashes raw solution bytes, caps JSON body size, and avoids
persisting raw solutions as settlement truth. It is not a production quarantine
system.

## KYC, Sanctions, And Withdrawals

No KYC/sanctions threshold is approved yet. Counsel must review:

- whether bounty payouts require identity checks by size, jurisdiction, or risk,
- whether Coinbase Onramp changes the compliance posture,
- tax reporting obligations for winners and funders,
- Terms of Service language for solver agents and affiliated P42 agents.

Until that review is complete, mainnet Coinbase Onramp and real-ETH pools stay
disabled.

## Gate 2 Evidence Required

- Security owner approves this policy against the implemented portal, contracts,
  and solver-agent SDK.
- Counsel approves KYC/sanctions, tax, Terms, and onramp posture.
- Production deploy provisions reviewed, scoped, expiring hashes in
  `P42_MUTATION_API_CREDENTIALS_JSON`; no wildcard credential exists.
- Distributed rate limits, API audit logs, and payload quarantine are live.
- Session-key behavior is tested against the deployed Base contracts.

### Operational-control evidence packet

Gate 2 operational readiness is established only by a successfully normalized
`p42-operational-controls/v3` packet conforming to
`schemas/operational-controls.schema.json`. Source, policy, mock, or fixture
claims are not operational evidence and must not be described as a gate pass.
The historical `v1` and single-board `v2` formats remain parseable for audit
history but cannot satisfy production launch authorization.

The packet must contain exactly these independently evidenced controls:

- `mutation_api_auth`
- `distributed_rate_limit`
- `distributed_idempotency`
- `abuse_alerting`
- `payload_size_limit`
- `payload_quarantine`
- `malware_archive_bomb_rejection`
- `session_expiry`
- `session_revocation`
- `chain_contract_problem_scope_binding`
- `spend_cap_and_forbidden_actions`

Every control needs its own resolved, hash-bound test artifact and output
artifact; artifacts or hashes cannot be reused between controls. The record
also includes the exact command, passed status, UTC execution time inside the
packet evidence window, and a production-equivalent environment binding to the
same Git commit, chain, deployment manifest, configuration, and canonical
release hash. Each session control carries the same ordered ten
`session_domains`, derived from `protocol/production-board-set-v1.json` and the
exact deployment manifest. Every domain binds board number and slug, chain,
that board's submission manager, concrete target/selector/calldata permissions,
future expiry, successful revocation, and canonical per-call and cumulative
spend caps. Missing, duplicated, reordered, substituted, or cross-board domains
fail closed.

Each production domain carries a fresh snapshot at an independently agreed
finalized block no more than one hour before report completion. Two pinned RPC
providers with distinct certified ownership groups must agree on the current
block hash and timestamp, every wallet getter, every allowlist and call-policy
entry, the complete runtime bytecode, `owner()`, and the historical creation
transaction and receipt. The creation block/hash must itself be canonical and
finalized. The transaction must create the claimed wallet from the observed
owner with the exact capsule-derived creation input, and its ordered
`SessionKeySet`, `SessionPolicySet`, and `CapsSet` logs must match. Block-global
`logIndex` values are deliberately excluded from authority.

`P42AgentWallet.allowlistedPolicyCount()` closes the mapping-enumeration gap.
Every false-to-true and true-to-false transition changes the count exactly
once; replacements do not double count, and deletion clears the stored call
policy. Current-state and authorization readers require the count to equal
exactly five while separately reading and validating all five canonical
permissions. An extra sixth policy, or a missing canonical policy replaced by
an unobserved extra policy, therefore fails closed.

`P42AgentWallet.policyMutationEpoch()` closes the insert-use-delete history
gap. The capsule baseline is independently read at deployment and must be zero;
the current finalized value must be exactly five, one transition for each
canonical permission. Both values are bound through the operational packet and
authorization recheck, so returning to the expected final count and entries
cannot erase a transient policy mutation.

Wallet provenance is derived, not asserted. The validator resolves the release
capsule, finds the single committed `P42AgentWallet` compiler output, verifies
that its only immutable reference is the `owner` address, patches that owner
into the runtime template, and compares the full live bytecode and keccak hash.
The owner-policy hash is recomputed from canonical release-capsule, chain,
wallet, owner, session, expiry, cap, and exact permission bytes.

Control execution is separate from that active production snapshot. Every
board/control receipt embeds a dedicated historical test wallet at its own
canonical finalized block. Expiry is tested only after that test session's
expiry; revocation uses an active revoked test session; scope and spend use
active unrevoked test sessions with exact policies. The scope test performs two
actual violations: current-board calldata against another board's challenge
manager (`CallNotAllowed`), then other-board calldata against the current
allowed manager (`CalldataHashMismatch`). The validator independently replays
every exact `from`/`to`/value/calldata request and compares canonical raw revert
bytes and decoded selector/arguments. Static observations, fabricated JSONL,
missing board results, or an exact allowed scope call cannot pass.

The seven service controls use a separate canonical machine-receipt boundary;
runner prose, generic observations, repository harness output, and chain RPCs
have no service authority. Report receipts bind the exact abstract request
sequence and release/build/deployment identity, but cannot select or rename a
live endpoint. At authorization, a root-owned immutable registry supplies each
exact HTTPS URL, instance, ownership group, release/build digest, Ed25519 key,
control set, and freshness/size bound. The issuance packet archives one
issuance-bound probe snapshot, but it is not freshness authority. On every
validation the validator uses its actual clock and a validation-time CSPRNG to
generate a new 256-bit challenge, then directly POSTs canonical JSON with
redirects forbidden and bounded responses. Every endpoint signs the challenge and request digests,
control, release/build, protected identity, response time, raw outcomes, and
derived invariant; the validator reconstructs semantics and exact-compares a
fresh replay. Rate-limit and idempotency controls must cross at least two
distinct service instances, HTTPS endpoints, and ownership groups while using
distinct Ed25519 keys for distinct ownership groups. The closed sequences also prove
unauthorized and authorized mutation, alert emission and deduplication, payload
limit and limit-plus-one behavior, quarantine without execution through
release, and malware/archive-bomb rejection under declared resource bounds.
Missing probes, fabricated or relabelled receipts, same-instance simulations,
redirects, stale/cached responses, bad signatures, or any probe drift fail
closed. The challenge, registry digest, exact requests, and signed responses are
part of the launch authorization digest. Fresh validation responses must match
the archived stable semantics, and authorization lifetime is capped at five
minutes; supplied, cached, archived, backdated, or reused challenge material
cannot establish currentness.

Production launch authorization does not treat a recently completed packet as
proof that wallet state remained unchanged. The packet must have completed no
more than 15 minutes before authorization issuance, and the authorizer must
independently re-query all ten wallets at one canonical finalized block no more
than five minutes old through two RPC operators with distinct ownership. The
recheck compares runtime bytecode and hash, owner, session key and expiry,
revocation, value and cumulative caps, spent value, allowlisted count, mutation
epoch, and every installed policy against the packet. Its block/hash/timestamp, exact wallet results, and RPC
quorum are normalized into the signed authorization digest. A post-report
revocation, session rotation, policy/cap mutation, call-count drift, stale
block, or same-operator quorum therefore invalidates authorization.

The responsible operational-control owner is a real evidenced identity. That
owner signs each canonical control hash with Ed25519 after all evidence was
created and before packet completion. The key, identity, role, attestation
class, and validity window must already exist in the out-of-band trust
registry. The built-in production registry intentionally trusts nobody, so a
fresh checkout cannot claim Gate 2 passed. Test registries and generated test
artifacts exercise rejection behavior only; they are never launch evidence.
