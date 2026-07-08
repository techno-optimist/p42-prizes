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
- When `P42_REQUIRE_MUTATION_API_KEY=1`, every mutable route requires a P42
  mutation API key supplied as `X-P42-API-Key` or `Authorization: Bearer ...`.
  Server configuration stores only hashes in `P42_MUTATION_API_KEY_SHA256S`
  as comma-separated `sha256:<hex>` values.

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
- retention policy linked to DA/Arweave evidence,
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
- Production deploy sets `P42_REQUIRE_MUTATION_API_KEY=1` with hashed keys.
- Distributed rate limits, API audit logs, and payload quarantine are live.
- Session-key behavior is tested against the deployed Base contracts.
