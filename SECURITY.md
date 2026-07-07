# Security Policy

P42 Prizes is pre-mainnet software. Do not send real funds to any address shown
by this repository or portal unless a later release explicitly marks that pool
as audited and mainnet-enabled.

## Reporting a Vulnerability

For now, report vulnerabilities privately to the repository owner or Project
Forty Two operator before public disclosure. Include:

- affected commit, route, contract, verifier, or problem slug,
- reproduction steps and expected impact,
- whether the issue can move funds, corrupt verifier output, bypass
  commit-reveal binding, or tamper with event history,
- any proof-of-concept artifact needed to reproduce the issue.

Please do not submit exploit transactions against live or third-party wallets.
Phase 0 wallets are Base Sepolia testnet-only and exist for integration testing.

## Scope

In scope:

- verifier report binding and deterministic runner behavior,
- commit/reveal and raw-byte content binding,
- funding/session gates,
- event-ledger integrity claims,
- API routes under `web/src/app/api`,
- problem manifests, schemas, and verifier fixtures.

Out of scope:

- issues requiring social engineering,
- denial-of-service against local development machines,
- reports against unaffiliated third-party services unless they directly affect
  P42 Prizes' configured integration.

## Current Mainnet Status

No real-ETH bounty is enabled. The required gates remain:

- external smart-contract audit,
- written legal review,
- reviewed Base mainnet pool addresses,
- canonical sandbox runner and N-host determinism evidence,
- bonded resolver / transcript path,
- production database, distributed idempotency, and monitoring.
