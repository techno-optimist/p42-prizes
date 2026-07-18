# Bounded dual-RPC chain monitor

`p42-chain-monitor` is a read-only, fail-closed comparison of two independently
reconstructed views of the current v2 deployment. It is monitoring evidence,
not portal, checkpoint, launch, settlement, or governance authority. Every
report says this explicitly with `nonAuthoritative: true` and schema
`p42-prizes/dual-rpc-chain-monitor/v1`.

The production API and CLI accept only a strict-file-read production v2
manifest. The production API accepts a manifest path, never a parsed manifest
or caller-asserted digest. It computes SHA-256 over the exact accepted file
bytes internally. A green
report binds `chainId`, that exact manifest byte digest,
`deploymentCommit`, `deploymentConfigHash`, `releaseBindingDigest`, and the full
prepared manifest binding shared by both reconstructions. Missing or malformed
identity data is a configuration refusal, never an identity-light green report.

Production exposes no provider-validation, binding-preparation, reconstruction,
or digest injection hook. Unit adapters exist only behind exports prefixed
`testOnly`. Their reports use schema
`p42-prizes/dual-rpc-chain-monitor-test/v1`, set `testOnly: true` and
`productionPass: false`, expose `testPassed` instead of a true `ok`, and cannot
be presented as a production PASS. The CLI calls only the production API.

## Trust and reconstruction boundary

The command accepts the deployment manifest plus two exact profiles selected
from the existing protected RPC operator registry. The registry path, trusted
root, exact byte digest, operator IDs, canonical HTTPS origins, and profile
digests are checked before either provider is constructed. Operators and hosts
must both be distinct. No credential belongs in the manifest, registry, report,
or command history; provider authentication must be supplied by the operator's
protected endpoint configuration.

Production validation runs exactly once with the two selected provider objects;
there is no environment-derived or implicit fallback provider. Its manifest
binding is passed unchanged into both independent reconstruction lanes.
The CLI constructs both providers through the monitor's capability-binding
wrapper. A module-private capability binds each object to its exact authority
profile, endpoint origin, role, and construction pair. Unbound objects, swapped
roles, and objects mixed across otherwise identical wrapper invocations are
rejected before their first chain read.

The monitor does not consume a portal projection or a previously published
checkpoint as authority. For each RPC it independently invokes the exported
indexer primitives for runtime identity, complete log scanning, replay,
historical storage reads, runtime configuration checks, and reconciliation from
the manifest start block. The portal-shaped fields used in comparison are
freshly derived from that replay by the existing checkpoint builder.

## Bounded anchor selection

Both providers are queried for `finalized` and current head. Each finalized-tag
result must equal a second read at its exact numeric height in number, timestamp,
and hash. Their finalized and head-number differences must be within
`--max-finalized-lag-blocks` (default
`2`, maximum `128`). The lower finalized height is selected. A provider above
that height must prove each `parentHash` link, one block at a time and within the
same bound, down to the common hash. Both common observations must have the same
safe-integer timestamp and hash. After reconstruction, the complete tag binding
and ancestry proof is repeated against both providers' then-current finalized
heads. A lag, missing/invalid anchor, broken ancestry, disagreement, or changed
anchor field fails the report.

## Compared data

The report canonical-compares logs and historical storage snapshots first,
then these replay-derived domains for every board:

- frontier;
- submission lifecycle and challenges;
- submission, challenge, and resolver bonds;
- funding authorization, pool accounting, ledger close, and rollover state;
- solver credits;
- payouts.

Each solver payout row includes `finalEntitlementGrossWei`, `claimedGrossWei`,
`claimableGrossWei`, `claimFeeWei`, `claimableNetWei`, `claimDeadline`, and the
boolean `claimDeadlinePassed`. Claimable fields are zero after a nonzero passed
deadline. All report integer quantities use canonical decimal strings.

The monitor requires the exact ordered manifest board IDs and board count. The
aggregate reconstruction and every board reconstruction must be `ok`, complete,
carry a nonempty check list whose every check passed, and carry a manifest
binding canonically equal to the single prepared binding. It also requires each
board's event evidence, on-chain snapshot, lifecycle/challenge maps, all bond
maps, funding and accounting objects, credit maps, and payout/deadline inputs.
There are no zero defaults for required fields, including per-solver credit and
claim-map entries. A field omitted by one provider or by both providers fails as
storage/reconstruction evidence instead of comparing two shared omissions.

Funding, accounting, rollover, credit, and payout projections enumerate their
required integer leaves explicitly. Every such leaf must be a canonical
nonnegative decimal string; numbers, booleans, nulls, undefined values, signed
values, leading-zero strings, and nonnumeric strings are rejected rather than
coerced or hidden by generic tree comparison.

A zero claim deadline means claims are unavailable, not unbounded. For a closed
ledger, positive total credit requires a nonzero deadline. Entitlement is the
exact floor-proportional result, which may legitimately be zero even for a
positive-credit solver; such a row must remain unclaimed and unclaimable. A
zero-credit close permits only zero entitlements and claimables. `consumeClaim` is treated
as all-or-nothing, so claimed gross is either zero or the full entitlement.
Claim fees use integer floor rounding and production `feeBps` is capped at 250.

Solver rows use unique canonical lowercase EVM addresses. Their address set
must exactly equal the key sets of both `creditAtomsOf` and `claimedWeiOf`.
Duplicate rows, noncanonical aliases, and equal-value claimant omission or
substitution fail before credit or claim totals are considered.

Runtime code/ABI, log/decode/scan, storage/reconciliation, lag, anchor, and reorg
divergence fail closed. Canonical domain mismatches are named in `divergences`.
Failed reports omit `comparedDomains` so a partial view cannot be mistaken for a
usable state snapshot.

Transport and RPC-read failures use the separate `transport` divergence class,
including failures during the final finalized-tag/ancestry reread. They are not
reported as storage mismatches or reorg evidence.

## CLI

```bash
p42-chain-monitor \
  --manifest /protected/current-deployment.json \
  --rpc-operator-registry /protected/rpc-operators.json \
  --rpc-registry-digest sha256:... \
  --rpc-registry-trusted-root /protected \
  --primary-rpc https://primary.example \
  --secondary-rpc https://secondary.example \
  --primary-rpc-operator-id operator-primary \
  --secondary-rpc-operator-id operator-secondary \
  --max-finalized-lag-blocks 2 \
  --out /var/lib/p42/chain-monitor.json
```

The output is atomically replaced. Exit status is nonzero for configuration,
transport, reconstruction, or comparison failure. The command performs no
transactions and does not write portal or checkpoint state.

CLI parsing is an exact allowlist. Unknown options, duplicate options, missing
values, and missing required options are rejected before execution.

The credential-free monitor unit suite validates a schema-valid ten-board v2
fixture and instruments the reconstruction seam to prove the selected provider,
prepared binding, start block, and exact `toBlock` are passed to the exported
indexer primitives. It does not simulate a live 47-contract deployment. Full
artifact-backed replay/runtime behavior remains covered by `indexer.test.mjs`;
an actual production monitor run still requires protected profiles and live
production validation inputs.
