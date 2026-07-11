# Gate 1 open-witness launch evidence

An open phase establishes a board's initial frontier on chain without paying
credit. It is a protocol mechanism, not by itself launch evidence. A board may
claim Gate 1 only when `normalize_open_witness_launch` accepts a packet matching
`schemas/open-witness-launch.schema.json` against current canonical chain state.

## Per-board evidence boundary

Every packet binds one board ID, registry problem ID, problem slug, network and
chain ID to the exact deployment manifest, configuration artifact, 40-character
Git commit, and the release-bound registry, pool, and submission-manager
addresses. The admitted verifier image hash and admission-matrix hash, solution
CID, DA hash, canonical transcript/report hash, and pre/post frontier atoms are
part of the same signed object. A packet from another board cannot be reused.

The transcript bytes are resolved beneath a frozen artifact root and hashed.
They must repeat the board identity, witness CID/DA binding, verifier hashes,
and exact frontier transition. Release artifacts are additionally required to
be the bytes committed at the bound Git commit. Symlinks, path traversal,
changed bytes, and caller-declared hashes fail closed through the shared secure
artifact and release-binding validators.

## Live chain proof

The legacy Python `ChainReader` proves only block hashes and runtime code and is
explicitly insufficient. The normalizer requires an `OpenWitnessChainReader`
with `read_open_witness(...)`. No production CLI builds that reader today, so
production remains unavailable and fail-closed until the JS indexer/collector
integrates it. The explicit reader must return:

- canonical, successful commit, reveal, finalize, and `armFunding` receipts;
- each receipt's transaction hash, block number, and current finalized block hash;
- versioned canonical collector-format transaction and event summaries encoded
  as hex JSON; Python checks their phase, target, submission ID, solver, CID,
  DA hash, score/frontier, event signatures, and arguments. These fields retain
  the schema names `raw_input` and `raw_receipt_logs` for v1 compatibility,
  but they are not raw Ethereum calldata, topics, or receipt bytes;
- registry problem ID, board/problem slug, contract addresses, verifier pins,
  witness ID, solution CID/DA hash, and canonical report hash;
- finalized storage reads for the exact pre/post frontier atoms, submission
  credit, registry problem ID, funding state, and pool balance;
- `fundingArmed == false` at finalization and zero pool balance before arming;
- a successful `armFunding` receipt strictly after witness finalization.

The normalizer compares every returned field with the packet. Missing RPC
resolution, stale or reorged block hashes, failed or duplicate receipts,
mismatched frontier state, a reused witness, nonzero paid credit, pre-arm pool
funds, or arming before/at finalization rejects the gate claim. Cached fixture
data cannot claim a live gate because `canonical` and `finalized` must come from
the out-of-band reader and all receipt/state fields must resolve live.

The production collector must independently fetch and ABI-decode the actual
transaction calldata and receipt logs before constructing these summaries.
Python validates the collector-format contract only; it does not independently
decode Ethereum ABI bytes, and therefore cannot set `gate_passed`.

The release-bound configuration must identify the exact board and admission
matrix, declare `objective: minimize`, and pin a positive `min_improvement_atoms`.
The validator requires `post < pre` and `pre - post >= min_improvement_atoms`.
Collector observations may be at most 15 minutes old, no more than 60 seconds
in the future, and every lifecycle receipt must be at least 12 blocks behind the
finalized head with the same current canonical block hash.

## Signoff order

After artifacts and chain evidence are complete, an organizationally independent
reviewer and a distinct engineering owner sign the canonical evidence hash using
the shared `P42-ATTESTATION-V2` Ed25519 envelope. Both identities, roles, keys,
and validity windows must already exist in the out-of-band trust registry for
`p42-open-witness-launch/v1`. Signatures created before evidence completion are
invalid. Successful normalization emits `evidence_valid: true` and
`attestation_valid: true`, but always emits `gate_passed: false`. Caller-authored
`gate_passed: true` is rejected. Test registries and generic readers can never
elevate the gate; explicit production collector authority is not integrated.

The deployment ceremony has **11 setup operations per board**; evidence binds
the resulting final addresses and state and must not assume the older count 10.

No committed example or fixture is launch evidence. Until a current deployment
produces a packet that passes this live normalization, every board remains
unfundable.
