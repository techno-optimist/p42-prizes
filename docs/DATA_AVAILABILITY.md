# Data Availability Evidence

The red-team DA failure was simple: a solver can be honest during the challenge
window and still strand future challengers if the winning blob disappears later.
P42 therefore needs two separate evidence anchors:

- commit-time availability, bound into the `p42:v1` commitment preimage,
- finalize-time permanence, backed by an Arweave transaction id before any payout
  credit is recorded.

The local Gate 1 scaffold now has an offline evidence format:
`p42-da-receipt/v1`, with schema at `schemas/da-receipt.schema.json`.

## Build Evidence

```bash
PYTHONPATH=src python3 -m p42_prizes.cli da-receipt \
  --problem problems/hadamard-mini \
  --solution problems/hadamard-mini/examples/valid-4.json \
  --solution-cid sha256:<raw-solution-hash> \
  --solver-address 0x... \
  --salt <commit-salt> \
  --commit-provider base-sepolia-calldata \
  --commit-receipt-uri https://sepolia.basescan.org/tx/0x... \
  --commit-block-reference base-sepolia:<block> \
  --arweave-txid <43-char-base64url-txid> \
  --output da-evidence.json
```

The command emits:

- `commit_time`: provider, receipt URI, block reference, solution CID, and
  `sha256:` payload hash.
- `permanence`: Arweave txid/URI plus the same CID and payload hash.
- `contract.commit_da_hash`: `bytes32` SHA-256 anchor for the canonical
  commit-time receipt object.
- `contract.permanence_hash`: `bytes32` SHA-256 anchor for the canonical
  permanence receipt object.
- `contract.commitment_preimage`: the exact
  `p42:v1|cid:<len>:...|solver:...|da:...|salt:<len>:...` string mirrored by
  `P42SubmissionManager`.
- `evidence_hash`: hash of the full canonical evidence object.

## Verify Evidence

```bash
PYTHONPATH=src python3 -m p42_prizes.cli da-verify \
  --evidence da-evidence.json \
  --problem problems/hadamard-mini \
  --solution problems/hadamard-mini/examples/valid-4.json
```

This fails closed if the payload hash does not match the solution bytes, if the
commit/permanence objects no longer hash to the advertised contract anchors, if
the Arweave URI does not point at the txid, or if the preimage no longer matches
the solver, CID, DA hash, and salt segment.

## Honest Limit

This is not yet a live provider proof. It does not fetch from Arweave, verify a
Base receipt, prove inclusion at a commit block, or slash unavailable payloads.
It is the local artifact gate that the deployer, indexer, and resolver must
agree on before real DA provider checks are wired.
