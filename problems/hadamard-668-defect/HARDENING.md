# Hardening Notes

## R1 - Exact arithmetic

The certified path uses integer bit operations only. Row-pair dot products are
computed from exact hamming distances; no floating-point linear algebra is
present.

## R2 - Recompute, never echo

The verifier ignores claimed scores and recomputes all `222778` row-pair dot
products from the submitted row bits.

## R3 - Determinism and reproducibility

The verifier emits canonical JSON with sorted keys and exact rational strings.
It performs no random, clock, network, locale, environment, or filesystem reads
other than the supplied solution path.

## R4 - Total and bounded

Inputs are capped before parsing. Shape, encoding, row length, and hex alphabet
failures return typed reports instead of uncaught exceptions.

## R5 - Canonical output

The verifier emits the `VerdictReport` schema in
`../../schemas/verdict.schema.json`.

## H1 - Compact encoding

Rows are hex bitstrings, not nested sign arrays. The payload is small enough for
data-availability receipts and deterministic runner queues.

## H2 - Boundary and near-equality

Orthogonality is a single exact integer condition: hamming distance exactly
`334`. There is no tolerance band.

## H3 - Sampling gaps

Every row pair is checked.

## H5 - Claimed-value trap

The lying-score fixture claims defect zero for an all-ones matrix. The verifier
ignores the claim, recomputes defect `222778`, and rejects it.

## H6 - Open-problem scope

This package is a defect ladder. It does not claim a Hadamard matrix of order
668 exists; only defect `0` would exhibit one.
