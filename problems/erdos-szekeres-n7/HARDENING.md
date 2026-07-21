# Hardening Notes

## Closed input and resource surface

The solution is capped at 16,384 bytes. Strict JSON rejects duplicate object
keys and non-JSON constants. The schema and parser allow only 32 or 33 point
pairs, reject unknown fields, booleans, duplicate coordinates, malformed pairs,
and coordinates outside `[-10^12,10^12]`. Fixed point count bounds both loops:
at most 5,456 determinant checks for general position and 4,272,048 hull checks.

## Deterministic exact path

Point order is discarded by lexicographic canonicalization. The verifier uses
only Python integers, lists, tuples, and deterministic combination enumeration.
The test suite AST-scans the verifier to reject float literals, `float()`, and
numerical imports. The verifier emits a canonical `VerdictReport` for expected
and unexpected failures.

## Adversarial coverage

Fixtures cover the exact 32-point baseline, a 33-point convex-curve rejection,
lying score fields, duplicate points, collinearity, wrong counts, malformed
JSON, duplicate keys, booleans, oversized coordinates, unknown fields, and
schema agreement. Tests independently recompute the baseline's triple and
seven-subset counts.

## Unclosed admission gates

This package is deliberately non-admitted. Before promotion it still needs:

- an independent clean-room verifier review and signed mathematical review;
- a legal/license decision for retaining and redistributing the frozen point vector;
- an immutable verifier image and source-release binding;
- identical-hash N-host evidence across independent x86_64 and aarch64 Linux operators;
- hostile runtime measurements on the certified image and production sandbox;
- launch-slate, production-board-binding, funding-target, contract, and governance review.

None of those missing artifacts is simulated here.
