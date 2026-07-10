# P42 v1 cross-language conformance

`conformance/p42-v1.mjs` is a dependency-free Node implementation of the
Python `VerdictReport` wire contract. It independently normalizes exact
rationals, emits Python-compatible ASCII-only canonical JSON, and computes the
SHA-256 digest over those exact UTF-8 bytes.

The shared corpus executes the checked-in adversarial transcript fixtures and
covers synthetic rational sign and reduction
edge cases, nested details, control characters, non-ASCII strings, Unicode key
ordering, large rational integers, and the largest exactly representable Node
integer. The harness rejects missing or additional report fields, malformed or
zero-denominator rationals, malformed hashes, type confusion, non-finite or
unsafe numbers, sparse arrays, `undefined`, and non-JSON objects.

Run the cross-language proof through the existing CI entry point:

```sh
make test
```

The Python test invokes Node, compares every canonical byte string and digest
against `p42_prizes.verdict`, and fails on any disagreement. No workflow or
package dependency is required.

## Numeric boundary

Python's generic canonical JSON accepts arbitrary integers and finite floats.
JavaScript's `number` cannot represent all of either domain without loss. The
Node p42:v1 implementation therefore accepts only safe integers in `details`;
larger or fractional numeric evidence must be encoded by a registered string
format. This fail-closed boundary prevents distinct source values from
collapsing to the same report bytes.
