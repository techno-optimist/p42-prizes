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

Python's generic canonical JSON remains available to non-verdict evidence, but
`VerdictReport.details` is restricted in both implementations to null, strings,
booleans, recursively structured arrays/objects, and lossless integral numbers
in JavaScript's safe range. Python normalizes integral JSON floats such as `1.0`
to `1`; larger or fractional numeric evidence must use a registered string
format. This fail-closed boundary prevents distinct source values from
collapsing to the same report bytes.
