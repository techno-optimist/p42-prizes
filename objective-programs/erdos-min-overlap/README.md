# Erdos Minimum-Overlap Objective Core

Candidate-only Rust port of the fixed-resolution canonical verifier, exact on
the documented production input domain,
`0.1.1` at exact-main `1b65b84b13dbe350339bcd985b44b5224e6c6df7` in
`/private/tmp/p42-gate-ledger-live-truth`. It requires `n == 2400`, exactly
2,400 integer dyadic numerators, and preserves the `HALF_N = 1200`
normalization and first-maximum lag tie rule.

`objective-shared` reproduces canonical UTF-8/16/32 BOM/null-pattern detection,
recursive duplicate-key rejection after escape decoding, and the standard
4,300-digit CPython integer-token ceiling. Candidate production additionally
limits JSON to 256 nested containers in both Python and Rust. This explicit
domain intersection avoids claiming equivalence to CPython's
environment-dependent stack-overflow depth. Python numeric equality is
preserved for `n`, so
`2400.0` and `2.4e3` equal 2400, while booleans, non-integral values, and
nonfinite overflow values do not. Denominator powers and vector entries still
must be actual non-boolean integer tokens. Raw surrogatepass code points and
escaped lone surrogates in ignored metadata are accepted across UTF-8/16/32.
The provenance-aware duplicate scanner preserves CPython's distinction between
raw code-unit pairs and JSON `\u` pairs; metadata values themselves are not
retained or exposed as Rust strings.

`evaluate_and_journal` prepares the complete
`P42_OBJECTIVE_VERDICT_JOURNAL_V2` challenge digest using the existing
`p42-objective-core` word/address/hash types. `evaluation_digest` remains only
a diagnostic helper and is not an activation journal. Malformed or otherwise
invalid solutions map to `expected_score_atoms=None`, allowing construction of
the canonical challenger-winning journal.

Input is capped at 256 KiB before JSON parsing. Work is fixed at 5,760,000
exact products across 4,799 lags; `BigUint` arithmetic avoids integer wrap.
This is not an SP1
activation artifact: there is no active SP1 dependency, guest manifest, ELF,
vkey, or proof. See `BUILD_PENDING.md` for the fail-closed activation gate and
accurate abort semantics.

```bash
cargo test --workspace
cargo test --release -p p42-erdos-min-overlap-objective-core -- --ignored
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
python3 objective-shared/tests/test_python_authority.py --canonical-root /private/tmp/p42-gate-ledger-live-truth
```
