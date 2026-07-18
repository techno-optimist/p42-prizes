# Autoconvolution C1 Upper Objective Core

Candidate-only Rust port of canonical verifier `0.1.1`, exact on the documented
production input domain, at exact-main
`1b65b84b13dbe350339bcd985b44b5224e6c6df7`. The nine-prime
NTT/CRT implementation, coefficient checksum, first-maximum tie rule,
minimization threshold, and `ceil(score*10^18)` atom conversion are preserved.
Qualification requires a score strictly below the seed and an exact
improvement of at least `1/10^12`.
Every admitted coefficient is at most `N*(10^36)^2 < 2^256`; the CRT product is
about `2^278.66`, and the executable range test enforces uniqueness.

The shared parser matches the authority's UTF-8/16/32 byte detection, recursive
duplicate-key rejection after escape decoding, and 4,300-digit CPython
integer-token ceiling. Candidate production additionally limits JSON to 256
nested containers in both Python and Rust; this is an explicit domain
intersection, not a claim that Rust reproduces CPython's environment-dependent
stack limit. Python numeric equality is preserved for
`n`, including `90000.0` and `9e4`; vector entries remain actual non-boolean
integer tokens. Hostile vectors cover encodings, duplicates, exponents,
booleans, raw and escaped surrogates, integer length, and depth. Raw surrogate
metadata is admitted for parser consensus but is not retained or exposed as a
Rust string.

`evaluate_and_journal` prepares the full
`P42_OBJECTIVE_VERDICT_JOURNAL_V2` digest. Invalid solutions map to
`expected_score_atoms=None` so a challenger-winning journal remains provable.
The input cap is checked before JSON
parsing, but no SP1 artifact is active: 6.3.1 was removed and no replacement
version is asserted safe. See `BUILD_PENDING.md`. In particular, a future SP1
guest abort on invalid input means no valid proof, not a committed typed reject.

```bash
cargo test --workspace
cargo test --release -p p42-autoconvolution-c1-upper-objective-core -- --ignored
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```
