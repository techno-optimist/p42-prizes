# CHRONOS — Arithmetic Kakeya v0.2 Final Read-Only Red-Team Audit

## Audit Metadata

- **Auditor:** CHRONOS (ProjectForty2 wheel-holder), read-only git-bound audit.
- **Repository:** P42 Prizes portal / protocol artifacts (`/home/chronos/audits/p42-kakeya-final-audit-264440b`).
- **Git HEAD (verified):** `264440baba0298c6bf81715b58e29bcf30a27f0c`
  - `git rev-parse HEAD` at start **and** at report-write time both returned the pinned SHA.
  - Commit: `Bind Kakeya improvement atoms to claimed score` — Kevin Russell, 2026-07-17 06:13:46 -0600.
  - Working tree: detached HEAD, one untracked file (`chronos-audit.log`). **No tracked file, Git ref, service, or Atlas state was modified.** All builds/tests were executed in an isolated `/tmp` venv and a throwaway `/tmp` Cargo probe; the repo source tree was untouched.
- **Audit UTC timestamp:** 2026-07-17T14:55:08Z.
- **Scope:** Arithmetic Kakeya v0.2 objective, **P0–P2 severities only**. Python↔Rust acceptance parity; shared differential corpus; Unicode/JSON/integer/bounds/closure/threshold/atom semantics; the canonical `improvement_atoms` computation; dishonest claimed-score fraud-proof behavior; Solidity ABI/journal conformance; and activation state. External proof obligations recorded.
- **Explicit non-claim:** This audit **does not** assert production readiness. Findings are audit observations at stated confidence. Phase-0 safety gates and external attestations remain open by design.

## Scope & Methodology

Evidence-first. Every claim below is backed by a file read at the pinned HEAD or by a command that actually executed in this session. Where a common inference would have been wrong, it was resolved by running code rather than reasoning from source shape (see the duplicate-key finding). Surfaces examined:

- Rust consensus core: `objective-programs/arithmetic-kakeya/core/src/lib.rs` (1214 lines, full read).
- SP1 guest: `objective-programs/arithmetic-kakeya/program/src/main.rs`.
- SP1 host/executor: `objective-programs/arithmetic-kakeya/script/src/main.rs`.
- Python verifier: `problems/arithmetic-kakeya/verifier/verify.py` and shared `src/p42_prizes/verdict.py`.
- Shared corpus: `objective-programs/arithmetic-kakeya/fixtures/differential-vectors.json`.
- Cross-language differential harness: `tests/test_arithmetic_kakeya_sp1_differential.py` and the Rust `#[test] shared_v02_differential_vectors_match`.
- Examples: `kt-2x2-forcing.json`, `tampered-seed-claim.json`, `wrong-grid.json`.
- Solidity: `P42SP1VerifierGateway.sol`, `P42ChallengeManager.sol`, `P42ResolverQuorum.sol`, `mocks/MockObjectiveVerifierGateway.sol`.
- Binding dossier: `protocol/production-board-bindings-v1.json`, `SPEC.md`.

Commands executed (verbatim results captured):

- `python3 -m venv /tmp/kakeya-audit-venv && pip install -e . pytest` → RC 0.
- `pytest tests/test_arithmetic_kakeya_sp1_differential.py` → **4 passed**.
- `cargo test -p p42-arithmetic-kakeya-objective-core` → **6 passed; 0 failed** (incl. the shared differential vectors test).
- Standalone serde probe reproducing the exact struct pattern → duplicate keys **REJECT**.

## Finding Summary

| ID | Area | Severity | Status |
|----|------|----------|--------|
| — | Python↔Rust acceptance parity | — | **No P0–P2 defect. Verified equivalent on the shared corpus.** |
| — | Duplicate JSON object-key rejection (both langs) | — | **No defect. Empirically confirmed reject on both sides.** |
| — | Integer/bounds/Unicode/closure/threshold semantics | — | **No P0–P2 defect.** |
| — | `improvement_atoms` canonical formula | — | **No defect. Matches SPEC and tests.** |
| — | Dishonest-claim fraud-proof behavior | — | **No defect. Correction is forced.** |
| — | Solidity ABI / journal conformance | — | **No P0–P2 defect. Journal opaque on-chain; V2 tags bound.** |
| — | Activation state | — | **Correctly `missing` / `proof_kind: none`; gateway inert.** |
| N1 | Python `problems/` suite fails under bare interpreter | Note (non-blocking, out of parity scope) | Environment/harness artifact, not a code defect. |

No P0, P1, or P2 verifier-parity defect was found within scope. The single observation (N1) is an environment artifact, documented for honesty and explicitly *not* rated P0–P2.

## 1. Python ↔ Rust Acceptance Parity

Both implementations parse, validate, build the rational generator subspace, run simultaneous forcing closure, score, threshold-check, and round to atoms. Parity was verified by executing **both** oracles against the **same** corpus:

- Python (`tests/test_arithmetic_kakeya_sp1_differential.py::test_python_exact_oracle_matches_shared_v02_vectors`) — PASSED.
- Rust (`core/src/lib.rs::tests::shared_v02_differential_vectors_match`) — PASSED.

Both consume `fixtures/differential-vectors.json` (schema `p42-arithmetic-kakeya-v0.2-differential/v2`) and assert the identical accept/reject verdict, `score`, `chain_atoms`, and forcing `rounds` for every solution vector, plus identical threshold and outcome results. Because the two harnesses replicate the same mutation set (`mutate()` in Rust, `vector_bytes()` in Python) and assert against a shared expectation table, agreement is a genuine cross-language equivalence check on this corpus, not a self-consistency check.

Structural parity confirmed by direct read:
- Grid forced to `(2,2)`; slope set must contain `[0,0]`; nonzero slopes must not satisfy `a+b=0` (Rust lib.rs:328–336; Python verify.py:122–126).
- Generator construction (`build_generators`) uses identical axis-key rules: axis-1 key must be `[1]`; axis-2 key must be `[1,1]` or `[2,1]` (Rust lib.rs:427–458; Python verify.py:242–257).
- Closure (`can_force` + Gaussian consistency over exact rationals) is structurally identical (Rust lib.rs:462–515; Python verify.py:261–313). Denominator is derived from the **de-duplicated** free set with a `> 0` guard, so a padded `free` list cannot drive the denominator to zero (Rust lib.rs:545–548; Python verify.py:344–354).

**Confidence: high** for this corpus. See obligation E4 for the residual (corpus is finite; exhaustive equivalence is not proven).

## 2. Shared Corpus Consistency

The corpus is authoritative and consumed by both languages plus the SP1 host. Cross-checked invariants:
- `improvement_scale` = `atom_scale` = `1000000000000000000` (1e18); Rust asserts both equal `SCORE_ATOM_SCALE` (lib.rs:969–976).
- `minimum_improvement` = `1/1000000000000` (1e-12), asserted in both harnesses.
- Solution vectors cover: seed accept (`7/4`, atoms `1750000000000000000`), incomplete closure reject, duplicate root/nested keys reject, duplicate semantic entries reject, malformed bool reject, unknown fields reject, UTF-8 BOM / UTF-16 / UTF-32 reject, non-canonical JSON numerics reject, lone-surrogate reject, reflected-grid accept (simultaneous not sequential closure), integer at/over bound accept/reject, worst-case rational accept (`9/4`), slope-count at/over bound accept/reject.

The `production-seed-honest-claim-is-not-improvement` outcome vector encodes the F1 hardening: seed `7/4`, honest claim, `improvement_atoms = 0`, and `challenger_wins = true` — i.e. resubmitting the seed itself does not mint a prize. This matches the binding dossier (`verified_improvement: "0/1"`, `verdict_valid: false`).

**Confidence: high.**

## 3. Semantic Checks

- **Unicode:** Both reject UTF-8 BOM, UTF-16, UTF-32, and lone surrogates; both accept a valid escaped surrogate pair. Rust rejects BOM at the byte prefix and requires valid UTF-8 (lib.rs:242–245); Python rejects BOM and decodes strict UTF-8 (verify.py:98–100) and manually walks surrogate pairs in scalar strings (verify.py:68–82). Verified via the passing corpus vectors `utf8-bom`, `utf16-le`, `utf32-be`, `escaped-*`.
- **JSON canonicality:** Non-canonical integer encodings (`+2`, `02`, `2.0`, `2e0`) reject. Rust's `BoundedInt` deserializer rejects any token containing `. e E +` (lib.rs:261–263). Python's `strict_json_loads` rejects `Infinity/NaN` constants and duplicate keys via `object_pairs_hook` (verdict.py:34–50). `-0` normalizes to `0` and is accepted (corpus `json-negative-zero` → accept `7/4`).
- **Duplicate object keys — empirically resolved (see §3a).**
- **Integer bounds:** `|x| <= 2^255 − 1`. Rust `BoundedInt` enforces `value.abs() > (1<<255)-1 → error` (lib.rs:265–270); Python `require_int` enforces the same and rejects `bool` (an `int` subclass) (verify.py:51–56). Corpus `integer-at-bound` accepts and `integer-over-bound` rejects on both sides.
- **Collection bounds:** slopes ≤ 128, edge labels ≤ 32/axis, free ≤ 4, relations ≤ 128 — identical constants (Rust lib.rs:15–18; Python verify.py:34–37). Corpus `slopes-at-bound` accept / `slopes-over-bound` reject confirmed.
- **Closure:** simultaneous (all currently forcible vertices added per round), not sequential. The reflected-grid vector proves round-shape parity (`rounds` compared exactly).
- **Threshold:** `is_minimum_improvement` uses exact cross-multiplication with `MIN_IMPROVEMENT_DENOMINATOR = 1e12` and checked arithmetic (lib.rs:582–601). Corpus `exact-minimum` accepts, `one-attounit-below-minimum` rejects.
- **Atom rounding:** ceil to 1e18 scale. Rust `(numerator * SCORE_ATOM_SCALE).div_ceil(denominator)` (lib.rs:562); Python `(scaled.numerator + scaled.denominator − 1)//scaled.denominator` (test helper) and `atoms_from_score` uses `-((-n*scale)//d)` (verdict.py:150–155). Independently reproduced: `7/4 → 1750000000000000000`, `1749999999999/1000000000000 → 1749999999999000000`.

### 3a. Duplicate-Key Rejection — Empirical Correction of a Plausible False Positive

A naive source read suggests a parity gap: the Rust core parses with bare `serde_json::from_slice` (lib.rs:246) and has **no** `object_pairs_hook`, whereas Python's `strict_json_loads` explicitly rejects duplicates. Python stdlib `json.loads` is last-wins by default (confirmed: `{"a":1,"a":2}` → `{"a":2}`), so one might infer Rust silently accepts duplicates and diverges. **This inference is wrong**, and I resolved it by execution rather than argument:

- The Rust `shared_v02_differential_vectors_match` test **passed**, and that corpus requires `duplicate-grid-key` and `duplicate-relation-slope-key` (`duplicate-json-key`) to **reject**.
- A standalone Cargo probe reproducing the exact `#[derive(Deserialize)] #[serde(deny_unknown_fields)]` struct pattern returned:
  - `dup_grid: REJECT (duplicate field \`grid\` at line 1 column 20)`
  - `dup_slope: REJECT (duplicate field \`slope\` at line 1 column 49)`
  - `ok: ACCEPT`

Mechanism: serde's derived struct `Deserialize` visitor errors on a repeated struct field independent of `preserve_order`. Since every Kakeya JSON object (root, `EdgeLabel`, `Relation`) is a `deny_unknown_fields` struct, duplicate keys inside those objects are rejected on the Rust side, matching Python. **No parity defect.** Recorded as a resolved candidate finding to prevent future re-litigation.

**Confidence: high (executed on both paths).**

## 4. `improvement_atoms` Canonical Formula

Per the HEAD commit intent, `improvement_atoms` is bound to the claimed score:

```
improvement_atoms = uint256( seed_score_atoms − claimed_score_atoms )   [1e18 scale]
seed_score_atoms  = ceil( seed_numerator * 1e18 / seed_denominator )
```

`canonical_claimed_improvement_atoms` (lib.rs:603–636):
- Computes `seed_score_atoms` by ceil-division (lib.rs:613); bounds it to `int256` max (fails `ImprovementComputationOutOfRange` otherwise).
- Interprets `claimed_score_atoms` as a **signed int256** two's-complement word: if the high bit is set, subtract `2^256` (lib.rs:619–624).
- Computes `seed − claimed`; if negative → `None` (claim above seed fails closed, lib.rs:626–628); if it exceeds 32 bytes → `None`.
- The verifier requires `witness.improvement_atoms == expected` or errors `ImprovementAtomsMismatch` (lib.rs:150–155).

Verified by passing tests: `production_seed_requires_zero_claim_relative_improvement_atoms` (honest seed ⇒ `improvement_atoms = 0`; supplying `1` ⇒ mismatch `expected 0 supplied 1`), `relaxed_seed_rejects_inflated_and_deflated_improvement_atoms` (±1 attounit both rejected), `claimed_score_word_uses_signed_int256_semantics` (all-`0xff` claim treated as negative), and `claimed_score_above_seed_fails_closed_before_journaling` (`ImprovementComputationOutOfRange`). The Python corpus outcome-vector test reproduces the same `seed_atoms − claimed_atoms` relation with a `>= 0` assertion.

**Confidence: high.**

## 5. Dishonest Claimed-Score Fraud-Proof Behavior

The core recomputes the true score and forces the corrected outcome regardless of a plausible (matching-arithmetic) but dishonest claim:

- `expected_score` = recomputed chain atoms **only if** the recomputed score also clears `is_minimum_improvement` against the seed; otherwise `None` (lib.rs:157–159).
- `expected_challenger_wins = expected_score.is_none_or(score != claimed_score_atoms)` — the challenger wins whenever the claim is unverifiable **or** does not equal the recomputed score (lib.rs:160–161).
- `corrected_challenger_wins` must equal that expectation (`CorrectedOutcomeMismatch` otherwise, lib.rs:162–167) **and** must contradict the pending outcome (`NonContradictoryOutcome` otherwise, lib.rs:168–170).

`dishonest_claim_with_matching_improvement_still_produces_correction` (lib.rs:1180–1189) demonstrates a claim of `1.7e18` against a true `1.75e18` seed still resolves to a valid correction. The `production-seed-honest-claim-is-not-improvement` corpus vector confirms even an honest restatement of the seed yields `challenger_wins = true`. So a solver cannot mint a prize by (a) restating the seed, (b) claiming a score the certificate does not achieve, or (c) supplying an arithmetically self-consistent but false claim.

**Confidence: high.**

## 6. Solidity ABI / Journal Conformance

The on-chain journal is **opaque**. The verifier gateway interface takes only `(programVKey, journalDigest, proof)` — improvement atoms and claimed score are **never ABI-decoded on-chain**; they live entirely inside the SP1 guest computation and are bound only through the journal preimage.

- Guest journal (Rust `keccak_tagged(b"P42_OBJECTIVE_VERDICT_JOURNAL_V2", [...])`, lib.rs:222–234) commits: chain_id, quorum, manager, `guest_elf_sha256`, `program_vkey`, `context_hash`, `corrected_challenger_wins`, `proof_beneficiary`.
- On-chain digest (`P42ResolverQuorum.proveObjectiveFraud`, lines 496–508) reconstructs the identical preimage with the same `"P42_OBJECTIVE_VERDICT_JOURNAL_V2"` tag, `objectiveGuestElfSha256Of[manager]`, `programVKey`, `contextHash`, `correctedChallengerWins`, `proofBeneficiary`, then calls `objectiveVerifier.verify(programVKey, journalDigest, proof)`.
- `contextHash` derivation (`objectiveProofContext`, ChallengeManager lines 599–621) matches the guest `P42_OBJECTIVE_CHALLENGE_CONTEXT_V2` construction (lib.rs:211–221), including `keccak256(bytes(transcriptURI))` and the reveal/challenge/pending decision sub-hashes.
- `keccak_tagged` implements ABI-style dynamic `string` head/tail encoding (32-byte offset word, length word, right-padded tag; lib.rs:707–718), consistent with Solidity `abi.encode(string, ...)`.
- The proof beneficiary is journal-bound so a copied proof cannot redirect the resolver-bond reward (ResolverQuorum comment lines 478–481; ChallengeManager lines 561–563). `applyObjectiveResolution` additionally re-checks contradiction on-chain (`P42_OBJECTIVE_OUTCOME_NOT_CONTRADICTORY`, lines 541–543).

Address/codehash pinning: `P42SP1VerifierGateway` pins SP1 verifier `0xb69f...f4e2` with codehash `0xcceb...04dd` and reverts `BadSP1VerifierRuntime` on mismatch (lines 44–46, 35). This binding is an **external attestation obligation** (E1).

**Confidence: medium-high.** Byte-exact keccak preimage agreement between the Rust `keccak_tagged` string encoding and Solidity `abi.encode` is asserted by structural reading and by the guest/host executor round-trip in `script/src/main.rs` (public-values equality check, line 101), but a dedicated on-chain-vs-guest journal-digest differential vector was not exercised in this session (E2).

## 7. Activation Status

Activation is correctly **missing / none**, and the on-chain proof capability is inert:

- `protocol/production-board-bindings-v1.json`, arithmetic-kakeya record (lines 219–286): `guest = { activation_eligible: false, execution: null, identity: null, proof_kind: "none", resource_profile: null, status: "missing" }`; `math_review.status: "pending"`; `provenance.status: "incomplete"` with unresolved independent math + rights review; seed `verdict_valid: false`, `verified_improvement: "0/1"`, `verified_score: "7/4"`.
- `P42SP1VerifierGateway._objectiveProofsActive()` returns `false` (line 60) and `verify()` reverts `ObjectiveProofCapabilityInactive` while inert (line 33).
- `tests/...::test_production_board_remains_missing_and_activation_ineligible` PASSED, pinning the exact `missing`/`none` guest record.

**Confidence: high.**

## 8. External Proof Obligations (for maintainers)

These are **not** closed by code presence and remain outside this audit's authority:

- **E1 — Verifier runtime attestation.** The pinned SP1 verifier address `0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2` and codehash `0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd` must be independently confirmed to be the genuine Succinct SP1 V6.1.0 Groth16 verifier on Base and Base Sepolia.
- **E2 — Guest ↔ on-chain journal differential.** A published test vector proving byte-exact equality between the Rust guest's `P42_OBJECTIVE_VERDICT_JOURNAL_V2` digest and the Solidity `abi.encode` reconstruction in `P42ResolverQuorum` should be added and run in N-host CI before activation.
- **E3 — Guest ELF + vkey registration.** The `guest_elf_sha256` and `program_vkey` registered on-chain (`objectiveGuestElfSha256Of`, `objectiveProgramVKeyOf`) must equal a reproducibly built guest from this exact source under the pinned SP1 toolchain (`sp1Version 6.1.0`). Currently `status: missing` — no ELF/vkey is admitted.
- **E4 — Corpus completeness.** Python↔Rust equivalence is verified on the finite differential corpus, not proven exhaustively. Any future corpus extension must be added to **both** harnesses and pass on both.
- **E5 — Independent mathematical + provenance review.** The dossier records these as unresolved (`math_review.pending`, `provenance.incomplete`). The `7/4` seed is a scoped 2x2 forcing warm-up, explicitly not an arithmetic-Kakeya record; the claim scope must remain narrow.
- **E6 — Seed semantics.** Under `docs/OPEN_WITNESS_SEEDING.md`, `7/4` is a loose starting ceiling for the free open-witness phase; the on-chain frontier self-establishes before `armFunding()`. This is a design decision requiring owner/operator sign-off, not a verifier property.

## 9. Notes (Non-Blocking, Out of P0–P2 Parity Scope)

- **N1 — Python `problems/` suite under a bare interpreter.** `problems/arithmetic-kakeya/tests/test_arithmetic_kakeya.py` failed (15 cases) because it shells out to a per-problem `make verify` → `p42_prizes.cli`, which imports `referencing` (a `jsonschema` dependency) that the invoked subprocess interpreter lacked, and because the subprocess resolves `make` relative to the invocation directory. This is an **environment/harness provisioning artifact, not a verifier defect**: the in-scope SP1 differential suite (which directly imports `verify.py`) and the Rust core suite both pass. Maintainers should ensure the runtime lock (`requirements.runtime.lock`) is installed into the interpreter that runs the per-problem tests. Rated **Note**, explicitly not P0–P2.

## Conclusion

Within the audited P0–P2 scope, the Arithmetic Kakeya v0.2 objective at HEAD `264440b` shows **no P0, P1, or P2 verifier-parity, semantic, atom, or fraud-proof defect**. Python and Rust acceptance were verified equivalent on the shared corpus by executing both suites; duplicate-key rejection was empirically confirmed on both paths (correcting a plausible false-positive parity claim); the `improvement_atoms = uint256(seed_score_atoms − claimed_score_atoms)` formula matches the SPEC and passing tests with signed-int256 claim semantics and fail-closed behavior; dishonest claims force a corrected outcome; the on-chain journal is opaque and V2-tag-bound with a pinned verifier runtime; and activation is correctly `missing`/`none` with the proof capability inert.

**This audit does not certify production readiness.** External obligations E1–E6 (verifier-runtime attestation, guest↔on-chain journal differential, ELF/vkey registration, corpus completeness, independent math/provenance review, seed-semantics sign-off) and the Phase-0 safety gates remain open by design. Read-only: no source, Git, service, or Atlas state was modified.
