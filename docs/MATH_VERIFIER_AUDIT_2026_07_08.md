# Math And Verifier Audit

Status date: 2026-07-08.

This audit checks the ten launch-slate boards against the production admission
bar in `docs/P42_PROBLEM_V1.md` and `docs/GATE_LEDGER.md`. It is deliberately
conservative: a board is not fundable merely because a certificate repo or arena
note reproduces locally. It must be a self-contained P42 problem with exact
fixtures, resource bounds, immutable verifier image evidence, and a passing
N-host matrix.

## Bottom Line

The portal is correctly fail-closed and honest for Phase 0: all ten boards are
listed, every board has a reserved testnet donation wallet, and only
`hadamard-mini` accepts local pilot submissions. The math source material for
several locked boards reproduces locally, but the nine locked boards are not
production-admitted prize problems yet.

No real ETH funding gate closes from this audit. Gate 1 and Gate 2 remain
blocked.

## Evidence Replayed

From `/Users/nivek/Desktop/p42-prizes`:

```bash
make validate
make lint
make test
make verify-seed
make admit-host-seed
make contracts-test
cd web && npm run test && npx tsc --noEmit && npm run build:prizes && npm audit --audit-level=moderate
```

Results:

- Problem validation and exact-path lint passed for `hadamard-mini`.
- Python test suite passed: 38 tests.
- Seed verifier emitted a canonical valid `VerdictReport`.
- Local host evidence emitted two identical report hashes on the Mac host.
- Contract scaffold tests passed: 22 Hardhat tests, zero moderate-or-higher npm
  audit findings.
- Web test/build/audit passed: 59 Vitest tests, TypeScript clean, production
  build clean except the known Turbopack dynamic-import warning from the local
  portal store path, zero moderate-or-higher npm audit findings.

Additional arena and certificate evidence:

- `PYTHONPATH=.. pytest -q tests/test_build_pnt_lp.py` passed in the arena
  worktree: 15 tests. This covers PNT LP domain and midpoint-row pitfalls.
- `/Users/nivek/Desktop/pnt-ceiling-certificates`: `make verify` reproduced
  the exact K=4800 and K=12000 ceiling certificates.
- `/Users/nivek/Desktop/autoconvolution-inequality-certificates`: exact Board
  2, Board 3, Board 4 fraction checks reproduced, and `scripts/certify.py`
  confirmed the expected published-fraction match plus expected non-match
  against the stronger internal C2 target.
- `/Users/nivek/Desktop/cultural-soliton-observatory/arena/erdos_note`:
  `scripts/erdos_upper_exact.py` matched `certs/lane_u_exact_output.txt`.

## Ten-Board Readiness

| Board | Audit status | Production-readiness judgment |
| --- | --- | --- |
| `hadamard-mini` | Runnable local pilot. Exact integer verifier, hardening tests, schema validation, deterministic canonical report, and portal/API wiring all pass. | Not yet fundable. Needs pinned immutable image digest and collected four-host matrix covering x86, ARM, and at least two glibc versions. |
| `erdos-min-overlap` | P42 package now exists with dyadic-integer witness format, exact normalization, all 4,799 lags checked, lying-claim fixture, shape fixture, rescale-range fixture, and local host evidence on one Mac host. | Locked. Needs immutable verifier image, collected four-host matrix, and external review of the piecewise-linearity/reduction lemma before funding. |
| `edges-vs-triangles` | Arena findings indicate exact live-verifier evidence and a sealed global-model result below the gate. The P42 repo has no self-contained verifier package yet. | Locked. Build a rationalized problem package around the exact row-normalization, moment-curve, area, and max-gap model. Include fixtures for the trapezoid/scoring trap. |
| `arithmetic-kakeya` | No admitted local exact verifier interface was found. This remains the highest-risk marquee board. | Locked. Do not fund until the official status, statement, certificate language, and exact self-certifying verifier are externally reviewed. |
| `autoconvolution-c1-upper` | External certificate repo reproduces exact Board 2 arithmetic. It certifies an existing leader vector rather than a new prize verifier package. | Locked. Wrap the exact integer convolution and rational scoring path in a P42 repo with canonical encoding, runtime cap, lying-score tests, and N-host timing. |
| `autoconvolution-c2-lower` | External certificate repo reproduces exact Board 3 arithmetic. Large-vector memory/runtime risk remains unresolved for the portal runner. | Locked. Define chunked artifact format, explicit memory ceiling, exact `L1`/`L2`/`Linf` checks, and adversarial size fixtures before admission. |
| `signed-autoconvolution-c3-upper` | External certificate repo reproduces exact Board 4 signed fraction. | Locked. Package signed normalization and sign/max checks with sign-flip, zero-vector, malformed-sign, and claimed-score fixtures. |
| `mertens-lp-ceiling-k12000` | PNT ceiling certificate repo verifies the K=12000 proof-side ceiling exactly. It is not a construction board and does not imply monotonicity across reaches. | Locked. Package canonical dyadic dual arrays, interval-log audit, residual checks, and skeptic fixtures. UI copy must avoid overclaiming beyond the finite reach. |
| `pnt-sparse-mertens-construction` | Arena PNT LP guard tests pass, but this construction board has no self-contained exact verifier in P42 yet. | Locked. Replace all sampling/proxy checks with exhaustive exact constraints, pin sparse rational support encoding, and add planted sampling-gap fixtures. |
| `hadamard-668-defect` | The verifier shape is straightforward integer row-pair dot products, but no compact encoding, baseline artifact, runtime profile, or problem package exists. | Locked. Build compact matrix encoding, enforce row/sign grammar, benchmark all pairwise dot products, and collect N-host evidence before funding. |

## Cross-Cutting Findings

1. The verifier moat is working as a policy: the portal refuses submissions for
   every board that lacks an admitted exact verifier.
2. The current donation-wallet surface is safe only because the wallets are
   marked testnet/local-chain provenance and the locked boards cannot settle.
3. The local admission tooling is correctly stricter than "two runs on one
   machine": it requires at least four distinct host labels, x86 and ARM
   coverage, two glibc versions, and identical canonical report hashes.
4. The external certificate repos are useful seeds, but none of them should be
   treated as drop-in verifiers until they are wrapped in the P42 `VerdictReport`
   contract with hostile fixtures and resource ceilings.
5. The two proof-side boards, especially `mertens-lp-ceiling-k12000`, need copy
   and scoring language that cannot be confused with constructive frontier
   submissions.

## Required Next Work

1. Freeze `hadamard-mini` and `erdos-min-overlap` image metadata and collect
   their real four-host matrices.
2. Package the next lowest-risk verifier, likely `autoconvolution-c1-upper`.
3. Keep `arithmetic-kakeya` locked until a certificate standard exists and an
   external math reviewer signs the statement.
4. Add one P42 problem package at a time. Do not unlock a portal board until
   `make validate`, `make lint`, exact verifier tests, `admit-host`,
   `admit-matrix`, and `admit-ready` all pass.
5. Run the full Gate Ledger command set after every admitted verifier package.

## Go/No-Go

- Phase 0 public portal and local pilot: go.
- Testnet prize settlement: no-go until Gate 1 blockers close.
- Real ETH or Coinbase Onramp: no-go until Gate 2 blockers close.
- Any of the nine locked boards accepting submissions: no-go until admission
  artifacts exist and the gate ledger is updated with links to evidence.
