# Funding Admission Semantics

Fundable admission treats verifier output as evidence, not policy. Signed host
records bind the verifier's canonical `VerdictReport`, but the final readiness
gate independently decides whether that report describes a strict improvement.

## Trusted inputs

The readiness gate takes objective policy only from `problem.yaml`:

- `objective.seed_best`
- `objective.direction`, exactly `minimize` or `maximize`
- `objective.min_improvement`, which must be a positive exact rational

It takes the candidate score from the canonical rational `report.score` embedded
in the signed admission evidence. Rational parsing and scaling are exact; no
float conversion, decimal approximation, verifier gauge string, or unbound
verifier threshold decision participates in admission.

## Independent derivation

For a maximizing objective:

```text
derived_improvement = max(0, report.score - objective.seed_best)
```

For a minimizing objective:

```text
derived_improvement = max(0, objective.seed_best - report.score)
```

The exact value above is the only acceptable `report.improvement`. Funding
validity is deliberately not decided by comparing that rational directly with
`objective.min_improvement`, because deployment quantizes the seed, candidate,
and threshold independently.

## Deployment atom derivation

Admission mirrors `agent/lib.mjs`, the runner, the deployment ceremony, and
`P42SubmissionManager` at `SCORE_ATOM_SCALE = 10^18`:

```text
atomsFromScore(x) = ceil(x * 10^18)

chainScoreAtoms(x, minimize) = atomsFromScore(x)
chainScoreAtoms(x, maximize) = atomsFromScore(-x)

seedScoreAtoms       = chainScoreAtoms(seed_best, direction)
scoreAtoms           = chainScoreAtoms(report.score, direction)
minImprovementAtoms  = atomsFromScore(min_improvement)
marginalAtoms        = max(0, seedScoreAtoms - scoreAtoms)
fundingValid         = marginalAtoms >= minImprovementAtoms
```

Ceiling is applied to each input before subtraction. Quantizing the exact delta
instead is not equivalent. For example:

```text
seed_best              = 102 / 10^19  -> seedScoreAtoms = 11
report.score            =  91 / 10^19  -> scoreAtoms = 10
min_improvement         =  11 / 10^19  -> minImprovementAtoms = 2
exact improvement       =  11 / 10^19
marginalAtoms           = 1
fundingValid            = false
```

Admission requires `report.improvement` to equal `derived_improvement` exactly
and `report.valid` to equal `fundingValid`. Verifier admission does not require
an unpublished winning solution before a prize can open: it accepts either a
strict witness or a structurally valid non-winning report whose reason is exactly
`NOT_STRICT_IMPROVEMENT`. Other false reports remain inadmissible. Seed and
candidate atoms must be strictly inside `(-2^254, 2^254)`, matching the
submission-manager score range, and
`minImprovementAtoms` must fit a positive `uint256`. These checks cover negative
scores and both native objective directions.

A verifier that uses a ratio, inverted direction, stale seed, different
threshold, rounded value, exact-delta thresholding, or any other score semantics
inconsistent with deployment therefore fails closed even when its image,
signatures, report hashes, and N-host matrix are otherwise valid.

Cross-language golden vectors in `tests/test_admission_semantics.py` duplicate
the expected BigInt outputs of `agent/lib.mjs` explicitly and assert that both
admission and the Python runner produce those values.

## JSON boundary

Strict JSON parsing rejects `NaN`, infinities, and duplicate object keys at every
nesting depth. Duplicate-key rejection prevents parser-dependent last-key-wins
or first-key-wins interpretations before evidence hashing and validation.
Canonical valid JSON is unchanged.

## Semantic funding blocks

Some packages are ineligible independently of operational evidence:

- `hadamard-mini` is a Phase 0 demo fixture with bundled solving witnesses and
  is permanently ineligible for funding.
- `signed-autoconvolution-c3-upper` is blocked from funding admission until its
  score semantics and objective/verifier contract are redesigned. Rebuilding an
  image or collecting a new host matrix cannot clear this block.
