# P42 Problem v1

This is the executable Phase 0 slice of the larger design in `docs/BUILD.md`.
It defines the smallest repository shape an agent can clone, inspect, verify,
and submit against.

## Repository contract

Every problem lives under `problems/<problem-id>/` and must provide:

- `problem.yaml`: manifest pinned by the registry.
- `SPEC.md`: exact statement, objective, score, and improvement metric.
- `solution.schema.json`: canonical raw solution format.
- `verifier/`: code for the certified path.
- `Makefile`: `make verify SOLUTION=path` prints one canonical `VerdictReport`.
- `tests/`: known-good, known-bad, and hardening fixtures.
- `HARDENING.md`: R1-R5 and H1-H6 evidence.
- `BOUNTY.md`: chain, bond, challenge, and pool metadata.
- `LEADERBOARD.md`: append-only frontier history.
- `Dockerfile` and `requirements.lock`: reproducible runtime declaration.

## Certified path rules

The verifier must recompute the score from the raw solution. Claimed scores in
the submitted JSON are treated as untrusted comments. The certified path uses
only integer, rational, or enclosed-interval arithmetic; no native float may
influence `valid`, `score`, or `improvement`.

The canonical report is stable JSON with sorted keys, exact rationals serialized
as `"num/den"`, and a `sha256:` hash of the raw solution bytes. The report is
the unit of dispute in the optimistic oracle.

## Admission evidence

Local verification is not enough for a funded bounty. Each fundable verifier
must produce host evidence on the N-host matrix and then combine those files
into one matrix artifact:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli admit-host \
  --problem problems/hadamard-mini \
  --solution problems/hadamard-mini/examples/valid-4.json \
  --runs 3 \
  --host-label <unique-host-label> \
  --output host-evidence.json

PYTHONPATH=src python3 -m p42_prizes.cli admit-matrix \
  --evidence x86-glibc-a.json \
  --evidence x86-glibc-b.json \
  --evidence arm-glibc-a.json \
  --evidence arm-glibc-b.json \
  --output admission-matrix.json
```

The matrix gate requires at least four distinct host labels, both `x86_64` and
`aarch64`, at least two distinct `glibc` versions, and byte-identical canonical
`VerdictReport` hashes. The artifact schemas live at
`schemas/admission-host.schema.json` and `schemas/admission-matrix.schema.json`.

## Local developer loop

```bash
make validate
make lint
make test
make verify-seed
make admit-host-seed
```

The seed problem is intentionally tiny (`hadamard-mini`) so this loop can run in
seconds while exercising the same exactness and hardening constraints expected
from real launch problems.
