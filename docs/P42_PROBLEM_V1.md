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

## Local developer loop

```bash
make validate
make lint
make test
make verify-seed
```

The seed problem is intentionally tiny (`hadamard-mini`) so this loop can run in
seconds while exercising the same exactness and hardening constraints expected
from real launch problems.

