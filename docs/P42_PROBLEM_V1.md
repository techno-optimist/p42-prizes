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

Before a problem can be funded, the verifier image must also pass the immutable
digest gate:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli admit-ready \
  --problem problems/<slug> \
  --matrix admission-matrix.json
```

This rejects placeholder images such as `sha256:local-dev`, `sha256:pending`,
or `sha256:pilot`. See `docs/VERIFIER_IMAGE_REGISTRY.md` for the registry
fields and evidence requirements.

## Data availability evidence

For a funded submission, DA rides the chain itself: the commit binds
`commitDaHash = sha256(raw solution bytes)` on-chain, and for on-chain-DA
problems (≤ 512 KB) the reveal carries the raw bytes in calldata with the
contract enforcing `sha256(bytes) == commitDaHash`. The 3 large autoconvolution
problems use an off-chain content-addressed store gated by the same anchor. A
permanence receipt at finalize is optional (an Arweave mirror is
defense-in-depth, not a requirement) — see `docs/DATA_AVAILABILITY.md`. The
local CLI packages optional mirror-receipt evidence:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli da-receipt \
  --problem problems/<slug> \
  --solution solution.json \
  --solution-cid sha256:<raw-solution-hash-or-external-cid> \
  --solver-address 0x... \
  --salt <commit-salt> \
  --commit-provider base-sepolia-calldata \
  --commit-receipt-uri https://sepolia.basescan.org/tx/0x... \
  --commit-block-reference base-sepolia:<block> \
  --arweave-txid <43-char-base64url-txid> \  # optional mirror receipt
  --output da-evidence.json

PYTHONPATH=src python3 -m p42_prizes.cli da-verify \
  --evidence da-evidence.json \
  --problem problems/<slug> \
  --solution solution.json
```

`da-verify` checks canonical receipt hashes, the raw solution hash, the optional
Arweave txid shape, and the exact `p42:v1` commitment preimage. It does not
fetch live provider receipts — the load-bearing availability + integrity proof
is the on-chain `sha256(bytes) == commitDaHash` check at reveal; see
`docs/DATA_AVAILABILITY.md`.

## Challenge window rationale

The v1 challenge window defaults to 72 hours because the verifier is the trust
root. After reveal, watchers need enough time to fetch the payload, re-run the
exact verifier, compare the canonical report, prepare a challenge transaction,
and survive normal ops delays such as time zones, weekends, RPC lag, and a heavy
verifier. Shorter windows make theft viable by submitting near monitoring blind
spots. Longer windows lock solver bonds and payouts, so the parameter should be
tuned per problem and pool size after testnet evidence.

P42 should still verify immediately. The runner/indexer path watches each
commit/reveal, fetches the payload, re-runs the verifier, publishes a transcript,
and alerts or auto-challenges on mismatch. That early pass is operational
evidence, not the final oracle: the challenge window keeps the arena open to
independent re-runs and protects against watcher outages, provider hiccups,
stale images, corrupted caches, and slow high-value verifiers.

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
