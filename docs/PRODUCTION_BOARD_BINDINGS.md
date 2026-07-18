# Production Board Source Bindings

`protocol/production-board-bindings-v1.json` is the ordered source-integrity
dossier for the exact ten slugs in `protocol/production-board-set-v1.json`.
Its schema is `schemas/production-board-bindings.schema.json`.

The dossier binds current repository bytes and local executions. It is not a
production approval, mathematical approval, provenance approval, guest
readiness statement, funding authorization, or launch authorization.

## Bound Source Surface

Each record binds:

- the slug at its exact position in the frozen board cohort;
- `problem.yaml`, `SPEC.md`, and `solution.schema.json` by repository-relative
  path and SHA-256;
- verifier version, command, and the current
  `p42-source-tree-sha256/v2` digest produced by `p42-prizes source-hash`;
- the pinned seed bytes, canonical verifier-report digest, actual verdict
  fields, recomputed exact score, and recomputed exact improvement;
- every manifest objective field plus an explicit target classification;
- a narrow claim scope and hashed local provenance references.

The source-tree digest covers the canonical verifier build-input bundle used
by the repository: shared `src/`, shared `schemas/`, the complete problem
package, and root verifier build files. The manifest image is normalized to
the source sentinel by the versioned hashing algorithm. Image publication and
runtime admission are separate evidence layers.

All ten pinned seeds currently recompute to their manifest `seed_best` value.
Accordingly, every bound report has `valid: false`,
`reason: NOT_STRICT_IMPROVEMENT`, and `improvement: 0/1`. The dossier's
`verified_score` means the verifier recomputed that exact score; it does not
mean the seed won, passed an improvement threshold, or received approval.

## Target Classifications

The classification describes how the manifest `optimum` is used in this
source package. It does not independently prove the underlying mathematics.

- `proven_exact`: the target is represented as an exact established optimum.
- `proven_lower_bound`: the target is represented as an established lower
  bound, not necessarily an attainable optimum.
- `proven_upper_bound`: the target is represented as an established upper
  bound, not necessarily an attainable optimum.
- `search_target`: the target is an aspirational endpoint whose attainability
  is not established here.
- `scoped_surrogate`: the target belongs to a deliberately finite or narrowed
  model and must not be promoted to the unscoped problem.

These labels remain inside records whose provenance status is `incomplete`
and whose math review status is `pending`. The per-record `claim_scope` and
`unresolved` list are controlling limitations, not footnotes.

## External Math Review

Local exact recomputation establishes what the checked code does to the pinned
bytes. It does not establish that a finite encoding faithfully resolves a
broader mathematical question, that a cited bound is correct, that a frontier
claim is current, or that the public framing is suitable for funding.

Every record therefore has:

- `provenance.status: incomplete` with nonempty unresolved work;
- hashed local evidence references only;
- `math_review.status: pending`; and
- `math_review.artifact: null`.

No independent reviewer identity, signature, artifact, or approval is claimed.

## Guest Readiness

Nine boards have `guest.status: missing`, null guest artifacts,
`proof_kind: none`, and `activation_eligible: false`.

Hadamard alone binds the repository's objective-program identity, execution,
and resource-profile artifacts. Its status is
`source-bound-mock-only`: the execution artifact itself says
`single-host-mock-execution`, the proof kind is `none`, and the resource
profile says activation is unauthorized. This binding proves only which mock
artifacts are present in this source tree. It supplies no proof, independent
reproduction, production audit, or activation authority.

## Reproduction

After installing the locked root and per-problem verifier dependencies,
validate the schema, all repository hashes, manifest fields, source trees, and
exact seed verifier outputs with:

```bash
make verify-production-board-bindings
```

After a reviewed shared verifier change, refresh only the source-tree digest
field through the repository command below; it atomically rewrites the dossier
and immediately replays all ten records before succeeding:

```bash
make refresh-production-board-bindings
make verify-production-board-bindings
```

For schema-only inspection:

```bash
python3 - <<'PY'
import json
import jsonschema

schema = json.load(open("schemas/production-board-bindings.schema.json"))
dossier = json.load(open("protocol/production-board-bindings-v1.json"))
jsonschema.Draft202012Validator.check_schema(schema)
jsonschema.Draft202012Validator(schema).validate(dossier)
PY
```

Recompute one source-tree binding and seed verdict with:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli source-hash \
  --problem problems/q6-intersecting-hypergraph
PYTHONPATH=src python3 -m p42_prizes.cli verify \
  --problem problems/q6-intersecting-hypergraph \
  --solution problems/q6-intersecting-hypergraph/tests/seed-pg25.json
```

The seed verifier exits nonzero because a tied seed is not a strict
improvement; inspect its canonical JSON report rather than treating that
expected non-winning exit as a source-integrity failure.
