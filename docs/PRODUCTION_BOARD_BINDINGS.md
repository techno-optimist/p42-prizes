# Production Board Source Bindings

`protocol/production-board-bindings-v1.json` is the ordered source-integrity
dossier for the exact ten slugs in `protocol/production-board-set-v1.json`.
Its schema is `schemas/production-board-bindings.schema.json`.

The repository also defines the non-activating migration protocol at
`protocol/production-board-bindings-v2.schema.json`. There is intentionally no
committed production v2 dossier yet. The existing v1 dossier remains unchanged,
and every v1 record is activation-ineligible.

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

## V2 Proof Promotion

V2 is an overlay, not a reinterpretation or replacement of v1 source evidence.
The validator hard-pins the exact current v1 dossier and board-set paths and
byte digests, hard-pins the exact v1 schema digest, recursively applies that
schema and the full exact verifier, then
requires all ten base records to remain `activation_eligible: false` with
`proof_kind: none`. Each overlay record also binds its ordered v1 source record
by canonical JSON digest. Every v2 record is required to remain
`activation_eligible: false`, including records with a complete promotion
evidence object. V2 validates and binds migration evidence only; it cannot
authorize funding. Eligibility requires a later protocol version with pinned
executable SP1 Groth16 verification and deployed-Solidity replay adapters.
The v2 migration envelope is fixed to Base Sepolia (chain 84532); a mainnet
promotion requires that later activating protocol rather than a coordinated
rewrite of signed v2 evidence.

The overlay contains only typed evidence references. Referenced JSON must use
the schemas in `protocol/objective-proof-promotion-evidence-v2.schema.json`, be
exact canonical ASCII JSON with one trailing newline, carry a valid self-hash,
and have a valid Ed25519 signature from the required identity and role in the
separately pinned authority registry. The registry pin is not supplied by the
overlay. No production registry or pin is committed yet.

The typed evidence derives and cross-binds:

- a regular frozen ELF, its SHA-256, program vkey, source commit, and separate
  identity evidence;
- an immutable `repository@sha256:...` verifier image and release evidence;
- a claimed nonempty Groth16 artifact with `mock: false`, typed public values, and exact
  ELF/vkey/image/journal/admission/release bindings;
- exact journal and Solidity replay evidence, public-values digest, contract
  address, nonempty runtime bytecode, its derived Ethereum Keccak-256 codehash,
  and the fixed Base Sepolia chain ID;
- measured worst-case admitted-input instructions, proving time, memory, proof
  size, verification gas, and prover cost, each within a release limit;
- an explicit N-host matrix with at least three distinct hosts, operators, and
  hardware fingerprints reproducing the same proof identity and journal;
- completed math, provenance, rights, and scope reviews from distinct review
  operators independent of the prover, hosts, and external runtime;
- SP1 dependency-security clearance with zero open vulnerabilities and pinned
  policy, lockfile, and advisory-database digests;
- an independently operated external runtime bound to the same ELF, vkey,
  image, journal, admission digest, and release digest; and
- one signed admission/release receipt that closes over the exact content
  digest of every subordinate receipt.

Distinct evidence roles must have distinct content digests even when paths
differ. Host entries are individually self-hashed and signed; host IDs,
operators, keys, hardware fingerprints, and runtime IDs must all be distinct.
Review identities, operators, keys, and typed roles are distinct and separated
from operational authorities. All evidence must fall inside the dossier's
bounded UTC freshness window. Metadata duplication, mixed release/admission
claims, host/operator collapse, digest substitution, mock or non-Groth16 proof
state, stale or future evidence, incomplete reviews, over-limit economics,
v1/cohort substitution, and schema downgrade fail closed.

These signed claims remain useful for assembling and reviewing a future
promotion packet, but signatures are not substitutes for cryptographic proof
verification or chain replay. The current validator therefore returns false
eligibility for every record even when all claims are internally consistent.

Migration is per record but not incremental within a record:

1. Keep the canonical v1 dossier and all v1 activation flags unchanged.
2. Assemble genuine external artifacts outside this source-binding change.
3. Create a v2 overlay only when one record's complete evidence set exists.
4. Keep the claimed flag false and run the validator with the v2 dossier path.
5. Treat success as evidence-packet conformance only. It is not funding,
   deployment, launch authorization, or proof validity.

For a future v2 dossier:

```bash
PYTHONPATH=src:. python3 scripts/verify_production_board_bindings.py \
  --dossier path/to/production-board-bindings-v2.json
```

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

To inspect the v2 protocol schema without asserting that a production v2
dossier exists:

```bash
python3 - <<'PY'
import json
import jsonschema

schema = json.load(open("protocol/production-board-bindings-v2.schema.json"))
jsonschema.Draft202012Validator.check_schema(schema)
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
