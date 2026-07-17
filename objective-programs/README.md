# P42 Objective Programs

This workspace contains the SP1 programs used by the permissionless objective
fraud-proof tier. It is pinned to SP1 `6.1.0` because the deployed Base verifier
gateway and release authority pin that verifier generation.

The artifact-bound program covers `hadamard-668-defect`. Its private witness reconstructs
the exact Solidity hash chain from the committed solution bytes through the
reveal, challenge, pending resolver decision, objective package binding, and
beneficiary-bound journal. It then re-runs the exact integer Hadamard scorer and
commits exactly the 32-byte `P42_OBJECTIVE_VERDICT_JOURNAL_V2` digest.

The workspace also contains an unbound `distinct-subset-sums-a11` guest. It
parses the verifier's finite JSON field set, requires optional metadata to be
Unicode strings, rejects unknown or duplicate root keys, and checks all 2,048
subset sums with checked integer addition. Its production-board guest record
remains deliberately `missing`: the frozen ELF, vkey, mock execution, and
deterministic resource profile are source-side evidence only, not a production
binding or proof. Activation still requires the independent reproduction,
review, audit, authorization, and deployment gates listed below.

The unbound `q6-intersecting-hypergraph` guest ports the complete finite Python
predicate: bounded canonical JSON, 6-uniform distinct edges, every pair
intersecting, and exhaustive depth-5 hitting-set rejection. Its host harness
reconstructs the same objective-correction journal. Two DGX source roots agree
with each other after source-path remapping, and two GitHub x86 images agree
with each other, but the native-ARM and x86 candidate ELFs differ because the
official host-specific SP1 toolchains embed different prebuilt-sysroot paths.
The rejected hosted run retains both x86 bundles as untrusted forensics; it is
not release authority or cross-architecture reproducibility evidence. Q6
remains `guest.status=missing` until a clean hosted gate, a canonical
cross-architecture artifact ceremony, genuine proof vector, independent
review, and production binding are complete.

This source does **not** activate production objective proofs. Ubuntu 22.04 and
24.04 GitHub-hosted x86 runners now reproduce the same frozen ELF and vkey, and
the deterministic resource envelope is machine-checked in
`resource-profile.json`. These are same-operator builds, not independent
hardware attestation. The same runners also compare the unbound A11 and Q6 ELF,
derived vkey, and mock execution across both images before any source binding.
Activation still requires a genuine Groth16 proof and cost benchmark,
independent operator/hardware reproduction, all ten board programs, audit, and
Base Sepolia rehearsal under a new release/gateway/authorization version.

With the SP1 v6.1 toolchain installed:

```bash
cd objective-programs
cargo test -p p42-objective-core
cargo run -p p42-hadamard-668-objective-script -- identity
cargo run -p p42-hadamard-668-objective-script -- execute path/to/witness.json
cargo run -p p42-distinct-subset-sums-a11-objective-script -- execute-fixture \
  ../problems/distinct-subset-sums-a11/tests/conway-guy-594.json
cargo test --locked --manifest-path q6-intersecting-hypergraph/Cargo.toml \
  -p p42-q6-objective-core
cargo run --locked --manifest-path q6-intersecting-hypergraph/Cargo.toml \
  -p p42-q6-objective-script -- execute-fixture \
  ../problems/q6-intersecting-hypergraph/tests/seed-pg25.json
```
