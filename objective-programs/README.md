# P42 Objective Programs

This workspace contains the SP1 programs used by the permissionless objective
fraud-proof tier. It is pinned to SP1 `6.1.0` because the deployed Base verifier
gateway and release authority pin that verifier generation.

The first program covers `hadamard-668-defect`. Its private witness reconstructs
the exact Solidity hash chain from the committed solution bytes through the
reveal, challenge, pending resolver decision, objective package binding, and
beneficiary-bound journal. It then re-runs the exact integer Hadamard scorer and
commits exactly the 32-byte `P42_OBJECTIVE_VERDICT_JOURNAL_V2` digest.

This source does **not** activate production objective proofs. Ubuntu 22.04 and
24.04 GitHub-hosted x86 runners now reproduce the same frozen ELF and vkey, and
the deterministic resource envelope is machine-checked in
`resource-profile.json`. These are same-operator builds, not independent
hardware attestation. Activation still requires a genuine Groth16 proof and
cost benchmark, independent operator/hardware reproduction, all ten board
programs, audit, and Base Sepolia rehearsal under a new
release/gateway/authorization version.

With the SP1 v6.1 toolchain installed:

```bash
cd objective-programs
cargo test -p p42-objective-core
cargo run -p p42-hadamard-668-objective-script -- identity
cargo run -p p42-hadamard-668-objective-script -- execute path/to/witness.json
```
