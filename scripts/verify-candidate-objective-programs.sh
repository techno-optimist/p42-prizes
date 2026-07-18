#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
programs="$root/objective-programs"
audit="$(mktemp -d "${TMPDIR:-/tmp}/p42-candidate-objectives.XXXXXX")"
trap 'rm -rf "$audit"' EXIT

cd "$programs"

cargo test --locked \
  --manifest-path q6-intersecting-hypergraph/Cargo.toml \
  -p p42-q6-objective-core
cargo test --locked \
  --manifest-path edges-vs-triangles/Cargo.toml \
  -p p42-edges-objective-core
cargo test --locked \
  --manifest-path arithmetic-kakeya/Cargo.toml \
  -p p42-arithmetic-kakeya-objective-core
cargo test --locked \
  --manifest-path erdos-min-overlap/Cargo.toml \
  -p p42-three-objective-shared \
  -p p42-erdos-min-overlap-objective-core
cargo test --locked \
  --manifest-path autoconvolution-c1-upper/Cargo.toml \
  -p p42-autoconvolution-c1-upper-objective-core
cargo test --locked \
  --manifest-path autoconvolution-c2-lower/Cargo.toml \
  -p p42-autoconvolution-c2-lower-objective-core

cargo build --locked \
  --manifest-path q6-intersecting-hypergraph/Cargo.toml \
  -p p42-q6-objective-script
cargo build --locked \
  --manifest-path edges-vs-triangles/Cargo.toml \
  -p p42-edges-objective-script
cargo build --locked \
  --manifest-path arithmetic-kakeya/Cargo.toml \
  -p p42-arithmetic-kakeya-objective-script

q6_elf="q6-intersecting-hypergraph/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/p42-q6-objective-program"
edges_elf="edges-vs-triangles/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/p42-edges-objective-program"
arithmetic_kakeya_elf="arithmetic-kakeya/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/p42-arithmetic-kakeya-objective-program"
test -f "$q6_elf" && test ! -L "$q6_elf"
test -f "$edges_elf" && test ! -L "$edges_elf"
test -f "$arithmetic_kakeya_elf" && test ! -L "$arithmetic_kakeya_elf"

cargo run --locked \
  --manifest-path arithmetic-kakeya/Cargo.toml \
  -p p42-arithmetic-kakeya-objective-script -- \
  identity-elf "$arithmetic_kakeya_elf" > "$audit/arithmetic-kakeya-identity.json"
cargo run --locked \
  --manifest-path arithmetic-kakeya/Cargo.toml \
  -p p42-arithmetic-kakeya-objective-script -- \
  execute-fixture-elf "$arithmetic_kakeya_elf" \
  "$root/problems/arithmetic-kakeya/examples/kt-2x2-forcing.json" \
  > "$audit/arithmetic-kakeya-execution.json"

mkdir "$audit/q6" "$audit/edges"
cp "$q6_elf" "$audit/q6/program.elf"
cargo run --locked \
  --manifest-path q6-intersecting-hypergraph/Cargo.toml \
  -p p42-q6-objective-script -- \
  identity-elf "$q6_elf" > "$audit/q6/identity.json"
cargo run --locked \
  --manifest-path q6-intersecting-hypergraph/Cargo.toml \
  -p p42-q6-objective-script -- \
  execute-fixture-elf "$q6_elf" \
  "$root/problems/q6-intersecting-hypergraph/tests/seed-pg25.json" \
  > "$audit/q6/execution.json"
python3 "$root/scripts/verify-sp1-objective-reproduction.py" \
  --program q6-intersecting-hypergraph \
  --directory "$audit/q6" \
  --write-source-manifest

cp "$edges_elf" "$audit/edges/program.elf"
cargo run --locked \
  --manifest-path edges-vs-triangles/Cargo.toml \
  -p p42-edges-objective-script -- \
  identity-elf "$edges_elf" > "$audit/edges/identity.json"
cargo run --locked \
  --manifest-path edges-vs-triangles/Cargo.toml \
  -p p42-edges-objective-script -- \
  execute-fixture-elf "$edges_elf" \
  "$root/problems/edges-vs-triangles/examples/rational-curve-sample.json" \
  > "$audit/edges/execution.json"
cargo run --locked \
  --manifest-path edges-vs-triangles/Cargo.toml \
  -p p42-edges-objective-script -- \
  execute-fixture-elf "$edges_elf" \
  edges-vs-triangles/fixtures/worst-case-500-rows.json \
  > "$audit/edges/resource.json"
python3 "$root/scripts/verify-sp1-objective-reproduction.py" \
  --program edges-vs-triangles \
  --directory "$audit/edges" \
  --write-source-manifest
