# Base Sepolia Deployments

This directory is the Gate 1 evidence target for Base Sepolia contract
deployments. A real deployment must commit `p42-prizes.json` with:

- chain id, deploy commit, and deployment timestamp
- role assignments for deployer, owner, treasury, and resolver
- every contract address, constructor arg, deployment tx hash, and block number
- setup tx hashes for ledger/recorder/challenge-manager wiring
- registered problem ids, hashes, metadata URI, component addresses, and register tx
- indexer start block and latest reconciliation report pointer
- source verification status and explorer links

Generate it from `contracts/`:

```bash
BASE_SEPOLIA_RPC_URL=... \
BASE_SEPOLIA_PRIVATE_KEY=... \
P42_TREASURY_ADDRESS=0x... \
P42_RESOLVER_ADDRESS=0x... \
P42_PROBLEM_SLUG=hadamard-mini \
P42_VERIFIER_VERSION=0.1.1 \
P42_PROBLEM_SPEC_HASH=0x... \
P42_VERIFIER_SOURCE_DIGEST=sha256:<64-lowercase-hex> \
P42_VERIFIER_SOURCE_HASH=0x... \
P42_VERIFIER_IMAGE_DIGEST=sha256:<64-lowercase-hex> \
P42_VERIFIER_IMAGE_HASH=0x... \
P42_ADMISSION_MATRIX_HASH=0x... \
P42_METADATA_URI=ipfs://... \
npm run deploy:base-sepolia
```

Fresh ceremonies require `P42_VERIFIER_IMAGE_DIGEST` to be the bare canonical
`sha256:<64 lowercase hex>` digest, not a registry reference, tag, or
`sha256:local-dev` placeholder. `P42_VERIFIER_IMAGE_HASH` must equal
`keccak256(utf8(P42_VERIFIER_IMAGE_DIGEST))`; the fresh manifest records both
values and `verifierImageHashAlgorithm: "keccak256-utf8/v1"`.

`p42-prizes.example.json` is explicitly `example-not-deployed`. Its all-`a`
digest is synthetic and exists only to exercise this anchor relation; it does
not identify a published image or make a problem fundable.

The source anchor is separate: `P42_VERIFIER_SOURCE_DIGEST` is the canonical
`p42-source-tree-sha256/v2` digest of the canonical Dockerfile, `.dockerignore`, root runtime lock, `schemas/`, `src/`, and `problems/<slug>/`, with
`problem.yaml.verifier.image` normalized to its source sentinel. The ceremony
records the problem slug and verifier version, and requires
`P42_VERIFIER_SOURCE_HASH = keccak256(utf8(P42_VERIFIER_SOURCE_DIGEST))`.

Optional parameter overrides include `P42_RESOLVER_DECISION_BOND_WEI` and
`P42_RESOLVER_FRAUD_WINDOW_SECONDS`; the example manifest uses a 24-hour
resolver-bond fraud window.

The deployer is the immutable owner in the current scaffold. Real ETH remains
blocked until the governance/multisig design replaces that testnet shortcut and
the manifest points at verified source plus an indexer reconciliation report.

After deployment, generate a read-only reconciliation report:

```bash
BASE_SEPOLIA_RPC_URL=... npm run reconcile:base-sepolia
```

The default output is
`deployments/base-sepolia/reconciliation/latest.json`. It reconstructs event
counts, funding/claim/credit sums, submission states, challenge states, and
consistency checks from the manifest start block through the latest indexed
block. Gate 1 still requires a real committed report from Base Sepolia and a
production indexer plan for reorg handling, monitoring, and portal reads.
