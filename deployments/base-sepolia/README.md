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
P42_PROBLEM_SPEC_HASH=0x... \
P42_VERIFIER_SOURCE_HASH=0x... \
P42_VERIFIER_IMAGE_HASH=0x... \
P42_ADMISSION_MATRIX_HASH=0x... \
P42_METADATA_URI=ipfs://... \
npm run deploy:base-sepolia
```

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
