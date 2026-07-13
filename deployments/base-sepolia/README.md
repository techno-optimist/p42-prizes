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

The production target is the 47-contract, timelock-owned, exact-ten
ceremony in [`docs/MULTIBOARD_CEREMONY.md`](../../docs/MULTIBOARD_CEREMONY.md)
and [`docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md). Do not use the legacy
single-board environment flow as Gate 1 evidence. The current deployer
materializes seven shared roots, including the capsule-attested inactive SP1
gateway, plus forty board contracts. It refuses any topology drift before
nonce reservation or broadcast.

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

The deployed `P42MultisigTimelock` is the immutable owner of every child in the
production path. The deployer must be role-separated from guardian, treasury,
and resolver, and it receives no child ownership.

After deployment, generate a read-only reconciliation report:

Reconciliation requires the completed production manifest, two independently
operated RPCs, the release capsule, a hash-pinned explorer dossier, trusted
explorer-verification operators, and an Etherscan API key. Use the complete
command in [`docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md); a primary-RPC-only
invocation is intentionally rejected.

The default output is
`deployments/base-sepolia/reconciliation/latest.json`. It reconstructs event
counts, funding/claim/credit sums, submission states, challenge states, and
consistency checks from the manifest start block through the latest indexed
block. Gate 1 still requires a real committed report from Base Sepolia and a
production indexer plan for reorg handling, monitoring, and portal reads.
