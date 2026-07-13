# Multi-Board Ceremony

Status: implementation path only. It is not authorization to deploy, fund, or
accept value. The current launch slate is `0/10` fundable boards: every package
still needs a registry-pullable verifier image, trusted host evidence, a fresh
admission matrix, and current launch-witness evidence. The canonical release
bar remains [GATE_LEDGER.md](GATE_LEDGER.md).

## Topology

A v2 ceremony deploys one governance root and one isolated contract stack per
problem:

- One `P42MultisigTimelock`.
- One `P42ProblemRegistry` owned by that timelock.
- One `P42RolloverVault` bound to that registry.
- Per board: `P42BountyPool`, `P42PayoutLedger`,
  `P42SubmissionManager`, and `P42ChallengeManager`.

The canonical topology is six shared contracts plus four contracts per board,
for 46 contracts across ten boards. Every board receives its own funding
cap, data-availability mode and byte cap, close window, seed score, minimum
improvement, certified objective, source-tree anchor, image anchor, and
admission-matrix digest, durable matrix URI, and derived on-chain matrix
anchor. Global governance and dispute economics are shared only where the
manifest says they are shared.

**Current implementation boundary.** The production deployer still constructs
the historical three-shared-plus-forty-board plan. It must fail before reading
the pending nonce, reserving addresses, signing a journal, or broadcasting any
transaction. The canonical guard is intentionally removed only after the two
manager factories, their CREATE2 provenance, and the resolver quorum are all
materialized and every downstream evidence consumer has migrated to 46.

Registry IDs are not operator-selected. Board array position `n` is required to
use registry ID `n`, and `registerExpected` reverts if an out-of-order timelock
operation tries to register a different ID.

## Typed Input

`P42_DEPLOY_MODE=deploy-multiboard-production` reads a strict JSON file named by
`P42_MULTIBOARD_CEREMONY_CONFIG`. Its root shape is:

```json
{
  "schema": "p42-prizes/multi-board-ceremony/v1",
  "governance": {
    "signers": ["0x...", "0x...", "0x..."],
    "threshold": "2",
    "delaySeconds": "172800",
    "guardian": "0x..."
  },
  "roles": { "treasury": "0x...", "resolver": "0x..." },
  "parameters": {
    "alphaBps": "200",
    "betaBps": "500",
    "challengeWindowSeconds": "259200",
    "feeBps": "0",
    "minCounterBondWei": "...",
    "minPostingBondWei": "...",
    "rerunCostMultiplierBps": "30000",
    "rerunCostWei": "...",
    "resolverDecisionBondWei": "...",
    "resolverFraudWindowSeconds": "86400"
  },
  "problems": [
    {
      "fundingCapWei": "...",
      "maxSolutionBytes": "...",
      "earliestCloseTimestamp": "...",
      "closeByTimestamp": "...",
      "specHash": "0x...",
      "problemSlug": "...",
      "verifierVersion": "...",
      "verifierSourceDigest": "sha256:...",
      "verifierSourceHash": "0x...",
      "verifierImageDigest": "sha256:...",
      "verifierImageHash": "0x...",
      "admissionMatrixDigest": "sha256:...",
      "admissionMatrixURI": "ipfs://...",
      "admissionMatrixPath": "release-evidence/<slug>/admission-matrix.json",
      "metadataURI": "ipfs://...",
      "seedScoreAtoms": "...",
      "minImprovementAtoms": "...",
      "onchainDa": true,
      "certifiedObjective": {
        "seedBest": "numerator/denominator",
        "direction": "minimize",
        "minImprovement": "numerator/denominator"
      }
    }
  ]
}
```

All fields are required. The parser rejects unknown fields, noncanonical
phase-0 image placeholders, malformed addresses/hashes, inconsistent global terms, duplicate
slugs, non-exact rational objectives, and score atoms that do not re-derive
from the certified objective. `onchainDa: false` requires `maxSolutionBytes` to
be `"0"`. The local matrix path is deployment input only and is not published
in the manifest; the manifest records its canonical `sha256:` digest, durable
`ipfs://` or `ar://` locator, and
`admissionMatrixHash = keccak256(utf8(admissionMatrixDigest))` instead.

## Execution

The deployer refuses a dirty worktree, reserves the output path before the
first broadcast, and journals each root and board deployment. Before it reserves
the output, it runs `p42-prizes admit-ready` for every board from the clean
release checkout, then checks that the validated matrix's `matrix_hash` equals
the configured digest and that the derived on-chain anchor matches. Set
`P42_ADMISSION_PYTHON` (or the existing `P42_RUNTIME_PYTHON`) to the explicitly
selected Python interpreter when the default `python3` is not the approved
verifier environment. It then writes a
`p42-prizes/deployment-manifest/v2` only after the independent manifest
validator accepts it.

The production slate's `imageRegistry` is the exact canonical
`p42-verifier-image-release/v1` dossier emitted by
`scripts/release_verifier_images.py --publish`, not an operator-authored
projection. Preflight hashes its raw bytes, verifies its canonical
`dossier_hash`, exact source commit and ten-board order, and requires every
board's verifier version, source digest, multi-platform index digest, OCI
labels, immutable reference, and runtime identity to match the ceremony. The
configured `verifierImageDigest` is the published multi-platform
`boards[].index_digest`.

Prepare the closed release set only with the canonical command from
the clean frozen checkout:

```bash
cd contracts
P42_MULTIBOARD_CEREMONY_CONFIG=/absolute/path/ceremony.json \
P42_PRODUCTION_IMAGE_DOSSIER_PATH=../release-evidence/verifier-images.json \
P42_RELEASE_EVIDENCE_ROOT=/absolute/path/release-evidence \
P42_EXPECTED_DEPLOYER_ADDRESS=0x... \
P42_RELEASE_GENERATED_AT=YYYY-MM-DDTHH:MM:SSZ \
P42_RELEASE_OUTPUT_ROOT=/absolute/path/outside-the-repository \
npm run release:prepare
```

The image dossier and all admission matrices must be inside the explicit
evidence root, which is outside the frozen repository because this evidence is
generated after the source commit is fixed. The ceremony config is evidence too
and must be beneath that same root. The output root must be outside
both roots. The command force-compiles the seven production contracts, builds
and independently re-attests the release capsule, derives the exact-ten slate,
runs every real `admit-ready` check, and rechecks the clean commit before and
after publication. Capsule and slate files are mode `0444` and content
addressed. Only the final content-addressed release index declares their pair
complete; a failed second publication can leave an unreferenced immutable
artifact but cannot create a complete release. A failed compile, attestation,
image check, admission check, checkout recheck, or publication produces no
release index.

An independent reviewer verifies the complete release set offline, without a
private key or RPC endpoint, from a separate clean checkout of the exact commit:

```bash
cd contracts
P42_MULTIBOARD_CEREMONY_CONFIG=/absolute/path/release-evidence/ceremony.json \
P42_RELEASE_EVIDENCE_ROOT=/absolute/path/release-evidence \
P42_RELEASE_OUTPUT_ROOT=/absolute/path/release-output \
P42_RELEASE_CAPSULE=/absolute/path/release-output/capsules/<digest>.json \
P42_PRODUCTION_SLATE_PATH=/absolute/path/release-output/slates/<digest>.slate.json \
P42_PRODUCTION_RELEASE_INDEX_PATH=/absolute/path/release-output/releases/<digest>.release.json \
P42_EXPECTED_DEPLOYER_ADDRESS=0x... \
npm run release:verify
```

This force-rebuilds and re-attests the capsule, verifies the final index binds
the exact commit/timestamp/capsule/slate tuple, reruns all ten real
`admit-ready` checks, and emits a
`p42-prizes/production-release-verification/v1` report. The command has no
deployer key, sends no transaction, and does not make an unattested release
fundable. The report self-hashes its complete body and binds the canonical
ceremony configuration digest in addition to every release and matrix digest.

Production deployment consumes all three published artifacts and the same
external evidence root. `P42_PRODUCTION_RELEASE_INDEX_PATH` is mandatory and
must bind the selected `P42_RELEASE_CAPSULE`, `P42_PRODUCTION_SLATE_PATH`, and
clean deployment commit exactly. Selecting an orphan capsule or slate without
its final index fails before broadcast.

```bash
cd contracts
P42_DEPLOY_MODE=deploy-multiboard-production \
P42_MULTIBOARD_CEREMONY_CONFIG=/absolute/path/ceremony.json \
P42_PRODUCTION_SLATE_PATH=/absolute/path/out/slates/<digest>.slate.json \
P42_RELEASE_CAPSULE=/absolute/path/out/capsules/<digest>.json \
P42_PRODUCTION_RELEASE_INDEX_PATH=/absolute/path/out/releases/<digest>.release.json \
P42_RELEASE_EVIDENCE_ROOT=/absolute/path/release-evidence \
P42_RELEASE_OUTPUT_ROOT=/absolute/path/out \
P42_DEPLOYMENT_MANIFEST=/absolute/path/private/p42-prizes.json \
BASE_SEPOLIA_RPC_URL=https://... \
P42_PRIMARY_RPC_OPERATOR_ID=... \
P42_SECONDARY_BASE_SEPOLIA_RPC_URL=https://... \
P42_SECONDARY_RPC_OPERATOR_ID=... \
BASE_SEPOLIA_PRIVATE_KEY=... \
npm run deploy:base-sepolia
```

The deployer sends no governance, `armFunding`, or `setAcceptingFunds(true)`
transaction. It emits exactly eleven timelock operations per board:

1. Pool-to-ledger wiring.
2. Ledger credit-recorder wiring.
3. Pool-to-submission-manager wiring.
4. Submission-manager-to-challenge-manager wiring.
5. Expected-ID registry registration.
6. Pool-to-registry wiring.
7. Ledger-to-rollover-vault wiring.
8. Registry freeze.
9. Ledger pause-target authorization.
10. Submission-manager pause-target authorization.
11. Challenge-manager pause-target authorization.

For ten boards this is 110 independently confirmed operations. The only
supported continuation command is `P42_DEPLOY_MODE=continue`. Production
continuation requires two named, operator-distinct RPCs to agree on canonical
Base Sepolia `finalized`/`safe` tags and OP Stack L1-origin/finality evidence.
It reserves a private governance-operation journal bound to the authenticated
release, deployment-config hash, timelock address/runtime, and complete ordered
operation builders. The continuation process has no governance signer keys and
never schedules or confirms an operation. It only ingests execution evidence at
the agreed finalized block, including a deterministic override fallback, and
persists recovered observations through the same fenced, dead-owner-reclaiming
lock used by the signed deployment journal.
The immutable policy is release evidence, not mutable indexer confirmations.
It rechecks the anchor immediately before atomically updating the manifest only after it proves every
runtime hash, owner, governance term, board term, registry pin, registry freeze,
pause target, funding flag, and primary-or-override operation execution.

## Observation

The v2 indexer and Base reconciliation runner select one board explicitly,
replay its child-contract events, and replay the shared registry stream against
that board's state. A v2 checkpoint contains separate state, event digest, and
reconstruction result for every registry ID. Calldata archives are separated by
board ID so repeated submission IDs cannot collide.

No portal, deployment manifest, reconciliation publication, or donation address may represent a board as
fundable until this complete ceremony, source verification, indexer
reconciliation, and the gate-ledger requirements all exist as current evidence.

Production governance completion also requires the closed explorer-verification
dossier (`schemas/explorer-verification-dossier.schema.json`). It must cover the
46 deployment addresses exactly once in canonical manifest order, bind the
release capsule, compiler input/settings, constructor arguments, and runtime
hashes, and contain fresh response digests from BaseScan's official API and the
independent Sourcify path. Operators load it through a no-follow regular-file
read using `P42_EXPLORER_DOSSIER_PATH`; offline consumers must independently pin
the exact file bytes with `P42_EXPLORER_DOSSIER_SHA256`. A URL, screenshot, or
caller-authored `verified` value is not evidence.

The v2 dossier stores each provider's exact bounded raw bytes and is attested by
two configured verification operators using EIP-712. Completion uses the
finalized block timestamp as the validation instant, rejects any future fetch
time or expiry anomaly, and live re-queries Etherscan V2 plus Sourcify V2 before
the manifest may transition to `governance-setup-complete`.
The admission preflight is a source-level prevention control, not a substitute
for independently attested hosts, immutable image publication, external math
review, audit, legal approval, or a real testnet rehearsal.
