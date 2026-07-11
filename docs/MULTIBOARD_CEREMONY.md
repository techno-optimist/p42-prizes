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
- Per board: `P42BountyPool`, `P42PayoutLedger`,
  `P42SubmissionManager`, and `P42ChallengeManager`.

Ten boards therefore create 42 contracts. Every board receives its own funding
cap, data-availability mode and byte cap, close window, seed score, minimum
improvement, certified objective, source-tree anchor, image anchor, and
admission-matrix digest, durable matrix URI, and derived on-chain matrix
anchor. Global governance and dispute economics are shared only where the
manifest says they are shared.

Registry IDs are not operator-selected. Board array position `n` is required to
use registry ID `n`, and `registerExpected` reverts if an out-of-order timelock
operation tries to register a different ID.

## Typed Input

`P42_DEPLOY_MODE=deploy-multiboard` reads a strict JSON file named by
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

The deployer sends no governance, `armFunding`, or `setAcceptingFunds(true)`
transaction. It emits exactly ten timelock operations per board:

1. Pool-to-ledger wiring.
2. Ledger credit-recorder wiring.
3. Pool-to-submission-manager wiring.
4. Submission-manager-to-challenge-manager wiring.
5. Expected-ID registry registration.
6. Pool-to-registry wiring.
7. Registry freeze.
8. Ledger pause-target authorization.
9. Submission-manager pause-target authorization.
10. Challenge-manager pause-target authorization.

For ten boards this is 100 independently confirmed operations. The only
supported continuation command is `P42_DEPLOY_MODE=continue`. It checks a
finalized block and atomically updates the manifest only after it proves every
runtime hash, owner, governance term, board term, registry pin, registry freeze,
pause target, funding flag, and primary-or-override operation execution.

## Observation

The v2 indexer and Base reconciliation runner select one board explicitly,
replay its child-contract events, and replay the shared registry stream against
that board's state. A v2 checkpoint contains separate state, event digest, and
reconstruction result for every registry ID. Calldata archives are separated by
board ID so repeated submission IDs cannot collide.

No portal, deployment manifest, or donation address may represent a board as
fundable until this complete ceremony, source verification, indexer
reconciliation, and the gate-ledger requirements all exist as current evidence.
The admission preflight is a source-level prevention control, not a substitute
for independently attested hosts, immutable image publication, external math
review, audit, legal approval, or a real testnet rehearsal.
