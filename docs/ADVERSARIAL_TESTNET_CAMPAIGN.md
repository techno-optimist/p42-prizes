# Adversarial Testnet Campaign Evidence

Gate 1 is not green until the exact deployed Base Sepolia release survives an
independently reviewed red-team campaign. A schema-valid declaration is not
enough: the validator resolves every artifact, verifies its SHA-256 digest,
checks release files against the bound Git commit, and cross-checks captured
`eth_getCode` results against contract addresses and runtime-bytecode hashes.

No production signer is registered in this repository. The gate remains open
until the owner provisions a production trust registry and genuine evidence.

## Validation Command

```bash
PYTHONPATH=src python3 -m p42_prizes.cli adversarial-campaign-validate \
  --report deployments/base-sepolia/adversarial-campaign.json \
  --trust-registry /owner-controlled/p42-attestation-trust-registry.json \
  --artifact-root /frozen/p42-prizes \
  --chain-rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --output deployments/base-sepolia/adversarial-campaign.normalized.json
```

`--artifact-root` must be the local checkout whose `remote.origin.url` and Git
object match `release_binding.repository_uri` and `git_commit`. Test registries
are rejected unless `--allow-test-trust-registry` is explicitly passed; that
flag is for local tests and cannot close Gate 1.

`--chain-rpc-url` is queried for `eth_chainId`, `eth_getBlockByNumber`, and
`eth_getCode` at each recorded evidence block. Captured chain evidence fails if
it differs from the queried block hash or bytecode.

The trust registry is supplied out of band from the campaign report. Each
registration binds `p42-adversarial-testnet/v1`, a reviewer role, the reviewer's
name/organization/professional email, Ed25519 public key, and validity window.
A signature by a key invented inside the campaign packet is rejected.

## Resolved Artifact Shape

Every artifact field uses this object:

```json
{
  "uri": "repo://deployments/base-sepolia/reconciliation/latest.json",
  "local_path": "deployments/base-sepolia/reconciliation/latest.json",
  "sha256": "sha256:<REAL-64-LOWERCASE-HEX>",
  "created_at_utc": "<STRICT-RFC3339-DATE-TIME-WITH-TIMEZONE>"
}
```

`local_path` must stay inside `--artifact-root`, exist as a regular file, and
hash to `sha256`. URI/digest declarations without locally resolved bytes fail.
All evidence `created_at_utc` values and attack/regression execution times must
precede the final reviewer signatures.

### Signed runner evidence

`transcript_archive` is not an opaque attachment. Its resolved bytes must be
canonical strict JSON conforming to
`p42-runner-transcript-archive/v1`. The archive binds the campaign ID, a
canonical hash of the complete release binding, a pre-registered
`runner-operator`, normalized relative transcript paths, unique job IDs,
canonical transcript self-hashes, and an Ed25519 signature over the canonical
archive hash. Reusing the same contract addresses does not make evidence
portable across commits, configuration, or runtime bytecode. Transcript and
archive timestamps must be ordered
inside the campaign window. Every transcript must carry the runner-derived
chain claim and self-hashed challenge candidate. Their chain ID, submission and
challenge contract addresses, submission identity, reveal hash, and challenge
deadline must agree with each other; the chain and contract addresses must also
match the exact release binding under review.

`runner_alert_bundle` is likewise recomputed, not trusted. Validation rebuilds
the exact `p42-runner-alerts/v2` bundle from the signed archive and rejects any
missing, inserted, reordered, or rewritten alert. The rebuilt bundle must flag
the exact planted verifier artifact and the exact planted DA artifact recorded
by their attack rows. An unrelated rejection cannot satisfy either attack.
The bundle generation timestamp is evidence too, so final reviewers cannot
sign before the alert computation they attest to.

A failed verifier execution without an independently derived
`challenge_candidate.action == "challenge"` is quarantined even if it emitted
parseable bytes and a report hash. A report hash alone never authorizes an
agent to spend the challenge key.

## Exact Release Binding

`release_binding` contains the HTTPS repository URI, exact 40-character Git
commit, network/chain ID, resolved deployment manifest, resolved configuration
artifact, and exactly five required contracts. The deployment manifest,
configuration artifact, and each source artifact must equal the bytes stored at
the bound commit.

Each contract contains:

- `name`, deployed `address`, and `runtime_bytecode_hash`.
- `source_artifact`, resolved from the bound Git commit.
- `runtime_bytecode_artifact`, containing non-empty `0x` EVM bytecode whose
  decoded bytes hash to `runtime_bytecode_hash`.
- `chain_bytecode_artifact`, a resolved captured `eth_getCode` JSON-RPC result
  with network, chain ID, address, block number/hash, and returned bytecode.

The captured chain result must exactly match the resolved runtime bytecode.

## Required Attacks

The campaign must contain each attack exactly once with `status: "passed"`, a
strict `executed_at_utc`, resolved `planted_artifact`, expected failure mode,
observed defense, and resolved `evidence_artifact`:

- `vesting_dilution_overpay`
- `empty_pool_bond_leverage`
- `leapfrog_sybil_split`
- `da_expiry_or_missing_payload`
- `resolver_false_transcript`
- `verifier_planted_exploit`

The report must also set all current invariants to true:

- `claim_capped_by_final_entitlement`
- `bond_uses_pool_at_submission`
- `da_bound_at_commit_and_finalize`
- `resolver_transcript_required`
- `invalid_verifier_alerted`
- `sybil_split_not_profitable`
- `reconciliation_ok`

Every regression requires `command`, `status: "passed"`, `executed_at_utc`, and
a resolved `output_artifact`. Open critical/high followups are rejected.

## Review And Signature Rules

Reviewers use the roles `external-auditor`, `engineering-owner`, optional
`ops-reviewer`, or optional `resolver-reviewer`. External auditor and
engineering owner are mandatory, must be distinct people with distinct keys,
and must belong to different organizations. The external auditor also supplies
an engagement identifier and resolved engagement artifact.

Each listed reviewer signs the canonical unsigned `campaign_hash` with its
pre-registered Ed25519 key. An attestation contains `algorithm`, `signer_role`,
`public_key`, `signed_hash`, `signed_at_utc`, and `signature`. The signature
time must match the reviewer's recorded signoff time, occur after all campaign
execution/evidence creation, and occur no later than campaign completion.

## Deliberately Invalid Template

The following is a field guide, not acceptable evidence. It deliberately uses
placeholders and omits five required attacks, contract entries, and signatures
so it cannot accidentally green-light Gate 1.

```json
{
  "schema_version": "p42-adversarial-testnet/v1",
  "campaign_id": "<REAL-CAMPAIGN-ID>",
  "started_at_utc": "<RFC3339>",
  "completed_at_utc": "<RFC3339>",
  "environment": "base-sepolia",
  "release_binding": {
    "repository_uri": "https://github.com/techno-optimist/p42-prizes",
    "git_commit": "<EXACT-COMMIT>",
    "network": "base-sepolia",
    "chain_id": 84532,
    "deployment_manifest": "<RESOLVED-ARTIFACT-OBJECT>",
    "configuration_artifact": "<RESOLVED-ARTIFACT-OBJECT>",
    "contracts": []
  },
  "deployment_manifest": "<SAME-RESOLVED-ARTIFACT-OBJECT>",
  "reconciliation_report": "<RESOLVED-ARTIFACT-OBJECT>",
  "runner_alert_bundle": "<RESOLVED-ARTIFACT-OBJECT>",
  "transcript_archive": "<RESOLVED-ARTIFACT-OBJECT>",
  "reviewers": [],
  "invariants_checked": {},
  "attacks": [
    {
      "attack_id": "vesting_dilution_overpay",
      "status": "passed",
      "executed_at_utc": "<RFC3339>",
      "planted_artifact": "<RESOLVED-ARTIFACT-OBJECT>",
      "expected_failure_mode": "<OBSERVABLE-EXPECTATION>",
      "observed_defense": "<OBSERVED-RESULT>",
      "evidence_artifact": "<RESOLVED-ARTIFACT-OBJECT>"
    }
  ],
  "regressions": [],
  "open_followups": [],
  "attestations": []
}
```

A `local-rehearsal` report can test the process. Gate 1 still requires a real
Base Sepolia deployment, all required evidence, and trusted independent review.
