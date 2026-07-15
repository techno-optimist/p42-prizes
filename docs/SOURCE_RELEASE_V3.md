# Source-release evidence v3 foundation

Status: implemented as a fail-closed foundation; not activated and not a current production receipt.

## Security boundary

V3 separates three authorities that v2 allowed the target repository to describe for itself:

1. `/etc/p42/source-release-trust-root.json` is a root-owned, non-group/world-writable local root read with `O_NOFOLLOW` and stable file-identity checks. It pins the equally protected policy path and digest plus the only allowed bootstrap artifacts. Production current validation accepts no caller policy, digest, report path, or offline override.
2. The threshold-signed policy pins the repository, branch, activation commit, canonical Render service, exact workflow bytes, closure algorithm `p42-git-ls-tree-closure/v1`, stable closure roots (`["."]`), exact six-job set, genesis receipt, deploy/evidence path policies, independent reviewers, and direct 12-probe semantics. Authority IDs and decoded Ed25519 public keys must both be unique.
3. The receipt chain is recursively loaded from committed Git bytes until it reaches the policy-pinned genesis. Each link must be the latest canonical receipt before the next receipt's publication commit; every receipt hash, schema, canonical path, publication commit, observed head, and publication transition must lie on first-parent `main` history.
4. Online validation authenticates remote `main` before applying the activation/downgrade rule, then authenticates the exact GitHub run attempt/jobs, merged PR and PR-head tree, allowlisted non-author approvals at that exact head, canonical Render deployment, and evidence-only publication tail. It pins and executes the committed 12-probe guard plus its board manifest, compares the guard's exported routes to the signed policy, and independently binds marker/API/final-URL/equivalence observations.

The commands are deliberately distinct. `source-release-evidence-validate` preserves historical v2 archive validation. `source-release-current-validate` always loads the canonical committed receipt and protected local root, authenticates remote `main`, and fails closed on every operational error. Once authenticated remote `main` descends from `activationCommit`, v2 is rejected.

## Direct pushes and bootstrap

A deploy-relevant first-parent commit must have exactly matching merged-PR coverage. A direct push fails current validation even when a later evidence PR tries to mask it.

The only exception is an explicit `p42-source-release-bootstrap-ratification/v1` artifact. It binds the full policy digest, authorization ID, expiry, and a closed contiguous interval: covered commits, first parent, final tree, and aggregate changed-path digest. The protected root must allowlist its exact digest/path/expiry, and it must meet the policy threshold with valid Ed25519 signatures. There is no unsigned, caller-supplied, or repository-local bypass.

Bootstrap ratification is for a disclosed migration interval only. It does not make an unreviewed direct push retrospectively PR-reviewed.

## Receipt fields added in v3

- `previousEvidence`: publication commit, repository-relative path, observed head, deploy commit, and canonical receipt hash.
- `trustPolicy`: external policy ID and hash.
- `ci`: workflow ID, path, raw-blob SHA-256, Git blob OID, closure algorithm/roots, immutable external refs, and run attempt in addition to the v2 run identity. Each receipt enumerates every Git entry under the policy roots at its own observed head and binds the ordered manifest with SHA-256. The policy does not pin that per-release digest, so a later source tree can produce new complete evidence without changing the closure rules.
- `deployProvenance`: predecessor baseline and an ordered, complete list of derived deploy commits with first parent, tree, changed-path digest, and PR or bootstrap authorization.
- `render.serviceId`: fixed to `srv-d96pokeq1p3s73foqk60` by both schema and external policy.
- `releaseGuard`: exactly 12 observations, adding paired `/prizes/intro` probes while retaining the historical v2 10-probe archive contract. The asserted command is the policy-pinned committed `node scripts/verify-render-release.mjs`, not an unbound command label.

## Activation ceremony

Activation is intentionally incomplete. The owner/release authorities must:

1. Provision independent Ed25519 custody for at least three release authorities and approve a threshold of at least two.
2. Review and sign one immutable external `p42-source-release-policy/v1` artifact. It must contain the final activation commit, genesis receipt, exact workflow identity, closure algorithm/roots, reviewer allowlist, and direct guard semantics.
3. Independently review the direct deploy commits in the migration interval. Either leave the production gate red or threshold-sign exact bootstrap ratifications; do not label those commits PR-reviewed.
4. Install the root, policy, and ratifications as protected local files outside the target checkout. Configure rotation/revocation and independently archive the signed bytes.
5. Obtain a complete policy-pinned six-lane `main` run using the merged paired intro guard, observe the canonical Render deployment, and publish the first v3 receipt in a later evidence-only PR.
6. Invoke `p42-prizes source-release-current-validate` from the independently installed release auditor. The historical archive command remains separate.

Until all six steps are evidenced, v3 current release authority is unavailable by design.

## Residual external blockers

- No threshold-signed external trust policy or protected `/etc/p42/source-release-trust-root.json` installation exists.
- No release-authority keys or custody/rotation/revocation procedure has been provisioned.
- The existing direct deploy commits have no PR provenance and no protected-root-allowlisted, unexpired bootstrap ratification binding their exact closed interval.
- The 12-probe release-guard source is now on remote `main`, but the canonical current receipt still records the historical 10-probe v2 run; no policy-pinned 12-probe current evidence exists.
- No complete successful policy-pinned `main` run exists at an activation head.
- No first v3 receipt exists; `docs/evidence/source-release-current.json` remains v2 and must not be represented as v3.
- Repository ruleset/branch-protection and private-vulnerability-reporting account gates remain external owner actions.
