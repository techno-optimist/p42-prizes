# Bounded Auto-Challenge-Key Policy

Status: Gate 1 operational policy template. This is a fill-in-the-blanks runbook
to be provisioned and funded by a human. Nothing in this document closes a gate.
Every placeholder marked `<...>` is a human action; recording a value here is not
the same as having rehearsed or funded it.

This policy governs the dedicated, bounded testnet key that the DGX
CHRONOS/Hermes verifier runner uses to file bonded challenges against invalid
reveals. It is the money-touching companion to the evidence-only runner
described in `docs/VERIFIER_RUNNER.md` and inherits the wallet/session/API-key/
payload-quarantine posture of `docs/WALLET_SESSION_POLICY.md` (the `challenge`
session-key scope there). Where the two overlap, `WALLET_SESSION_POLICY.md` is
authoritative; this document adds only the auto-challenge envelope.

## Purpose And Scope

- The challenge key exists to convert a runner-flagged invalid reveal into a
  bonded on-chain dispute inside a fixed spend envelope, fast enough to land
  inside the 72-hour challenge window without a human in the transaction loop.
- The key may call **only** `P42ChallengeManager.challenge(submissionId,
  revealInstanceHash, reasonHash)` and `P42ChallengeManager.claimBond()`.
  Nothing else.
- The key **never** holds or moves pool funds, never signs owner/resolver/
  treasury/deployer/solver actions, never posts resolver decisions, never
  finalizes, never claims solver entitlement, and never touches Atlas or any
  prize-state write.
- Runner output (transcripts, alerts, challenge candidates) is **evidence, not
  authority** (`docs/VERIFIER_RUNNER.md`, Trust Boundary). Filing a bonded
  challenge on testnet is an allowed agent-operated product action; writing
  Atlas/prize state is not, and is explicitly out of this key's reach.

## Key Identity And Isolation

| Field | Value | Notes |
| --- | --- | --- |
| Role | `challenge` session scope | Per `docs/WALLET_SESSION_POLICY.md` |
| Address | `<CHALLENGE_KEY_ADDRESS>` | Dedicated EOA/session key; testnet only |
| Chain | Base Sepolia (`84532`) | Bound; must not sign mainnet |
| Bound contract | `<P42ChallengeManager address>` | From `deployments/base-sepolia/p42-prizes.json` |
| Allowed selectors | `challenge(uint256,bytes32,bytes32)`, `claimBond()` | No other selector may be signed |
| Storage | hashed reference only | Same posture as API keys: store `sha256:<hex>` reference, never the raw key, in ops config; never in runner transcripts |

Isolation requirements:

- The address MUST be distinct from the deployer, treasury, resolver signer,
  `creditRecorder`, and any solver key. A single key that can both submit/claim
  and challenge is a policy violation.
- The session key MUST bind to chain id, the `P42ChallengeManager` address, and
  the two allowed selectors, and MUST expire and be revocable
  (`WALLET_SESSION_POLICY.md`, Production Session-Key Target).
- Host secrets, RPC keys, and API keys are scrubbed from the verifier
  subprocess and MUST NOT appear in any transcript that references this key
  (`docs/VERIFIER_RUNNER.md`, Trust Boundary).

## Spend Caps

The bond is sized **on-chain** from the ledger-derived disputed entitlement
(H2): `challenge()` takes no caller-supplied entitlement argument, so the runner
cannot collapse the value-proportional bond to the floor by under-reporting.
The runner must therefore read `requiredChallengeBond` before filing and refuse
if the required bond exceeds the per-challenge cap below.

v1 testnet defaults (consistent with the deploy defaults in
`contracts/scripts/deploy-base-sepolia.js`: `challengeWindowSeconds = 72h`,
`minCounterBondWei = 0.02 ETH`, `resolverDecisionBondWei = 0.005 ETH`,
`feeBps = 0`):

| Cap | v1 default | Rationale |
| --- | --- | --- |
| Per-challenge max bond | `0.05 ETH` | ~2.5x `minCounterBondWei`; absorbs value-proportional sizing while refusing an oversized/exploited entitlement |
| Per-problem per-day cap | `0.10 ETH` | Bounds a single-problem spurious-challenge burst (risk row 9, timing weapon) |
| Global per-day cap | `0.30 ETH` | Aggregate daily ceiling across all problems |
| Max concurrent open challenges | `3` | Contract already enforces one active challenge per submission; this bounds parallel disputes |
| Key funding ceiling | `0.30 ETH` | **Hard backstop.** Only fund the key to the daily global cap. If every other guard fails, the balance is the ceiling on total loss |

Rules:

- `agent/challenge-envelope.mjs` enforces these defaults in a restart-persistent,
  lock-protected v2 ledger. Reservations remain in their original UTC-day
  bucket across rollover; a later finalized receipt converts that same row to a
  spend in the original bucket. State replacement is fsync + same-directory
  rename. Missing reservations and legacy/incomplete state fail closed.
- A reservation and `p42-challenge-action-intent/v1` record are written
  atomically. Any exception before the signed raw-transaction journal is durable
  releases the reservation. Once the signed journal path/hash is durably bound
  to the intent, exceptions preserve the sole pending slot and restart resumes
  that exact journal instead of signing a replacement.
- Envelope locks record PID, random 256-bit token, hostname, process start, and
  lock creation time. Age never authorizes stealing. A lock may be reclaimed
  only when it belongs to this host and `kill(pid, 0)` proves `ESRCH`; foreign,
  live, permission-denied, malformed, or incomplete ownership fails closed.
  Release and reclaim verify the moved token before deletion, so a stale owner
  cannot remove a successor lock.
- Limits come only from the signed, hash-bound immutable
  `p42-challenge-provisioning/v1` artifact. Runtime policy may tighten those
  values, never raise them. There is no public cap-raising operator flag.
- Before startup succeeds and before every admission, the operator reconstructs
  all open challenges for its configured challenge manager from `Challenged`
  logs and contract storage at one finalized block. Missing, stale, future,
  behind-finality, duplicate, or incomplete evidence fails closed. Queue rows
  and local envelope state are never open-cap authority.
- The current wallet stores one exact policy per `(target, selector)`. Therefore
  **at most one challenge exact policy may be provisioned/pending at a time**.
  Three canonical challenges may remain open after their filing policies are
  consumed, but this source does not claim three simultaneous unconsumed exact
  `challenge(...)` policies. Raising that limit requires a wallet contract
  redesign and audit; contracts are intentionally unchanged here.

- If `requiredChallengeBond(disputedEntitlementWei)` > per-challenge max, the
  runner MUST NOT file; it raises an alert for human review instead.
- Reaching any daily cap disables auto-file until the next UTC day; open
  challenges are still pursued to `claimBond()`.
- The funding ceiling is the enforced backstop: the human funds the key to no
  more than the global/day cap so an unbounded misfire cannot exceed it. Refill
  is a deliberate human action, not automatic.

## Trigger Path

The normal path uses the L2 session key. If the sequencer withholds that path,
the autonomous operator may switch to the bounded two-deposit L1 path in
`docs/CENSORSHIP_FALLBACK.md`. That path preserves the wallet as challenger and
the exact one-call policy; it is not an owner bypass. It is source-complete but
must not be represented as operational until the controller alias binding and
full Base Sepolia rehearsal are in the canonical deployment evidence.

1. Reveal observed -> runner re-runs the exact verifier in the pinned sandbox and
   publishes a transcript (`docs/VERIFIER_RUNNER.md`).
2. `p42-prizes runner-alerts` emits a `p42-runner-alerts/v2` bundle. A
   `challenge_submission` / `challenge_or_block_finalize` alert carries
   `agent_action_mode: auto_challenge_candidate`,
   `requires_agent_challenge_key: true`, `requires_spend_cap: true`.
3. Bounded auto-file: the challenge key reads `requiredChallengeBond`, checks it
   against every cap above, reads the `Revealed` event's `revealInstanceHash`,
   re-checks that hash against current chain state, and — if inside the envelope
   — calls `challenge(submissionId, revealInstanceHash, reasonHash)` on-chain
   with `reasonHash` bound to the published transcript evidence. Because of H2,
   no entitlement is passed; the bond is sized on-chain. A stale raw transaction
   therefore reverts rather than attaching to a replacement reveal after a reorg.
4. **Hard boundary:** the candidate is filed on-chain automatically, but **NO
   Atlas/prize-state write happens without explicit user confirmation.** The
   challenge transaction is the only automatic effect. Finalization, resolver
   decisions, credit/frontier writes, and any Atlas mutation remain
   human-confirmed (`AGENTS.md`; `docs/VERIFIER_RUNNER.md`).
5. `quarantine_transcript` alerts (`agent_action_mode: auto_quarantine`,
   `requires_agent_challenge_key: false`) never touch this key.

## Revocation And Kill-Switch

- **Drain:** move the key balance to `<TREASURY/SINK ADDRESS>`. With no funds the
  key cannot file — the funding ceiling doubles as the fastest kill.
- **Rotate:** revoke the session key (expiry/revocation per
  `WALLET_SESSION_POLICY.md`), issue a new bound key, update the hashed
  reference in ops config.
- **Contract pause:** `P42ChallengeManager.setPausedNewActions(true)`
  (owner-only) blocks all new `challenge()` calls protocol-wide; use for a
  systemic incident, not routine revocation.
- **Runner disable:** stop the auto-file loop while leaving the evidence-only
  runner running.
- Who may trigger: the repo/deployer owner (drain, rotate, `setPausedNewActions`)
  and the runner operator (disable auto-file). Any one of them can stop
  auto-challenge unilaterally.
- **Burst/OOM gate:** auto-challenge stays enabled only while the runner health
  gate is green. `p42-prizes runner-burst-validate`
  (`docs/RUNNER_BURST_DRILL.md`) must show `oom_kills = 0`,
  `worker_restarts = 0`, `queue_corruption_events = 0`, and
  `max_active_running = 1`. A tripped memory/swap/host-capacity/concurrency guard
  (`runner-plan` -> `wait`) or any burst-drill regression MUST disable auto-file
  until the runner is healthy again — a degraded runner may emit bad candidates.
  During rollout tooling may still parse v1 outside production. Production
  requires a fresh (at most five minutes old, never future-dated), signed
  `p42-runner-health/v2` artifact at `--runner-health`; missing, stale,
  malformed, `wait`, OOM, restart, corruption, or any absent/non-green explicit
  swap, capacity, or concurrency field disables auto-file fail-closed. The
  configured signer, host/boot/queue identity, chain/contract, canonical block,
  sequence/predecessor, counters, queue hash, headroom algebra, archive health,
  and deadline slack must all validate. The action-intent lock remains held
  through asynchronous preflight and signing. During that interval a helper
  holds the queue's actual `flock`, authorization files are re-read with
  no-follow/private-path checks, and RPC revalidates block hash/time, finality,
  and live critical slack. Signing must occur within five seconds of fence
  acquisition. Production has no v1/false downgrade flag; only isolated
  direct-EOA local-test mode may consume v1. The private challenge envelope
  durably fences root replay, forks, sequence gaps, counter rollback, and signed
  boot transitions before an authorization reaches the signer.
  A reservation persists the exact health sequence/hash that authorized it.
  A newer health generation cannot sign that reservation unless an explicit
  envelope-locked reauthorization atomically advances high-water and rewrites
  the reservation binding first.
  Production also pins a recovery-policy public key distinct from the health
  key. Lifetime incident counters are cleared for admission only relative to a
  separately signed remediation/rehearsal authorization after its cooldown;
  the health producer cannot self-authorize recovery.

## Bond Recovery

`P42ChallengeManager.claimBond()` is an autonomous zero-value action, but it is
still exact-policy gated. `agent/challenge-envelope.mjs` exports the operator
`P42ChallengeManager` lifecycle: verify the session/chain/allowlist and exact
calldata/scope policy, journal signed raw bytes before broadcast, resume the
same transaction after restart, and credit `recovered_wei` only after the
receipt is canonical and final. `recovered_wei` is decoded from exactly one
positive `BondClaimed(claimant, amount)` event emitted by the configured
challenge manager, never from the pre-sign claimable snapshot. A disappeared
or noncanonical receipt becomes `reorged`, including after prior confirmation,
and recovered accounting rolls back to zero. Because `claimBond()` has its own
selector it does not overwrite the one pending `challenge(...)` policy.

Provisioning/rehearsal evidence must validate against
`schemas/challenge-provisioning.schema.json`: exact chain, nonzero challenge
manager/agent-wallet/operator addresses, default caps, health/restart/deep-reorg
rehearsals, rehearsal artifact hash, canonical artifact hash, and an EIP-191
operator signature are all mandatory. Canonical open evidence validates against
`schemas/canonical-open-evidence.schema.json`.
The runtime compiles the published Draft 2020-12 provisioning schema with Ajv
before applying hash, signature, and deployment-binding checks; unknown
top-level/nested properties and type coercion are rejected.

## Transcript And Audit

- Every auto-filed challenge references a published runner transcript
  (command, image digest, payload hash, `VerdictReport` hash, wall time, exit
  status) at `<TRANSCRIPT PUBLICATION LOCATION>`, with `reasonHash` bound to that
  transcript. Transcripts MUST contain no secret material
  (`docs/VERIFIER_RUNNER.md`).
- Reconciliation hook: every auto-filed challenge MUST appear in the Base Sepolia
  reconciliation report at
  `deployments/base-sepolia/reconciliation/latest.json` (the read-only
  `Challenged` / `ResolverTranscriptPosted` / `Resolved` reconstruction from
  `contracts/scripts/reconcile-base-sepolia.js`). A challenge on-chain with no
  matching transcript, or a transcript with no matching reconciliation row, is
  an audit failure and MUST trip the kill-switch.

## Gate 1 Rehearsal Checklist

Maps to the Gate 1 HUMAN_ACTIONS row "Provision the bounded DGX/Hermes agent
challenge-key envelope". Each item is a human action; none is closed by this doc.

- [ ] Challenge key address recorded: `<CHALLENGE_KEY_ADDRESS>` (distinct from
      deployer/treasury/resolver/`creditRecorder`/solver).
- [ ] Funding transaction recorded: `<FUNDING TX HASH>`, funded to <= global/day
      cap (funding ceiling backstop).
- [ ] Spend caps set and enforced: per-challenge, per-problem/day, global/day,
      max concurrent (values above or reviewed overrides).
- [ ] Revocation path rehearsed: drain, rotate, and
      `setPausedNewActions(true)/(false)` all exercised.
- [ ] Transcript publication location recorded: `<TRANSCRIPT LOCATION>`.
- [ ] Queue/OOM thresholds recorded and green: `runner-plan` guard cases +
      `oom_kills/worker_restarts/queue_corruption_events = 0`.
- [ ] Alert routing recorded: `<ALERT ROUTING>` for
      `auto_challenge_candidate` alerts.
- [ ] No-Atlas-write boundary confirmed: auto-file files on-chain only; no
      prize-state write without user confirmation.
- [ ] `p42-prizes runner-burst-validate` rehearsal completed and its report
      committed (`docs/RUNNER_BURST_DRILL.md`).
- [ ] Reconciliation shows every auto-filed challenge
      (`deployments/base-sepolia/reconciliation/latest.json`).
