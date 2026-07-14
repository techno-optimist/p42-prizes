# OP Stack Forced-Inclusion Challenge Fallback

Status: source implementation, crash-safe autonomous runner, and local tests
complete. Base Sepolia deployment, canonical role binding, and a live
two-deposit rehearsal remain required. This document does not claim Gate 3
closure or authorize real ETH.

## Threat And Invariant

The failure addressed here is a Base sequencer withholding an otherwise valid
`challenge(...)` transaction until the challenge window expires. The fallback
must preserve the same on-chain challenger identity and must not turn the wallet
owner into an arbitrary-call bypass.

The invariant is:

> Whether submitted through the session key or forced through L1, a challenge
> is sent by the same `P42AgentWallet` and is bounded by the same exact calldata
> hash, one-call policy, chain id, expiry, per-call cap, and cumulative spend cap.

## Components

- `P42AgentWallet.executeForcedPolicy(...)` is payable and restricted to a
  one-time configured `forcedInclusionOwner`, separate from wallet governance.
  Unlike the session path, it remains available after session expiry or
  revocation. It requires an exact policy for every call, requires
  `msg.value == value`, and shares policy consumption and spend accounting with
  session execution.
- `P42ForcedInclusionController` is deployed on L1. Its OP Stack L2 address
  alias is the wallet's forced-inclusion role. The controller has immutable portal, wallet,
  challenge-manager, and challenge-selector bindings. It can only install an
  exact one-call challenge policy and submit that exact selector; it cannot
  withdraw, rotate wallet policy generally, or target another contract.
- `agent/censorship-fallback.mjs` computes the alias, checks the deployment
  binding and deadline budget, and emits two ordered L1 controller calls. The
  operator never calls the portal directly; doing so would produce the wrong L2
  sender identity.
- `agent/censorship-fallback-runtime.mjs` and the
  `p42-censorship-fallback` command implement the autonomous run. The journal
  persists exact signed L1 bytes before broadcast, resumes those bytes after a
  crash, requires credential-free HTTPS RPCs on distinct hosts for each chain,
  and advances only on
  finalized exact storage plus an L2 event whose top-level transaction came
  from the controller alias and targeted the wallet. The type-`0x7e` deposit's
  OP Stack `sourceHash` must derive from the exact finalized portal log in the
  journaled L1 receipt; an older byte-identical deposit is not accepted.
- Every run requires an independently signed execution authorization binding
  the exact plan, controller path, operator, chain, expiry, maximum bond,
  portal gas, L1 gas, EIP-1559 fees, both transactions' worst-case total L1
  fee, finalized-head lag, and bounded L2 scan span/result count. The approver
  must differ from the hot operator. The authorization digest is immutable
  journal identity.

OP Stack deposits carry target, value, gas, and calldata to L2. When the L1
sender is a contract, the L2 sender is its aliased address. These semantics and
the modulo-160 alias rule are pinned to the official
[`deposits` specification](https://github.com/ethereum-optimism/specs/blob/fefdc5945cbc439c09550972bd409df29db4aaf9/specs/protocol/deposits.md).
The sequencing window is a chain-configured parameter; the planner defaults to
3,600 L1 blocks only as the current specification default and requires the
canonical deployment packet to pin the live value. See the official
[`configurability` specification](https://github.com/ethereum-optimism/specs/blob/fefdc5945cbc439c09550972bd409df29db4aaf9/specs/protocol/configurability.md).

## Deployment Order

1. Deploy and verify `P42ForcedInclusionController` on the selected L1 with the
   canonical Optimism Portal, intended L2 wallet address, challenge manager,
   exact `challenge(...)` selector, bounded operator, and recovery guardian.
2. Record the controller runtime code hash and compute its L2 alias using
   `applyL1ToL2Alias`.
3. Deploy `P42AgentWallet` on Base with the intended governance owner, then use
   that owner to set the controller alias as `forcedInclusionOwner`. This role
   can be set only once.
4. Verify on-chain that controller code hash, portal, wallet, manager, selector,
   operator, guardian, governance owner, and forced-inclusion role match the
   signed deployment packet.
5. Fund the L1 operator only to the approved challenge envelope. The operator
   is autonomous in routine operation; guardian rotation is emergency recovery,
   not part of challenge admission.

Binding the forced-inclusion role before the controller identity is fixed is
invalid. An EOA as controller is invalid because OP Stack contract-address
aliasing would not provide the required role identity and constrained forwarding
surface.

## Two-Deposit State Machine

1. The verifier runner produces exact challenge calldata and its transcript-
   bound scope hash. The planner verifies controller code identity, aliased
   forced-role binding, policy expiry, and deadline slack.
2. The L1 operator calls `depositChallengePolicy`. The controller deposits a
   call to `P42AgentWallet.setForcedCallPolicy` with immutable manager/selector,
   `maxCalls = 1`, exact calldata hash, chain id, expiry, and scope hash.
3. The operator waits for that deposit's canonical L2 receipt and verifies the
   emitted `CallPolicySet` fields and alias-origin transaction. Submitting or
   signing the second deposit before this finalized evidence is forbidden.
4. The L1 operator calls `depositChallenge` with exactly the required bond. The
   controller deposits a call to `executeForcedPolicy`, carrying the same bond as
   both portal value and wallet-forwarded value.
5. The operator verifies finalized `Challenged` evidence with challenger equal
   to the wallet and top-level transaction sender equal to the controller alias.
   Restart logic resumes the same signed L1 transaction; it never signs a
   replacement without reconciling both chains.

The nine journal stages are monotonic: `planned`, policy signed/broadcast/L1
final/L2 confirmed, then challenge signed/broadcast/L1 final/L2 confirmed. The
L2 observation start block, plan hash, both chain IDs, controller, and operator
are immutable journal identity. The shared chain-plus-operator nonce allocator
and lock are the same on-disk coordination contract used by the ordinary
challenge operator, so separate boards cannot sign different transactions at
one nonce. The gas limit and EIP-1559 fee ceilings are
normalized and hash-bound to the same journal, so a restart cannot loosen phase
two economics. Conflicting policy consumption, policy
replacement, challenge-slot occupation, RPC disagreement, reorged receipts,
or signer nonce conflict fails closed. Before phase-two signing the exact
finalized policy is observed again. A completed journal revalidates both L1
receipts plus both exact source-bound L2 transaction/receipt/event anchors. It
uses the persisted timing fields to recompute the historical challenge-instance
hash, so later legitimate challenge-slot mutation does not erase completion.

The challenge remains attributable to the wallet because the wallet, not the
controller alias or operator, calls `P42ChallengeManager`. Bond claims therefore
remain on the existing wallet lifecycle.

## Deadline Budget

The policy uses two sequential L1 deposits because execution must not race
ahead of policy installation. The fail-closed lower bound is:

```text
required_remaining = 2 * sequencing_window_l1_blocks * l1_block_seconds
                   + l1_confirmation_and_reorg_safety_seconds
```

With the planner defaults this is `2 * 3600 * 12 + 21600 = 108000` seconds,
or 30 hours. A 72-hour challenge window leaves operational margin. The plan
records the live deployment parameters, the runtime recomputes this arithmetic,
and the independent authorization signs the resulting plan. Both RPC latest
heads must stay within the configured lag bound; the newer timestamp is used
conservatively for every fallback. If the bound is not met, it alerts and refuses to manufacture a claim
of timely inclusion.

After the exact policy is finalized on L2, only one deposit remains, so the
fresh-signing bound becomes `sequencing_window_l1_blocks * l1_block_seconds +
safety`, or 18 hours with the defaults. Existing signed bytes continue through
reconciliation even if fresh-signing slack later expires; the runner never
abandons an already broadcast transaction to create a replacement.

## Failure Modes And Evidence

- A paused or broken portal, prolonged L1 failure, or an incorrect chain
  configuration can still defeat forced inclusion. This is not a bridge-proof
  or L1-liveness proof.
- Under-gassed deposits can fail on L2. Gas limits are deployment parameters and
  require measured Base Sepolia rehearsal with margin.
- The controller operator can file a false challenge using its own supplied
  bond or overwrite a pending challenge policy. It cannot spend pre-existing
  wallet ETH through this path because forced execution requires the deposit
  value to equal the forwarded value. Operator funding and the existing daily
  challenge envelope bound this residual grief risk.
- Guardian compromise can rotate the L1 operator. It cannot change immutable
  portal, wallet, manager, or selector bindings. Guardian custody remains a
  deployment and external-review gate.
- A live rehearsal must retain both L1 transaction hashes, L1 and L2 block
  hashes, deposit identifiers, wallet policy event, challenge event, code
  hashes, chain configuration, deadline calculation, gas used, and finality
  observations. Local mocks are not substitute evidence.

## Independent Terminal Verification

`p42-censorship-fallback-verify` revalidates a completed journal without the
operator private key. The observer supplies the expected operator address, the
frozen plan and authorization, the exact execution policy, and two independent
RPCs per chain. The command rechecks controller/wallet bindings, both finalized
L1 receipts, both canonical L2 anchors, each source-bound type-`0x7e` deposit,
and the exact policy/challenge events. Its content-addressed
`p42-censorship-fallback-terminal-verification/v1` output binds the journal and
all chain anchors while explicitly setting `sequencerCensorshipClaimed=false`
and `gate3Closed=false`.

The verifier accepts a release/deployment/chain-bound verification policy only
when its canonical hash exactly matches
`/etc/p42/censorship-fallback-verification-policy.sha256`. Provision that file
as a single `sha256:<64 lowercase hex>` line owned by root, with no write bits
and one hard link, beneath a root-owned `/etc/p42` directory that is not group-
or world-writable. The observer account must not be able to replace either the
directory or digest. The policy pins both chain genesis hashes and post-release
checkpoints, so matching chain IDs on a private fork are insufficient.

This technical verification is an input to the signed rehearsal dossier. It is
not release provenance, external review, or evidence that censorship actually
occurred.

## Supervisor Contract

`p42-censorship-fallback` performs one monotonic step. It emits exactly one
`p42-censorship-fallback-outcome/v1` JSON result. `complete` exits `0`, ordinary
pending progress emits `retry` and exits `75`, retryable RPC failures also exit
`75`, and invariant/configuration refusal emits `terminal-error` and exits
`64`. `p42-censorship-fallback-supervisor` runs each monotonic step with a
two-minute timeout, validates the child's fully drained bounded canonical retry
or completion outcome, waits 15
seconds after expected exit `75`, and continues without consuming systemd's
crash budget. A malformed retry fails immediately; after eight canonical
`rpc-unavailable` retries, a ninth consecutive failure exhausts the supervisor.
Expected finalized-chain
waiting resets that RPC-failure counter. Unexpected exit or child timeout maps
to supervisor exit `70`, while service `SIGTERM` is forwarded with a ten-second
kill grace and exits cleanly. `deployments/p42-censorship-fallback.service.example`
then applies an explicit six-start/20-minute manager-activation ceiling sized
above six worst-case 145-second failure cycles,
`RestartMode=direct`, and `RestartPreventExitStatus=64` before one terminal
`OnFailure` alert through the shipped
`p42-censorship-fallback-alert@.service.example` unit. The alert helper reads
the manager's exact result/code/status and durably creates a hash-bound mode-0600
record. It runs as a separate `p42-fallback-alert` account whose systemd state
directory is not writable by the fallback runtime account. `systemd-analyze
verify` statically parses both units in CI. The runtime unit creates and
uses fixed private `state/` and `coordination/` descendants of
`/var/lib/p42-censorship-fallback`; systemd does not expand environment
variables in `ReadWritePaths`. The mode-`0600` environment file must be readable only by the
dedicated fallback service account; RPC credentials belong behind local
credential-bearing HTTPS proxies because the command accepts only
credential-free root URLs.

Before enabling the units, install
`deployments/p42-censorship-fallback.sysusers.example` as
`/etc/sysusers.d/p42-censorship-fallback.conf` and run
`systemd-sysusers /etc/sysusers.d/p42-censorship-fallback.conf`. This provisions
the separate `p42-fallback` and `p42-fallback-alert` system accounts; unit
startup must fail rather than collapsing them into one identity.
The host must run systemd 254 or newer because `RestartMode=direct` is required
to suppress intermediate `OnFailure` activation while a restart remains
eligible. Treat an unknown `RestartMode` warning as a deployment failure.

## Test Evidence

- `contracts/test/p42-forced-inclusion-controller.test.js`: immutable routing,
  exact policy encoding, exact bond forwarding, caller/selector/value rejection,
  and guardian-only operator rotation.
- `contracts/test/p42-governance-v2.test.js`: forced-role fallback after session
  revocation, one-time role binding, exact calldata, one-call exhaustion,
  role-only access, and value binding.
- `agent/censorship-fallback.test.mjs`: modulo-160 aliasing, both controller calls,
  controller-code requirement, role binding, and two-window deadline refusal.
- `agent/censorship-fallback-runtime.test.mjs`: signed-before-broadcast
  durability, same-byte restart, strict phase order, journal tamper rejection,
  recomputed deadline refusal, stale-head rejection, signed cap enforcement,
  wallet-wide nonce separation, immediate phase-two policy revalidation,
  dual-RPC finalized state, formula-recomputed challenge-instance binding,
  bounded evidence scans, HTTPS endpoint separation, and exact L1-source-bound
  alias-origin event provenance.
- `agent/censorship-fallback-alert.test.mjs` plus
  `scripts/verify-censorship-fallback-systemd.sh`: exclusive hash-bound alert
  creation, separated writable roots, bounded step/retry directives, and
  static unit parsing.
- `scripts/run-censorship-fallback-systemd-drill.sh` and
  `deployments/dgx-supervisor-drill/2026-07-14/report.json`: a root-managed,
  disposable systemd 255 drill on CHRONOS using the shipped supervisor and
  alert helper. Canonical pending progress completed after three child steps
  with zero manager restarts; terminal exit `64` produced one alert and no
  restart; malformed `75`, malformed `0`, timeout, and crash each stopped after
  six child invocations with one post-exhaustion alert; service `SIGTERM`
  completed cleanly both during a child step and during the supervisor's retry
  delay; and the runtime account could not write the alert state
  root. The drill ran from clean source commit
  `88f306abdfaa5c281cfdbc7379ba8694cc2bd6c1`; report hash:
  `sha256:e827a69d3f241530eb5e7237f0293629673ed4c3422f95842df22537fb661579`.
  This closes only the local manager-semantics subgate. The ephemeral accounts,
  shortened timings, and fixture child do not attest the canonical deployment,
  a signed deposit, reorg recovery, or external review.

Gate 3 remains open until an externally reviewed release is deployed and the
signed Base Sepolia rehearsal evidence above passes canonical reconciliation.
