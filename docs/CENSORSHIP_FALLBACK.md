# OP Stack Forced-Inclusion Challenge Fallback

Status: source implementation and local tests complete. Base Sepolia deployment,
canonical owner binding, and a live two-deposit rehearsal remain required. This
document does not claim Gate 3 closure or authorize real ETH.

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
   emitted `CallPolicySet` fields. Submitting the second deposit before this
   receipt is forbidden.
4. The L1 operator calls `depositChallenge` with exactly the required bond. The
   controller deposits a call to `executeForcedPolicy`, carrying the same bond as
   both portal value and wallet-forwarded value.
5. The operator verifies canonical `Challenged` evidence with challenger equal
   to the wallet, then reconciles policy consumption and `spentWei`. Restart
   logic resumes the same signed L1 transaction; it never signs a replacement
   without reconciling both chains.

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
or 30 hours. A 72-hour challenge window leaves operational margin, but the
runner evaluates the live configured parameters and current deadline for every
fallback. If the bound is not met, it alerts and refuses to manufacture a claim
of timely inclusion.

## Failure Modes And Evidence

- A paused or broken portal, prolonged L1 failure, or an incorrect chain
  configuration can still defeat forced inclusion. This is not a bridge-proof
  or L1-liveness proof.
- Under-gassed deposits can fail on L2. Gas limits are deployment parameters and
  require measured Base Sepolia rehearsal with margin.
- The controller operator can file a false challenge using its own supplied
  bond or overwrite a pending challenge policy. It cannot spend pre-existing
  wallet ETH through this path because owner execution requires the deposit
  value to equal the forwarded value. Operator funding and the existing daily
  challenge envelope bound this residual grief risk.
- Guardian compromise can rotate the L1 operator. It cannot change immutable
  portal, wallet, manager, or selector bindings. Guardian custody remains a
  deployment and external-review gate.
- A live rehearsal must retain both L1 transaction hashes, L1 and L2 block
  hashes, deposit identifiers, wallet policy event, challenge event, code
  hashes, chain configuration, deadline calculation, gas used, and finality
  observations. Local mocks are not substitute evidence.

## Test Evidence

- `contracts/test/p42-forced-inclusion-controller.test.js`: immutable routing,
  exact policy encoding, exact bond forwarding, caller/selector/value rejection,
  and guardian-only operator rotation.
- `contracts/test/p42-governance-v2.test.js`: forced-role fallback after session
  revocation, one-time role binding, exact calldata, one-call exhaustion,
  role-only access, and value binding.
- `agent/censorship-fallback.test.mjs`: modulo-160 aliasing, both portal payloads,
  controller-code requirement, owner binding, and two-window deadline refusal.

Gate 3 remains open until an externally reviewed release is deployed and the
signed Base Sepolia rehearsal evidence above passes canonical reconciliation.
