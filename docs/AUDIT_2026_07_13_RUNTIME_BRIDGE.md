# Runtime Bridge Hostile Review - 2026-07-13

Status: internal source review and regression evidence only. This is not an
external audit, deployment rehearsal, or authorization to accept funds.

## Findings closed in source

1. **Resolver transport bypassed the canonical quorum.** The deployment assigns
   each challenge manager's resolver role to `P42ResolverQuorum`, while the old
   runtime encoded a direct manager call. The runtime now constructs the exact
   quorum EIP-712 decision, persists independent signer artifacts, validates
   current epoch membership and threshold, sorts signatures, and relays a
   zero-value quorum call. Direct manager resolution is local-test-only.
   A follow-up hostile pass found shared-stake overcommitment and artifact-file
   vetoes; the runtime now durably reserves one bond per unmined decision under
   a chain-and-quorum lock shared by all board runtimes. Signature ingestion is
   bounded to the 3-5 exact on-chain epoch signer filenames, so unrelated spool
   junk is ignored and bad signer artifacts cannot suppress a valid threshold.
2. **Funding activation aggregated governance custody.** The old executor could
   load a threshold key set in one process. It now rejects plural/treasury key
   variables, permits at most one local signer, and supports a self-contained
   unsigned request plus externally signed transaction import for independent
   or HSM-backed custody.
3. **Expired unresolved challenges could strand re-armed submissions.** The
   contract re-arms a submission after `ChallengeExpired` without emitting a
   second `Revealed` event. The operator now consumes finalized expiry events,
   reconstructs the canonical reveal and fresh deadline at the expiry block,
   and creates an idempotent generation-bound re-challenge job under a
   per-submission signing lock. A follow-up hostile pass also found that
   different submissions could populate the same wallet nonce before the
   existing spend lock. A shared durable allocator now reserves explicit
   nonces across all board runtimes from the maximum finalized/pending value of
   two independent RPCs; the wallet lock covers allocation through
   signed-journal durability and nonblocking broadcast reconciliation.

## Executable evidence

- `agent/resolver-quorum.test.mjs`: packet, signature recovery, epoch,
  membership, duplicate, ordering, and threshold behavior.
- `agent/resolver.test.mjs`: exact zero-value quorum policy and direct-local-test
  boundary.
- `contracts/test/p42-resolver-quorum.test.js`: an exact-ten deployment fixture
  gathers two EIP-712 signatures, relays the agent-produced policy, and observes
  the bound pending decision on-chain.
- `agent/funding-activation-executor.test.mjs`: one-key maximum, external
  request/import, restart, fail-closed binding behavior, and deterministic
  migration of validated v1 signed/broadcast/mined journals into v2 requests.
  External requests expire, bind their semantic journal generation, regenerate
  only before signing when dual-RPC nonce evidence advances, and remain valid
  across block-only finalized observations.
- `agent/runtime.test.mjs`: expiry reconstruction, generation idempotency,
  reorg invalidation, and per-submission serialization.

## Gates still open

- Independent resolver signer policy services must re-run the verifier and
  validate immutable transcript bytes before signing. A signature transport
  artifact alone is not a verdict attestation.
- Named signer custody, collective stake sizing, wallet provisioning, and
  rotation/pause/failure rehearsals are not deployed.
- The canonical Base Sepolia ceremony, event-to-runner-to-resolution campaign,
  external audit, legal approval, and real-value authorization remain open.
