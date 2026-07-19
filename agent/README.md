# P42 Autonomous Runtime

The agent runtime has three persistent state machines:

- `solver.mjs` owns one solver submission from commit through reveal,
  challenge/resolution, finalization, close, payout claim, and bond reclaim.
- `operator.mjs` ingests `Revealed` logs into the Python runner queue, runs one
  verifier at a time in the pinned Docker sandbox, and consumes deterministic
  bounded challenge candidates.
- `resolver.mjs` consumes finalized `Challenged` logs, admits a matching
  canonical runner transcript, and posts the bonded resolver decision.

This is Phase 1/testnet plumbing. It does not close the external audit, legal,
governance, resolver, verifier-image, or real-value gates.

## Detached Role Acceptance

The production role ceremony never loads a signing key. Prepare 15 EIP-712
requests from the exact pending-manifest and capsule bytes, distribute the
individual request objects to the five governance signers and other named role
holders, then assemble externally produced detached signature artifacts:

```bash
p42-role-acceptance-prepare \
  --pending-manifest ../deployments/base-sepolia/p42-prizes.json \
  --capsule /secure/release-capsule.json \
  --expected-explorer-dossier-sha256 sha256:... \
  --expires-at 1900000000 \
  --artifact-root /secure/role-acceptance/artifacts \
  --trusted-root /secure/role-acceptance \
  --output /secure/role-acceptance/requests.json

p42-role-acceptance-assemble \
  --pending-manifest /secure/role-acceptance/artifacts/sha256/<manifest-digest>.json \
  --capsule /secure/role-acceptance/artifacts/sha256/<capsule-digest>.json \
  --expected-explorer-dossier-sha256 sha256:... \
  --trusted-root /secure/role-acceptance \
  --request-set /secure/role-acceptance/requests.json \
  --signature /secure/role-acceptance/signature-01.json \
  --output /secure/role-acceptance/packet.json
```

Prepare first preserves the exact pending-manifest and capsule bytes as
read-only `sha256/<digest>.json` artifacts beneath `--artifact-root`; an
existing path is accepted only when its immutable metadata and bytes match.
Supply all 15 `--signature` arguments. Both commands create owner-private files
exclusively and refuse replacement. Assembly is offline: it performs no RPC
calls and accepts no private key, mnemonic, or seed-phrase input. Expiry is
checked later against the canonical finalized governance completion timestamp.
Completed production indexer and reconciliation validation must read those
preserved paths and receive independent pins through
`P42_ROLE_ACCEPTANCE_PENDING_MANIFEST_PATH`,
`P42_ROLE_ACCEPTANCE_PENDING_MANIFEST_SHA256`, and
`P42_ROLE_ACCEPTANCE_CAPSULE_SHA256`; packet-contained digests are not accepted
as their own observations.

## Operator Path

The only live verification path is:

```text
Revealed log
  -> immutable chain context + payload file
  -> lock-protected FIFO queue
  -> OOM planner / lease / stale-job reaper
  -> pinned Docker verifier (network off, cgroup memory, PID/CPU caps)
  -> exact VerdictReport score-atoms comparison
  -> canonical transcript + challenge candidate
  -> live window/bond-cap checks
  -> P42AgentWallet exact-calldata execute transaction
```

`operator.mjs` never starts verifier Python directly. It calls
`runtime_bridge.py`, which hard-pins `RunnerPolicy(max_running=1,
sandbox="docker")`. A missing runtime, mutable/placeholder image, low memory,
swap pressure, active lease, timeout, or malformed output fails closed.
Transient RPC calldata retrieval, Arweave lookup/gateway retrieval, and Docker
availability failures are different: they produce a durable retry outcome and
are retried until the canonical challenge deadline rather than becoming a
challenge or a terminal quarantine. Each retry yields the verifier slot during
a short durable backoff, so one unavailable submission cannot block later
eligible jobs.

On DGX, point the bridge at the existing isolated runtime instead of attempting
a system-wide package install:

```bash
export P42_RUNTIME_PYTHON=/home/chronos/inference-venv/bin/python3
```

The optional value must be an absolute interpreter path. Without it the bridge
uses `python3` from `PATH`.

For on-chain DA, reveal calldata is recovered by scanning the transaction for a
`reveal(...)` call and matching every decoded argument to the `Revealed` log.
This handles direct calls, `P42AgentWallet.execute`, and ERC-4337-style nested
calldata without assuming the top-level selector is `reveal`.

For off-chain DA, a completed lookup reporting missing bytes or a recovered
hash mismatch becomes a terminal `da_missing`/`da_hash_mismatch` candidate.
Transport failures remain retryable while the challenge window is open. The
same rule applies to on-chain calldata: a recovered malformed payload is
terminal, while an RPC outage or temporary transaction absence is retried.

```bash
cd agent
node operator.mjs \
  --rpc-url-file /run/credentials/p42/operator/rpc-primary-url \
  --nonce-rpc-secondary-url-file /run/credentials/p42/operator/rpc-secondary-url \
  --manifest ../deployments/base-sepolia/p42-prizes.json \
  --problem ../problems/hadamard-mini \
  --registry-problem-id 1 \
  --runtime /var/lib/p42/operator/hadamard-mini \
  --coordination-root /var/lib/p42/operator-coordination \
  --sandbox-staging-root /var/lib/p42/operator/hadamard-mini/sandbox-staging \
  --docker-host unix:///run/p42-docker-hadamard-mini/docker.sock \
  --operator-private-key-file /run/credentials/p42/operator-private-key \
  --agent-wallet 0x... \
  --challenge-provisioning /var/lib/p42/operator/hadamard-mini/challenge-provisioning.json
```

`--registry-problem-id` is the immutable on-chain `P42ProblemRegistry` ID for
the supplied problem directory. Startup requires it to resolve to the matching
manifest slug, frozen source digest, image digest, contract wiring, and a
finalized canonical block before it may queue or sign anything.

The current checked-in `deployments/base-sepolia/p42-prizes.json` is a stale
pre-remediation manifest and is invalid for this source; operator and
reconciliation startup fail closed on it. Do not edit it into a pretend current
deployment. A real run needs a new manifest produced by a fresh deployment and
reconciliation pass for the frozen source.

Off-chain problems also require `--da-dir <content-store>` or `--arweave`.
The Arweave path is mainnet-only and fail-closed: set `ARWEAVE_JWK_JSON` to a
funded Arweave JWK. The solver waits for at least one confirmation and verifies
the exact committed bytes through two distinct gateways before broadcasting the
commit. It never creates an ephemeral key or treats temporary devnet data as
permanent availability.
Production execution is Linux-only unless all memory inputs are supplied to the
bridge explicitly; the default memory guard reads `/proc/meminfo`.
Every board process using the same operator/session key must use the same
private `--coordination-root`. Chain-and-wallet nonce locks and
chain/manager/submission locks live there, so transaction population and
nonblocking rebroadcast cannot race across board-specific runtimes.
Production also requires `--nonce-rpc-secondary` on a different host. The
durable allocator uses the maximum finalized/pending nonce observed by both
RPCs before reserving an explicit nonce, so one stale provider cannot create a
conflicting immutable transaction.

Runtime artifacts under `--runtime` are:

- `runner-queue.json`: jobs, leases, transcript hashes, and action receipts.
- `inputs/`: immutable solution bytes, mode `0600`.
- `jobs/`: immutable event-bound queue specs.
- `transcripts/`: canonical `p42-runner-transcript/v1` evidence.
- `retry-state/`: latest retryable DA outcome for jobs awaiting payload
  recovery; it never authorizes an on-chain action by itself.
- `operator-cursor.json`: durable finalized-block cursor plus overlap anchors.
- `actions/`: exact `p42-session-call-policy/v1` call policies and signed challenge transaction journals.
- `challenge-envelope.json`: atomic, lock-protected v2 UTC-day history. Pending
  reservations survive rollover and finalized spends remain charged to their
  reservation day. This file is not an open-challenge authority.
- `challenge-provisioning.json`: immutable hash-bound, EIP-191-signed chain,
  wallet, operator, cap, and rehearsal configuration. Runtime limits may only
  tighten it.
- `runner-health.json`: externally produced fresh `p42-runner-health/v1`
  admission evidence; absent/stale/red health disables auto-file.
- `ALERTS.log`: quarantines, registry-binding refusals, expired windows, and cap
  refusals.

Each actionable challenge emits the exact
`challenge(submissionId, revealInstanceHash, reasonHash)` calldata and Keccak
calldata hash, target, selector, chain id, problem and submission/reveal scope
preimage/hash, challenge-window expiry, required value cap, and `max_calls=1`.
The operator reads the `Revealed` event fingerprint and re-checks the current
on-chain fingerprint immediately before signing, so a queued raw transaction
cannot be replayed against a replacement reveal after a reorg. Production
execution requires `--agent-wallet` and sends the
challenge through `P42AgentWallet.execute` only after the on-chain wallet shows
the matching session key, chain, expiry, caps, allowlist, calldata hash, scope
hash, and unused call count. Selector-only authorization is insufficient for
calls with arguments. Direct EOA challenge submission is available only with
`--local-test` on local chain IDs `1337` or `31337`; it refuses Base Sepolia and
non-local manifests.

Before broadcasting, the operator builds and signs the exact transaction bytes,
writes a `p42-signed-transaction/v1` journal under `actions/`, records the
`signed` action in the queue, and only then broadcasts. After a restart it
reconciles the receipt or rebroadcasts the same raw transaction bytes; it never
creates a replacement nonce transaction for the same candidate.

### Sequencer-censorship fallback

`p42-censorship-fallback` advances one crash-safe L1/L2 state-machine step per
invocation. It takes a frozen plan, an independently signed plan/cap
authorization, and a private journal path, while the two L1 RPCs, two L2 RPCs,
and operator key come only from environment variables. RPC pairs must be
credential-free root HTTPS endpoints on distinct hosts. Fee, gas, chain, L2
observation-start, RPC-lag, and shared coordination bounds are explicit command
arguments. The command never accepts a private key on argv.

The first transaction installs the exact one-call policy through the bounded L1
controller. The second cannot be signed until two L2 RPCs agree on finalized
policy storage and the exact `CallPolicySet` event is traced to an L2 deposit
from the controller alias. Completion similarly requires exact finalized
`Challenged` storage/event evidence. The durable journal preserves raw signed
bytes before either broadcast and resumes them after restart. A chain-plus-
operator lock and allocator journal are shared with the ordinary challenge
operator, preventing separate boards from signing conflicting nonces.

The authorization approver must differ from the hot operator and binds the
exact plan, expiry, bond, portal gas, L1 gas, EIP-1559 fees, both deposits'
worst-case fee, RPC lag, and L2 scan bounds.

After completion, `p42-censorship-fallback-verify` lets an independent observer
revalidate the immutable plan, authorization, completed journal, controller and
wallet bindings, both finalized L1 receipts, both source-bound type-`0x7e` L2
deposits, and both exact events through its own two-RPC-per-chain view. It takes
the expected operator address rather than the hot private key and emits a
content-addressed terminal verification report. The report always records that
sequencer censorship was not proved and Gate 3 was not closed; external review,
release binding, and the signed Base Sepolia rehearsal dossier remain separate.
The verifier's policy must match the root-owned, non-writable canonical digest
at `/etc/p42/censorship-fallback-verification-policy.sha256`; that policy binds
the release, deployment, chain genesis hashes, and post-release checkpoints.

Pending progress and retryable RPC failure exit `75`, completion exits `0`, and
terminal refusal exits `64`. The bounded systemd contract is in
`deployments/p42-censorship-fallback.service.example`; its packaged supervisor
keeps expected exit-`75` finality waits outside systemd's finite abnormal-crash
budget. Provision both isolated service accounts from
`deployments/p42-censorship-fallback.sysusers.example` before enabling it.

This is not deployment evidence. `docs/CENSORSHIP_FALLBACK.md` retains the
external review, canonical Base Sepolia deployment, live chain-parameter, gas,
restart, reorg, and two-deposit rehearsal gates.

The operator cursor stores finalized block anchors and always rescans an overlap
window. If an anchored block changes or a rescan no longer contains a queued
job's original `Revealed` source event, the bridge marks that job/action
`canonical_invalidated` and cancels queued work instead of wedging or replaying
from genesis.

The wallet currently has one exact-call slot per target/selector. The operator
therefore permits one pending provisioned `challenge(...)` policy, even though
up to three already-filed canonical challenges may remain open. Do not provision
three simultaneous challenge policies with this contract version.

At startup and before every challenge admission, the operator rebuilds a
complete `p42-canonical-open-evidence/v1` snapshot from finalized challenge
events and finalized contract storage. It fails closed if the RPC cannot supply
the full range or any evidence binding is incomplete; queue and local envelope
rows do not determine the three-open cap.

Each reservation embeds a durable action intent. Pre-journal failures release
it; after signed raw bytes are journaled, the intent stores the exact journal
path and transaction hash so restart resumes without consuming another pending
slot. Lock ownership is token/PID/host-bound and never expires by age; only a
same-host `ESRCH` owner can be reclaimed.

## Resolver Path

`resolver.mjs` resolves only from evidence that independently passes all of the
following checks: a canonical `p42-runner-transcript/v1` self-hash; Docker
sandbox provenance; a self-hashed challenge candidate; report shape/hash where
a VerdictReport exists; and an exact chain claim for the configured chain,
problem, submission, submission contract, challenge contract, and reveal
instance. A `quarantine` candidate is never converted into an on-chain verdict.

```bash
cd agent
P42_ARWEAVE_OWNER='<43-character funded wallet address>' \
node resolver.mjs \
  --rpc-url-file /run/credentials/p42/resolver/rpc-primary-url \
  --manifest ../deployments/base-sepolia/p42-prizes.json \
  --problem-id hadamard-mini \
  --registry-problem-id 1 \
  --transcripts /var/lib/p42/operator/hadamard-mini/transcripts \
  --runtime /var/lib/p42/resolver/hadamard-mini \
  --coordination-root /var/lib/p42/resolver-coordination \
  --quorum-signatures /var/lib/p42/resolver-quorum-signatures \
  --resolver-private-key-file /run/credentials/p42/resolver-private-key \
  --arweave-jwk-file /run/credentials/p42/arweave-jwk \
  --agent-wallet 0x... \
  --transcript-store arweave \
  --transcript-endpoint https://arweave.net \
  --transcript-endpoint https://arweave.dev
```

The runtime scans from the manifest's deployment start block and only processes
events beyond the configured finality depth. Before signing, it re-checks the
live resolver role, submission state, challenger, reason hash, dispute deadline,
reveal fingerprint, and challenge fingerprint. In production, that resolver
role must be the manifest's `P42ResolverQuorum`, not the runtime key or agent
wallet. The runtime writes a self-hashed `p42-resolver-quorum-decision/v1`
packet for the exact EIP-712 `Decision`, including the current signer epoch,
transcript URI/content bindings, manager, challenge instance, beneficiary,
nonce, and expiry.

`resolver-signer.mjs` is the fail-closed independent signer policy service. A
caller-selected local transcript is not rerun authority. Before dispatching its
isolated executor, the signer first creates a random, packet-scoped challenge in
its private `--signature-root`:

```bash
node resolver-signer.mjs --prepare-rerun \
  --manifest /opt/p42/deployments/base-sepolia/p42-prizes-v2.json \
  --registry-problem-id 1 \
  --packet /var/lib/p42/resolver/actions/decision.quorum-decision.json \
  --published-transcript /var/lib/p42/resolver/transcripts/published.json \
  --signature-root /var/lib/p42/resolver-quorum-signatures
```

Preparation emits a canonical `p42-resolver-rerun-request/v1`. It contains only
the signer challenge plus immutable packet, manifest, board, published-transcript,
and chain-claim references. A root-owned dispatcher installs that byte-identical
request as `/var/lib/p42/resolver-rerun-requests/<registry-problem-id>/request.json` and
starts `p42-resolver-rerun@<registry-problem-id>.service`; the requester cannot
provide a transcript, job id, elapsed time, or runner metadata.

The dispatcher is activated by a path unit plus a recovery timer. It validates
the signer authorization and a root-only board map, then journals a per-board
slot through `rotating`, `dispatching`, `dispatched`, and `completed`. A later
request can replace the fixed service slot only while the exact board unit is
inactive and the prior request is durably terminal. The rotation journal is
durable before bytes change, and the new slot binding is durable before start.
Only the dispatcher constructs the systemd unit name.

The dedicated per-board executor independently retrieves reveal calldata or
the Arweave payload, checks the exact bytes against `commitDaHash`, and enqueues
an ordinary `p42-runner` job over the host-global verifier executor socket. That
existing authority injects the protected board identity and applies its FIFO,
OOM, swap, cgroup, pinned-image, and resource policies. The host executor reads
its terminal queue or authenticated archive, reconstructs the canonical
`p42-resolver-rerun/v1` receipt, and signs it with an executor-only Ed25519 key.
The rerun UID never receives that key and cannot submit a receipt body or
transcript as signing authority. The signer pins that public key
through an owner-only credential file. The receipt binds the exact packet and
decision digests, chain/quorum/manager/submission and challenge/reveal instance,
published and local transcript hashes, solution and DA hashes, immutable image
and source digests, resource identity, and the signer-issued challenge nonce.
The signer rejects cross-packet replay, copied transcripts, timestamp-only
rewraps, altered receipts, and signatures outside the pinned executor trust
input. There is no production flag that accepts a caller transcript, unsigned
fixture receipt, caller-provided nonce, or caller-owned run metadata.

After that authority check, the service retrieves the published transcript
byte-for-byte from two independently operated gateways, validates the frozen
manifest/registry binding through two independent RPCs, requires those RPCs to
agree on one finalized block and complete signable state, and recomputes the
exact verdict hash. It repeats the finalized state check, binds the exact receipt,
fsyncs an anti-equivocation authorization keyed by chain, quorum, manager, and
challenge instance, durably writes the signature artifact, and finally records
attempt completion. An identical receipt retry resumes after a crash at any of
those boundaries. A different receipt or nonce is rejected. An expired attempt
may be renewed only when it has no receipt, authorization, or signature; renewal
retains an immutable tombstone for the prior nonce.

```bash
cd agent
P42_RESOLVER_SIGNER_PRIVATE_KEY=0x... \
P42_TRANSCRIPT_ENDPOINTS='https://gateway-one.example,https://gateway-two.example' \
node resolver-signer.mjs \
  --rpc https://independent-rpc-one.example \
  --rpc https://independent-rpc-two.example \
  --manifest ../deployments/base-sepolia/p42-prizes-v2.json \
  --registry-problem-id 1 \
  --packet /var/lib/p42/resolver/actions/decision.quorum-decision.json \
  --signature-root /var/lib/p42/resolver-quorum-signatures
```

The signer derives transcript and receipt paths from the active packet+nonce
under `/var/lib/p42/resolver-rerun-results/<registry-problem-id>/`; neither is a
CLI input. The attestor private credential is available only to
`p42-verifier-executor.service`. Per-board rerun users and the signer receive only
the matching public trust credential. Source and unit definitions do not prove
that an independent executor host, credential, HSM, or rehearsal has been
deployed. The environment decision-key adapter remains testnet plumbing, not a
custody claim.

The signer reads transcript and receipt through a dedicated cross-UID reader,
not the generic private-file helper. Generate the result-authority credential
and dispatch map from the actual `getent passwd/group` IDs after
`systemd-sysusers`; numeric IDs in the example JSON are illustrative. Result
directories must be exact rerun-UID/submitter-GID `0750` paths and files must be
single-link `0640` regular files with the same ownership. Descriptor traversal
is no-follow and checks inode stability. The signer has group read access only.

The executor trust credential path is fixed at
`/run/credentials/p42/resolver-rerun-executor-trust`; it is deliberately not a
CLI option. Provision that owner-only JSON credential with schema
`p42-resolver-rerun-executor-trust/v1`, purpose `resolver-rerun`, algorithm
`ed25519`, a stable `key_id`, and the pinned `ed25519:<64 lowercase hex>` public
key.

The private executor credential uses schema
`p42-resolver-rerun-executor-key/v1`, purpose `resolver-rerun`, algorithm
`ed25519`, the same `key_id`, and an `ed25519:<64 lowercase hex>` seed. Provision
it only to `p42-verifier-executor.service`; never provision it to a per-board rerun process, the packet
requester, resolver signer, operator, or relay. Install
`deployments/p42-resolver-rerun@.service.example`, the corresponding sysusers,
and the updated host-global executor unit together. A clean deployment must
also create each service's `staging` directory before activation.

The executor also pins an owner-only
`p42-resolver-rerun-request-trust/v1` credential with purpose
`resolver-rerun-request`, algorithm `eip191`, and the lowercase signer address.
`--prepare-rerun` signs the request hash with that resolver signer identity.
Re-signing an altered request with any other key is rejected before solution
retrieval or queue admission.

Executor staging is durable at
`/var/lib/p42/resolver-rerun/<registry-problem-id>/staging/<request-hash>/`.
The independently materialized solution and canonical job are fsynced before
enqueue, including every newly created ancestor directory. Restart therefore reuses the same solution path retained by the real
queue's `job_id` plus `source_event_hash` idempotency rule. Staging is removed
only after transcript and receipt files and their parent directories are
durable. The host executor exposes only request-bound enqueue, execute, attest,
and archive-recovery operations to rerun UIDs. Generic bridge, action,
terminalization, quarantine, and operator-job access are rejected. Attestation
validates the exact job, signed request, event hash, chain claim, solution/DA
hashes, manifest/image/source/resource identity, and executor-owned transcript.
Its dual-index archive lookup returns that validated terminal job after live
queue admission archives it, so crash recovery never treats rerun-owned
transcript bytes as signing authority.

Each accepted signer policy writes one
self-hashed `p42-resolver-quorum-signature/v1` artifact beneath
`<--quorum-signatures>/<decision_digest>/`. The relay recovers every signer,
quarantines malformed/duplicate/nonmember artifacts without letting one bad
file suppress a valid threshold, sorts valid signatures by signer address, and
rejects a stale epoch. Its exact production call is
`P42ResolverQuorum.resolve(decision, transcriptURI, signatures)` with zero ETH.
The quorum contract supplies the resolver decision bond from its collective
stake. The legacy direct `P42ChallengeManager.resolve(...)` path exists only
under `--local-test` on chain IDs `1337` or `31337`.

Signature artifacts remain transport records rather than external attestations.
Signer identities, independent hosts/runners, HSM custody, independently
reviewed per-board proof programs, an audited immutable verifier gateway, and a
deployed multi-signer/fraud-proof rehearsal remain launch gates. The source-level
trust boundary and settlement semantics are specified in
`docs/OBJECTIVE_FRAUD_PROOFS.md`.

One chain-and-quorum lock under the required shared `--coordination-root`
serializes state reload, decision reservation, transaction population,
journaling, and broadcast across all ten board runtimes. Every canonical quorum
decision reserves one live resolver bond until it is mined, superseded, or
orphaned; later decisions wait when collective stake minus durable reservations
cannot cover another bond. This prevents concurrent disputes from promising
the same quorum stake more than once.

Signer artifacts use the exact filename `<lowercase-signer-address>.json` in
the decision-digest directory. The runtime reads only the 3-5 addresses exposed
by the packet's on-chain signer epoch; unrelated spool files are ignored.

The resolver requires the same `--registry-problem-id` as the operator. It
rejects a transcript unless its typed registry binding names that frozen board,
matches the manifest's source/image anchors and contract wiring, and still
matches both the historical finalized observation and live registry state.

Production mode requires `--agent-wallet`: its session key, chain, expiry,
spend caps, allowlist, unused one-call exact-calldata policy, calldata hash, and
scope hash must all match the quorum relay call.
The runtime writes the policy artifact first and fails closed until the wallet
already exposes that exact policy. Direct EOA execution is only available with
`--local-test` on local chain IDs `1337` or `31337`.

`--transcript-store arweave` content-addresses and uploads the canonical
transcript bytes. Before uploading it searches Arweave by the artifact SHA-256,
so a restart after a successful post recovers the existing transaction instead
of paying for a duplicate. Before POST, the fully signed transaction and its ID
are durably journaled; a lost response or process crash therefore reposts the
same transaction bytes instead of creating a second paid upload. The provider
receipt is validated and durably journaled before retrieval; every retry still fetches byte-identical canonical
content through two independently operated HTTPS gateways before a resolver
call policy can be created. `--publication-receipts` remains an offline adapter
for bytes published by a separately controlled service. A funded Arweave JWK,
live deployment rehearsal, and dynamic owner provisioning of each wallet call
policy remain external integration gates.

Resolver state lives under its own `--runtime` directory:

- `resolver-cursor.json`: finalized-block anchors and rescan progress.
- `resolver-state.json`: event-bound decisions and reconciliation state.
- `actions/`: immutable signed Arweave uploads, publication receipts,
  EIP-712 decision packets, exact-call policies, and
  `p42-signed-transaction/v1` raw transaction journals.
- `ALERTS.log`: invalid evidence, missing transcripts, policy refusals, and
  reorg observations.

The resolver persists raw signed bytes before broadcast. It verifies receipt
block hashes against the canonical chain, waits for finality, and if a receipt
disappears after a reorg it re-checks the live fingerprints before rebroadcasting
the same raw bytes. A replacement challenge instance or resolved challenge is
marked superseded rather than retried against.

## Solver Path

```bash
AGENT_PRIVATE_KEY=0x... node solver.mjs \
  --rpc https://sepolia.base.org \
  --manifest ../deployments/base-sepolia/p42-prizes.json \
  --problem ../problems/hadamard-mini \
  --registry-problem-id 1 \
  --solution ../problems/hadamard-mini/examples/valid-4.json \
  --state /var/lib/p42/solver/hadamard-mini.json
```

The state file is mode `0600` and contains the salt, submission identity, DA
receipt, current phase, and every lifecycle transaction journal. Each transaction
is populated and signed first; the raw signed bytes and hash are persisted before
broadcast. Re-running the same command resumes it; identity mismatches fail
closed, and a restart reconciles or rebroadcasts the exact same transaction bytes
instead of creating a replacement nonce transaction.

`--registry-problem-id` is optional for a legacy one-board manifest and required
for a multi-board manifest. It selects the only child pool, ledger, submission
manager, and challenge manager the solver may touch.

The submission id is parsed from the matching `Committed` receipt log. It is
never inferred from global `submissionCount()`. The lifecycle loop handles:

- commit maturity and reveal;
- active challenges and permissionless challenge expiry;
- pending resolver decisions and permissionless finality after the fraud window;
- solver-favorable rearmed windows and repeated challenges;
- live posting-bond top-up before finalization;
- finalization retries and process restarts;
- posting-bond reclaim;
- optional owner close with `--close`, or waiting for external close;
- payout claim after close.

`--submit-only` persists commit/reveal and exits. `--fund` and `--close` are demo
options and must only be used when the key actually owns those roles.

## Checks

```bash
PYTHONPATH=../src python3 -m pytest -q \
  ../tests/test_runner_chain_runtime.py \
  ../tests/test_runner_queue.py \
  ../tests/test_runner_worker.py \
  ../tests/test_runner_sandbox.py
npm test
node --check operator.mjs
node --check resolver.mjs
node --check solver.mjs
node --check indexer.mjs
npm audit --audit-level=moderate
```

No runtime transcript or action artifact includes a private key, RPC secret,
token, or inherited verifier environment.
Agents may retain the frontier title while recycling a matured award into a
different active bounty with `--donate-winnings-to-pool <pool-address>`. The
solver uses the atomic `donateClaimToPool` path: no award touches the agent
wallet, the destination sponsorship is attributed to the solver, and a failed
destination deposit rolls the source claim back. The agent preflights the
destination's armed, open, cap, and deadline state. If it remains unavailable,
the agent waits without consuming its retry budget, then takes the ordinary
payout during the final 24 hours before the source claim deadline so a stale
donation target cannot destroy the award.

The indexer operator signs each exact checkpoint generation before portal
publication. Register its Ed25519 public key out of band for attestation class
`p42-indexer-checkpoint-attestation/v1` and role
`indexer-checkpoint-authority`, then run:

```bash
P42_INDEXER_ATTESTATION_PRIVATE_KEY=<32-byte-lowercase-hex-seed> \
  p42-indexer-checkpoint-attest \
  --trusted-root /srv/p42 \
  --checkpoint /srv/p42/indexer-checkpoint.json \
  --output /srv/p42/indexer-checkpoint-attestation.json
```

The private seed stays on the indexer host. The portal consumes only the
detached signature, exact checkpoint bytes, and separately pinned production
trust registry.

## Funding activation plan

Before building the activation plan, produce the non-custodial v2 authority
bundle. `p42-funding-authorization-request` revalidates the exact deployment
manifest and production launch authorization, then reads every submission
manager nonce from two independent RPCs at one common finalized block. It
writes one immutable private request set containing 30 separately identified
EIP-712 requests: three authority roles for each of ten managers. The command
does not accept or read a private key.

```bash
P42_PRIMARY_BASE_RPC_URL=https://primary.example \
P42_SECONDARY_BASE_RPC_URL=https://secondary.example \
p42-funding-authorization-request \
  --manifest /srv/p42/deployment-manifest.json \
  --authorization /srv/p42/production-launch-authorization.json \
  --trust-registry /srv/p42/trust-registry.json \
  --artifact-root /srv/p42/release \
  --sp1-security-report /opt/p42-prizes/docs/evidence/sp1-dependency-security-current.json \
  --python /opt/p42/bin/python \
  --repo-root /opt/p42-prizes \
  --trusted-root /srv/p42 \
  --output /srv/p42/funding-authorization-requests.json
```

Each external signer returns one
`p42-funding-authorization-role-signature/v2` JSON artifact copying the exact
`requestSetDigest`, `requestId`, generation, request expiry, board index,
manager, role, and signer from its request, plus the 65-byte EIP-712 signature.
After all 30 artifacts are present, assemble the canonical validator input:

```bash
P42_PRIMARY_BASE_RPC_URL=https://primary.example \
P42_SECONDARY_BASE_RPC_URL=https://secondary.example \
p42-funding-authorization-assemble \
  --manifest /srv/p42/deployment-manifest.json \
  --authorization /srv/p42/production-launch-authorization.json \
  --trust-registry /srv/p42/trust-registry.json \
  --artifact-root /srv/p42/release \
  --sp1-security-report /opt/p42-prizes/docs/evidence/sp1-dependency-security-current.json \
  --python /opt/p42/bin/python \
  --repo-root /opt/p42-prizes \
  --trusted-root /srv/p42 \
  --request-set /srv/p42/funding-authorization-requests.json \
  --signature /srv/p42/signatures/board-0-production.json \
  --signature /srv/p42/signatures/board-0-security.json \
  --signature /srv/p42/signatures/board-0-governance.json \
  --output /srv/p42/funding-activation-signatures-v2.json
```

Pass all 30 `--signature` arguments. Assembly repeats launch validation and
dual-RPC finalized nonce collection, rejects expired generations, stale manager
nonces, substitutions, role swaps, duplicates, and partial sets, recovers every
authority signer, and finally invokes the same v2 bundle validator used by the
activation planner. Outputs are owner-only, atomic, no-clobber files below the
named trusted root.

`p42-funding-activation-plan` is the non-signing production activation
preflight. It re-runs `production-launch-authorization-validate`, consumes the
exact validated bytes, regenerates the activation-bound SP1 dependency
security report, and writes a private immutable 30-operation plan for the
ten launch boards. Treasury authorization, timelock arming, and pool opening
are separated by global barriers. This command deliberately does not sign or
broadcast; the durable multi-signer executor remains a launch gate.

`p42-funding-activate` is the restart-safe one-transaction executor for that
plan. Each run reads two independent RPCs at one common finalized block,
revalidates target bytecode and all ten protocol states, and chooses at most one
authorize, schedule, confirm, or execute transaction. Finalized per-operation
confirmations and exact unsigned requests are persisted in the locked activation
journal. Every request records its journal generation, a 15-minute chain-time
expiry, and matching finalized/current signer nonces from both RPCs. Every new
request and imported signature is preceded by a fresh production-authorization
validation, chain-time check, and dual-RPC nonce check. A mined receipt does
not advance a barrier until both RPCs observe the resulting state as finalized.
An armed or open board also must name the exact plan-bound timelock operation in
`Executed` state; equivalent calldata executed under another salt is rejected.
Completion v2 records the exact arm/open operation IDs and states for all ten
boards and is unavailable until all twenty governance operations are executed.
Before reading either RPC, the run command revalidates the authorization,
rechecks the activation signature bundle, reconstructs the canonical ordered
30-operation plan, and requires the supplied private plan artifact to match its
exact serialized bytes and digest.
Immediately before the sole broadcast callback, including restart from an
already journaled signed transaction, the runner repeats that validation and
requires the Python interpreter, scanner, versioned policy, committed report,
and seven-lock roster to remain byte-identical and passing.

RPC endpoints come from `P42_PRIMARY_BASE_RPC_URL` and
`P42_SECONDARY_BASE_RPC_URL`; both must be credential-free root HTTPS endpoints
on different hosts. A process may hold at most one local key in
`P42_FUNDING_SIGNER_PRIVATE_KEY`. The legacy treasury and plural governance key
variables are rejected, so no activation host is required or permitted to
aggregate quorum raw keys.

For external, remote, or HSM-backed signing, run without a private key and name
the one signer assigned to that process:

```bash
p42-funding-activate <common-arguments> \
  --signer 0xSigner \
  --signing-request-output /srv/p42/actions/funding-signing-request.json
```

The command returns `awaiting-signature`. Sign the exact `unsignedTransaction`
from the `p42-funding-activation-signing-request/v2` artifact and return a
`p42-signed-transaction/v1` record that also copies
`requestGeneration`, `requestExpiresAt`, and `unsignedHash` into
`activation_request_generation`, `activation_request_expires_at`, and
`activation_request_unsigned_hash`. The coordinator imports and broadcasts it
with the same durable journal:

```bash
p42-funding-activate <common-arguments> \
  --signed-transaction /srv/p42/actions/funding-signed-transaction.json
```

Each governance signer repeats this independently after finalized chain state
selects it. A signer that already confirmed reports `wait-signers`; it never
needs access to another signer's key or artifact.

If unrelated signer activity advances the dual-RPC current nonce, an unsigned
request is invalidated and regenerated under the journal lock. Regeneration is
forbidden after any signed record exists for that action. Imports must match the
current journal generation and nonce, so an old remote signature cannot replace
or collide with unrelated signer activity.

On first restart, a legacy `p42-funding-activation-journal/v1` is migrated only
when every signed, broadcast, or mined raw transaction selects exactly one plan
action and reconstructs one exact unsigned request. Tampered, unbound, or
ambiguous records leave the v1 bytes untouched and stop activation.
