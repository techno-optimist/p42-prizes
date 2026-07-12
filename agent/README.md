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
OPERATOR_PRIVATE_KEY=0x... node operator.mjs \
  --rpc https://sepolia.base.org \
  --manifest ../deployments/base-sepolia/p42-prizes.json \
  --problem ../problems/hadamard-mini \
  --registry-problem-id 1 \
  --runtime /var/lib/p42/operator/hadamard-mini \
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
ARWEAVE_JWK_JSON='{"kty":"RSA",...}' \
P42_ARWEAVE_OWNER='<43-character funded wallet address>' \
P42_TRANSCRIPT_ENDPOINTS='https://arweave.net,https://arweave.dev' \
RESOLVER_PRIVATE_KEY=0x... node resolver.mjs \
  --rpc https://sepolia.base.org \
  --manifest ../deployments/base-sepolia/p42-prizes.json \
  --problem-id hadamard-mini \
  --registry-problem-id 1 \
  --transcripts /var/lib/p42/operator/hadamard-mini/transcripts \
  --runtime /var/lib/p42/resolver/hadamard-mini \
  --agent-wallet 0x... \
  --transcript-store arweave
```

The runtime scans from the manifest's deployment start block and only processes
events beyond the configured finality depth. Before signing, it re-checks the
live resolver role, submission state, challenger, reason hash, dispute deadline,
reveal fingerprint, and challenge fingerprint. Its exact call is
`resolve(submissionId, challengeInstanceHash, challengerWins,
transcriptHashBytes32, transcriptURI, verdictHash)` with the live
`resolverDecisionBondWei`; `verdictHash` is a domain-separated commitment to
the candidate, transcript, decision, and both instance hashes.

The resolver requires the same `--registry-problem-id` as the operator. It
rejects a transcript unless its typed registry binding names that frozen board,
matches the manifest's source/image anchors and contract wiring, and still
matches both the historical finalized observation and live registry state.

Production mode requires `--agent-wallet`: the contract's resolver role must be
that wallet, and its session key, chain, expiry, spend caps, allowlist, unused
one-call exact-calldata policy, calldata hash, and scope hash must all match.
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
  exact-call policies, and `p42-signed-transaction/v1` raw transaction journals.
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
destination deposit rolls the source claim back.

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

`p42-funding-activation-plan` is the non-signing production activation
preflight. It re-runs `production-launch-authorization-validate`, consumes the
exact validated bytes, and writes a private immutable 30-operation plan for the
ten launch boards. Treasury authorization, timelock arming, and pool opening
are separated by global barriers. This command deliberately does not sign or
broadcast; the durable multi-signer executor remains a launch gate.

`p42-funding-activate` is the restart-safe one-transaction executor for that
plan. Each run reads two independent RPCs at one common finalized block,
revalidates target bytecode and all ten protocol states, and chooses at most one
authorize, schedule, confirm, or execute transaction. Every new signature is
preceded by a fresh production-authorization validation and chain-time checks;
the raw transaction is durably journaled before broadcast. A mined receipt does
not advance a barrier until both RPCs observe the resulting state as finalized.

RPC endpoints come from `P42_PRIMARY_BASE_RPC_URL` and
`P42_SECONDARY_BASE_RPC_URL`; both must be credential-free root HTTPS endpoints
on different hosts. The current key adapter reads
`P42_FUNDING_TREASURY_PRIVATE_KEY` and
`P42_FUNDING_GOVERNANCE_PRIVATE_KEYS`. Production use still requires reviewed
independent signer custody rather than colocating authority keys merely because
the adapter supports it.
