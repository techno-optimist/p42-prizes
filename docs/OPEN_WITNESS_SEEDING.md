# Open-Witness-Phase Seeding — autonomous frontier establishment

**Status:** implemented (contracts + tests green). Supersedes the human-attested
seed policy in [`POLICY_DECISIONS_2026_07_08.md`](POLICY_DECISIONS_2026_07_08.md#seed-policy--rule--enforcement-machinery-decision-1-the-part-we-can-build-now).

## Why

The audit's F1 fix requires each problem's frontier `bestScoreAtoms` to start at
the **true best-known** score, or the first solver gets paid for re-submitting a
known result (a false prize). The debate's first answer was a human-signed
"seed dossier" attesting the published record. But the owner's goal is *no human
in the loop* — and the oracle can verify a score is **correct**, just not that
it is **novel** (novelty is a fact about the outside world, not about the bytes).

The insight that removes the human: **stop attesting a seed; let the frontier
establish itself on-chain.** The protocol pays for *verified on-chain frontier
movement*, not novelty attribution — so the "seed" is simply the best score
anyone bothered to prove on-chain **for free** before funding opens.

## The mechanism (two phases, one frontier)

- **Open phase (unpaid).** Funding is not armed. `seedScoreAtoms` is just a
  **loose starting ceiling** (any real solution beats it — no judgment call).
  Anyone — crucially the funder's own agent — posts witnesses for free; each
  verified strict improvement advances `bestScoreAtoms` exactly as in the paid
  path, but records **zero credit** (`finalize` gates credit on the commit
  phase). This establishes the true public frontier on-chain **by construction**.
- **Paid phase.** The funder calls `armFunding()` (one-shot, the single arm
  authority) and deposits ETH. From then on, a submission **committed after the
  arm** earns the **marginal over whatever frontier the open phase established**.

The erdos-vs-Haugland question dissolves entirely: whatever the Hyra witness
scores under the verifier, posting it for free during the open phase *is* the
seed — no one has to rule on whether it is a "genuine record."

## Why it is safe (the money-path invariants)

- **Credit is bound to the COMMIT phase, not the finalize phase**
  (`creditAtoms = fundingArmed && committedAt >= armedAt ? marginal : 0`). This
  closes the straddle attack: a witness committed+revealed for free in the open
  phase cannot earn by withholding `finalize` across the arm — it earns 0
  forever, even though its frontier advance still counts (for free).
- **Funding is impossible before arming.** `P42BountyPool.fund()`/`receive()`
  revert unless the manager is wired *and* `fundingArmed()` — a pool cannot be
  funded during the open phase, so no ETH is ever stranded in an unpaid phase.
  (The pool's payable constructor was removed so there is no un-armed funding
  path at all.)
- **Open-phase poisoning is recoverable.** A fraudulent free posting that
  advances the frontier earns 0 credit but could brick the problem; the
  governance `voidFinalize` (under `pausedAll`) restores the frontier for a
  0-credit finalize too, so honest postings can resume.

## The honest residual (not a protocol hole)

If a published result is **never posted for free** — not even by the funder's
agent — a funder can overpay for it. That is a funder's eyes-open economic
choice (run a proper open phase and this cannot happen), not a soundness bug.
And verifier **soundness** — does passing the check imply the theorem — is a
separate, genuinely categorical wall that only machine-checked formal proofs
(e.g. Lean) close.

## What this removes from the path to live

The **human seed sign-off is gone.** The funder's agent runs the open phase
autonomously (just running the verifier on public witnesses). The only remaining
irreducible human residue is (1) **verifier soundness** (a formal-proofs research
track) and (2) **legal accountability** (liability attaches to a person/entity,
not a keypair) — neither of which is a verification task the oracle could perform.

## Optional hardening (not in this pass)

An on-chain `OPEN_PHASE_MIN_SECONDS` gate on `armFunding` (require a minimum
public window before arming) would make "the public had a fair shot" a protocol
guarantee rather than relying on funder incentive. A `NOTE` marks the insertion
point in `P42SubmissionManager.armFunding`.
