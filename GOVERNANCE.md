# Project Governance

How decisions get made in the P42 Prizes repository: who decides what, how
someone gains or loses authority, and which decisions are deliberately *not*
open to community control.

> **Not to be confused with [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md)**, which
> covers *protocol* governance — the multisig, timelock, and guardian roles that
> control deployed contracts. This file covers *project* governance: the
> repository, the roadmap, and the people.

## Current state, stated honestly

P42 Prizes is at the beginning of its transition to community governance. Right
now there is **one maintainer**, the project founder, and that is a fact rather
than a design goal. This document describes the model being moved toward and the
concrete conditions for getting there. It should not be read as describing an
already-functioning multi-stakeholder process.

Treat every "the maintainers decide" below as "the maintainer decides, until
there is more than one." That is exactly the problem this transition exists to
solve, and the first milestone is straightforward: **a second maintainer with
real merge authority.** Until then, no PR in this repository can receive an
independent approval, because GitHub does not permit self-approval.

## Roles

**Contributors** — anyone who opens an issue or a pull request. No permission is
needed and no prior involvement is assumed. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

**Reviewers** — contributors with a track record in a specific area (a problem
board, the portal, the contracts, the verifier tooling) whose review is actively
sought there. Reviewers do not have merge rights. This is a recognised role
rather than a granted permission, and it is the normal path toward maintainer.

**Maintainers** — hold merge rights and are accountable for what lands. A
maintainer is expected to enforce the evidence discipline in
[`CONTRIBUTING.md`](CONTRIBUTING.md) even when it is inconvenient, and
especially against their own work.

**Problem owners** — accountable for a specific board: its spec, its verifier,
its fixtures, and the accuracy of the claims made about it. A problem owner is
not automatically a maintainer, and a maintainer is not automatically competent
to accept changes to someone else's board.

## Becoming a maintainer

The bar is demonstrated judgement, not volume. Concretely: a sustained history
of contributions in an area, review work that has caught real problems, and — the
part that matters most here — evidence of *calibration*. Someone who reliably
says "I could not verify this" when they could not verify it is more valuable to
this project than someone who ships more code.

Nomination is by an existing maintainer, in a public issue, with the reasoning
stated. Approval requires no sustained objection from existing maintainers. Once
there are three or more maintainers, this becomes a majority vote among them.

Maintainers who become inactive for an extended period move to emeritus status.
This is administrative rather than punitive and carries no judgement; returning
is a matter of asking.

## How decisions are made

**Ordinary changes** — lazy consensus. Open a PR; if no maintainer objects and
CI is green, it lands. Most work is this.

**Significant changes** — anything altering the payout mechanism, the verifier
standard, the admission rules, the gate model, or this document. These need a
public issue proposing the change, enough time for people to actually respond,
and explicit maintainer agreement. Objections are resolved by discussion; if
that fails, by maintainer majority.

**Disagreement** is expected and welcome. The escalation path is discussion in
the issue, then a maintainer decision with the reasoning written down. A decision
without stated reasoning is not a decision anyone can learn from or appeal.

## What is deliberately not community-governed

Some authority cannot be delegated to the community, and pretending otherwise
would be dishonest. These are tracked in
[`docs/HUMAN_ACTIONS.md`](docs/HUMAN_ACTIONS.md):

- **Anything moving real value.** Enabling funding, deploying contracts, and
  activating settlement are gated behind external audit, counsel review, and
  named custody. No amount of community consensus substitutes for those.
- **Credentials and infrastructure.** Deploy keys, registry credentials,
  repository settings, and signing keys stay with accountable named holders.
- **External attestations.** Audits, legal memos, and independent mathematical
  reviews derive their value from the independence and accountability of the
  signer. They cannot be crowdsourced or voted into existence.
- **Security embargo decisions.** Disclosure timing for an unpatched
  vulnerability is decided privately. See [`SECURITY.md`](SECURITY.md).

The honest summary: **the code and the roadmap are open to community control;
the money and the keys are not, and will not be until the mechanisms in
[`docs/GATE_LEDGER.md`](docs/GATE_LEDGER.md) make that safe.** The long-term
design goal is to remove the trusted resolver entirely via the fraud-proof path,
which is what would make "community-led" true at the protocol layer and not only
at the repository layer.

## Changing this document

Via the significant-change process above. Amendments are proposed in public,
discussed, and recorded in git history like anything else.
