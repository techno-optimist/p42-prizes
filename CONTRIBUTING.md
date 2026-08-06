# Contributing to P42 Prizes

P42 Prizes is an open, permissionless math-bounty arena whose oracle is an
**exact, deterministic verifier anyone can re-run**. A public re-run *is* the
proof. That single property is the moat, and it is why this repository holds
itself to an unusually strict evidentiary standard.

Read [`README.md`](README.md) for what the project is, and
[`docs/BUILD.md`](docs/BUILD.md) for the design spec. This file covers how to
work on it.

## Current posture — read this first

This is a **Phase 0 pilot**. It is not audited, not legally reviewed, and moves
**no real ETH**. Every funding target is `null` and fails closed. Contributions
are welcome anywhere in the stack, but nothing you contribute can make the
system live — see [What contributors cannot close](#what-contributors-cannot-close).

[`docs/GATE_LEDGER.md`](docs/GATE_LEDGER.md) is the canonical statement of what
is actually live versus merely specified. When in doubt, it wins over any other
document, including this one.

## The prime directive

**A gate does not close because code exists.**

This is the rule the project is built around, and the one most likely to get a
PR sent back. Working code, a passing shape validator, a generated key, or a
convincing document are not evidence that a gate is closed. A gate closes only
when the evidence artifact exists, the required attestation is named, and the
failure mode has an executable regression or an operational runbook.

Practical consequences for your PR:

- Distinguish **source evidence** ("the code does X, tests pass") from
  **deployed evidence** ("X was observed on a real deployment"). Never let the
  first imply the second.
- Never describe a local rehearsal, a mock execution, a same-operator
  reproduction, or a historical artifact as current closure.
- If you could not verify something, **say so explicitly**. "Not run, because
  the compiler download is blocked in this environment" is a good line in a PR.
  Silence is not.
- If your change alters a gate claim, update `docs/GATE_LEDGER.md` in the same
  PR. This is required, not optional.

If that sounds paranoid: the failure mode for a bounty arena that gets this
wrong is theft, and the whole design rests on the verifier being trustworthy.

## Ways to contribute

Roughly in order of how much they move the project:

**New problem boards.** The highest-value contribution. A board is a
self-contained repo following the `p42-problem` standard in
[`docs/P42_PROBLEM_V1.md`](docs/P42_PROBLEM_V1.md): an exact verifier, a spec, a
seed witness, and fixtures. Problems must be **exact, deterministic, and
self-certifiable** — integer/rational arithmetic or rigorously enclosed
intervals. No unenclosed floating-point result may decide a verdict. Start from
[`problems/hadamard-mini/`](problems/hadamard-mini/), the runnable reference
fixture, and open an issue with the "New problem board" template before doing
heavy work so scope can be checked early.

**Breaking the verifiers.** If you can make an exact verifier accept a wrong
answer, reject a right one, or behave differently on two hosts, that is the most
valuable bug you can file. Cross-platform nondeterminism is a real defect here,
not a curiosity. See [Security](#security) for anything exploitable.

**Red-teaming the mechanism.** The payout math, bonds, challenge window, and
resolver are adversarial surfaces. Every known attack is supposed to have an
executable test — see `contracts/test/p42-redteam.test.js` and
`contracts/test/RED_TEAM_COVERAGE.md`. Attacks not represented there are
especially interesting.

**Independent mathematical review.** Every fundable problem needs a review that
checks the correspondence between the public claim, the reduction, the accepted
witness language, and the scorer. A computational re-run is not a proof review.
The packet format is in [`docs/HUMAN_ACTIONS.md`](docs/HUMAN_ACTIONS.md).

**Portal, protocol, and tooling.** Ordinary software work across `web/`,
`contracts/`, `agent/`, and `src/p42_prizes/`.

**Documentation.** Particularly anywhere the docs disagree with the code. That
class of bug has bitten this repo more than once, and it is worth a PR on its own.

## Development setup

```bash
make validate
make lint
make test
make verify-seed
make admit-host-seed
make contracts-test
```

Run one problem verifier directly:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli verify \
  --problem problems/hadamard-mini \
  --solution problems/hadamard-mini/examples/valid-4.json
```

Portal:

```bash
cd web && npm ci && npm run dev
```

The full pre-commit gate list, including the web and contract gates, is in
[`AGENTS.md`](AGENTS.md). Run the subset relevant to a small docs-only change,
but **do not skip the contract or web gates when touching those surfaces**.

Some gates need things a laptop may not have — a pinned `cargo-prove` for the
SP1 objective-program gates, network access for Hardhat's compiler download, a
PostgreSQL instance for the portal database integrations. If a gate will not run
for you, say which one and why in the PR rather than working around it.

## Pull requests

Use the template. It asks for **Summary / Verification / Boundary**, and the
Boundary section is the one that matters most — it is where you state what your
change does *not* establish.

- Keep PRs scoped to one concern.
- Put real command output in Verification. Counts and exit codes.
- Branch CI only runs through an open pull request; `push` runs are restricted
  to `main`. A branch with no PR has **no** CI evidence however green it looks
  locally.
- Expect review to push back on overclaiming more than on style.

## What contributors cannot close

Some things are structurally out of reach of any contribution, no matter how
good. These need credentials, deployed state, external professional judgement,
or a human signature, and they are tracked in
[`docs/HUMAN_ACTIONS.md`](docs/HUMAN_ACTIONS.md):

- external smart-contract audit
- counsel-signed legal and compliance memo
- named custody, multisig signers, and guardian
- immutable verifier image publication and the trusted N-host matrix
- repository-owner settings, deploy credentials, and release attestations

Please do not open PRs that mark these complete. Do open PRs that make them
*easier* — better validators, better runbooks, better evidence schemas.

## Security

**Do not open a public issue for an exploitable vulnerability.** That includes
anything that lets a verifier be fooled, a bond be stolen, a payout be
mis-assigned, or a resolver decision be forged.

See [`SECURITY.md`](SECURITY.md) for the disclosure path. Private vulnerability
reporting is being enabled; until it is confirmed live, `SECURITY.md` records
the intended route. If you are unsure whether something is sensitive, treat it
as sensitive.

## Agent contributors

Much of this repository was written by AI agents, and that is expected to
continue. Agents are first-class contributors here and are held to exactly the
same standard as everyone else — in particular the prime directive above, which
exists largely because generated work is prone to confident overclaiming.

If you are an agent working in this repo, read [`AGENTS.md`](AGENTS.md) first.
It carries the deployment contract, the safety gates, and the rules for what you
may and may not represent as closed.

## Governance

[`GOVERNANCE.md`](GOVERNANCE.md) covers how decisions get made, how someone
becomes a maintainer, and — importantly — which decisions are deliberately not
open to community control, because they move real value or depend on an
accountable named signer.

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE), the license this project ships under.
