# OpenAI Build Week 2026 evidence packet

P42 Prizes existed before the OpenAI Build Week submission period. This file
defines the eligibility boundary so judges can evaluate only the meaningful
extension built after **July 13, 2026 at 9:00 AM Pacific**.

Development accelerated as soon as the hackathon was announced. The dated
July 9–13 history is retained as project provenance; the extension below gives
judges an unambiguous post-start evaluation target under the Official Rules.

## Pre-existing project

Before the submission period, the repository already contained the P42 problem
format, exact verifier runner, Phase 0 portal, agent API, testnet contract work,
and production gate ledger. Those systems are context, not claimed Build Week
work.

## Build Week extension

The eligible extension is the zero-setup **Verifier Lab** at `/build-week`:

- a client-side integer verifier for the order-4 Hadamard fixture;
- editable candidate JSON and three adversarial fixtures;
- recompute-don't-echo behavior that ignores solver-claimed scores;
- a canonical verdict view with exact rational score and improvement;
- automated tests for acceptance, partial progress, lying claims, and malformed
  input;
- a public before/after boundary and judge testing path.

The browser lab is an exact-integer mirror of the fixture's mathematical core,
not the settlement authority. The authoritative verifier remains the bounded,
strict parser invoked by `make verify`.

The extension was developed in Codex with GPT-5.6. The corresponding Codex
session ID is supplied in the private Devpost judging field.

## Judge test path

### Hosted

1. Open `/prizes/build-week` on the deployed P42 site.
2. Run **Exact order-4 certificate** and observe `ACCEPTED`, score `0/1`.
3. Run **Lying claimed score** and observe `REJECTED`, score `6/1`.
4. Edit any row or claimed field and run again.

The lab needs no account, wallet, API key, or funds.

### Local

```bash
cd web
npm ci
npm test
npm run dev
```

Then open `http://localhost:3000/build-week`.

## Honest boundary

P42 remains a Phase 0/testnet engineering pilot. The lab demonstrates exact
verification and adversarial rejection; it does not imply that mainnet prize
pools, trustless dispute resolution, or real-money settlement are live. The
canonical production readiness boundary remains `docs/GATE_LEDGER.md`.
