# Devpost submission packet — OpenAI Build Week 2026

This is the paste-ready submission packet for P42 Prizes. It is intentionally
conservative about what is live: the public portal and verifier lab work; the
money path remains testnet/Phase 0 and real funding is gated.

## Project overview

**Project name**  
Erdős's briefcase, rebuilt as protocol

**Elevator pitch**  
P42 turns open math problems into public, exact, rerunnable verifier challenges—so humans and AI agents can advance the frontier without trusting a leaderboard.

**Category**  
Developer Tools

**Repository**  
https://github.com/techno-optimist/p42-prizes

**Hosted judge path after deployment**  
https://projectforty2.ai/prizes/build-week

**Codex session ID**  
`019f5d0b-2643-7d63-81fd-16e8dc7c2f1e`

**Built with tags**  
Codex, GPT-5.6, TypeScript, React, Next.js, Python, Solidity, Base, Z3,
exact-arithmetic, verifiers

## About the project

### Inspiration

Paul Erdős carried prize checks in a briefcase. He posed an open problem,
attached a number to it, and paid when a proof held. The proof was the protocol.

P42 Prizes asks what that protocol should become when humans and AI agents can
both produce frontier mathematical claims. A fluent answer is not enough. A
score is not enough. The trust layer must be public, exact, deterministic, and
rerunnable by a stranger.

### What it does

P42 packages an open problem with a public verifier. The verifier reconstructs
the score from raw witness data instead of trusting the submitter's claimed
answer. The broader repository includes an agent API, commit-reveal mechanics,
bonded challenge work, testnet contracts, and an explicit production gate
ledger.

For Build Week we added a zero-setup Verifier Lab. A judge can load a valid
order-4 Hadamard certificate, edit it, or select a malicious fixture that claims
a perfect score. The browser lab recomputes all six row-pair dot products using
integers. The lying claim is rejected because claimed fields never decide the
verdict.

The lab is an exact-integer mirror of the verifier's mathematical core. The
authoritative path remains the strict, bounded `make verify` runner in the
repository.

### How we built it with Codex and GPT-5.6

P42 existed before the submission period, so we documented the boundary
explicitly. During the eligible window, Codex with GPT-5.6 helped us:

- audit the official rules and the existing Devpost draft;
- identify a judge-testing gap in the pre-existing developer tool;
- design and implement the interactive verifier lab;
- write adversarial fixtures and four focused tests;
- run the full 225-test web suite and a production base-path build;
- compare the browser result against the authoritative Python verifier; and
- rewrite submission claims so testnet evidence is never presented as live
  mainnet settlement.

The repository's dated history also includes meaningful post-window work on an
independent resolver signer and permissionless objective fraud-proof machinery.
The submission evaluates the new work while retaining the earlier P42 system as
context.

### Challenges

The hardest problem was not drawing a green checkmark. It was defining what the
checkmark is allowed to mean. We had to separate search from certification,
claimed scores from recomputed scores, browser demonstration from settlement
authority, and testnet evidence from production readiness.

The adversarial fixture captures the core failure mode: it declares defect zero
while repeating the same row four times. A leaderboard that trusts the claim
would accept it. P42 recomputes six nonzero dot products and rejects it.

### What we are proud of

- A judge can understand and attack the core idea in under a minute.
- The demo needs no account, wallet, API key, or funds.
- The same valid and lying witnesses produce matching mathematical verdicts in
  the browser lab and authoritative Python verifier.
- The public story states the boundary plainly: Phase 0, testnet, real funding
  gated.

### What is next

We will keep hardening the verifier runner, publish immutable verifier images,
complete independent review and governance gates, and only then consider real
funding. P42's target is an open settlement layer for verified frontier
progress. This submission demonstrates the smallest load-bearing piece: the
claim does not win; the re-run does.

## Judge testing instructions

Hosted path:

1. Open `https://projectforty2.ai/prizes/build-week`.
2. Select **Exact order-4 certificate** and run the verifier. Expect
   `ACCEPTED`, score `0/1`, improvement `1/1`.
3. Select **Lying claimed score** and run the verifier. Expect `REJECTED`, score
   `6/1`, improvement `0/1`, with all claimed fields listed as ignored.
4. Edit a row or any claimed field and run it again.

Local path:

```bash
git clone https://github.com/techno-optimist/p42-prizes.git
cd p42-prizes/web
npm ci
npm test
npm run dev
```

Open `http://localhost:3000/build-week`.

Supported platforms: current desktop and mobile browsers for the lab; macOS,
Linux, or Windows with Node.js 24 for the local web path; Python 3.11+ and GNU
Make for the authoritative verifier CLI.

## Demo video script — target 2:35

**0:00–0:15 — Hook**  
“An AI can announce a beautiful mathematical result in seconds. P42 asks the
harder question: can a stranger verify it without trusting the AI—or us?”

**0:15–0:35 — Product and boundary**  
Show the P42 register and Build Week page. Explain that P42 is a pre-existing
Phase 0/testnet developer tool and the Verifier Lab is the new Build Week judge
path.

**0:35–1:05 — Valid certificate**  
Load the exact order-4 fixture. Point to the four rows, run the verifier, and
show six checked pairs, defect `0`, and `ACCEPTED`.

**1:05–1:35 — Adversarial rejection**  
Load the lying fixture. Point out its claimed defect `0` and claimed score
`0/1`; run it; show recomputed defect `6`, ignored claims, and `REJECTED`.

**1:35–1:55 — Source and tests**  
Show the pure TypeScript verifier, its tests, and the authoritative Python
`make verify` path. Mention the full 225-test web suite and production base-path
build.

**1:55–2:20 — Codex and GPT-5.6**  
Show the Codex task. Explain that GPT-5.6 helped audit the rules, identify the
judge-testing gap, implement the lab, write adversarial tests, and police the
boundary between testnet evidence and production claims.

**2:20–2:35 — Close**  
“P42's idea is simple: the claim does not win; the re-run does. Erdős's
briefcase, rebuilt as a protocol anyone can inspect.”

## Remaining launch checklist

- [ ] Choose submitter type: Individual, Team of Individuals, or Organization.
- [ ] Add every teammate and have each invitation accepted.
- [ ] Choose and add a repository license, or make the repository private and
      share it with `testing@devpost.com` and `build-week-event@openai.com`.
- [ ] Commit and deploy the Build Week lab; verify the hosted URL anonymously.
- [ ] Record, upload, and verify the public YouTube demo under three minutes.
- [ ] Paste the fields above into Devpost and save the draft.
- [ ] Review the Official Rules and check the agreement box.
- [ ] Submit before July 21, 2026 at 5:00 PM Pacific.
