# SP1 v6.1 Challenger Transcript-Collision Reproducer

This isolated program executes the partial-chunk alias against the exact
`p3-challenger 0.3.2-succinct` crate locked by P42's SP1 `v6.1.0` objective
workspaces. It demonstrates that transcripts `[7]` and `[7, 0]` produce the
same sponge state and sampled challenge.

Run from the repository root:

```bash
make reproduce-sp1-challenger-collision
```

Expected vulnerable output:

```text
COLLISION: [7] and [7, 0] produce the same sponge state and challenge
```

This is a vulnerability reproducer, not a passing activation gate. A candidate
remediation must make both the SP1 v6.1 and current-upstream reproducers fail
their equality assertions, then replace them with inverse no-collision
regressions before any ELF, vkey, proof, release, or launch-authorization
regeneration.
