# SP1 Challenger Transcript-Collision Reproducer

This isolated program executes the partial-chunk alias against the exact
`p3-challenger 0.4.3-succinct` line shipped by SP1 v6.3.1 and current upstream
`main` on 2026-07-26. It demonstrates that transcripts `[7]` and `[7, 0]`
produce the same sponge state and sampled challenge.

Run from the repository root:

```bash
make reproduce-sp1-challenger-collision
```

Expected vulnerable output:

```text
COLLISION: [7] and [7, 0] produce the same sponge state and challenge
```

The lockfile pins the published crates. The downloaded
`p3-challenger-0.4.3-succinct.crate` must have SHA-256
`b6a908924d43e4cfb93fb41c8346cac211b70314385a9037e9241f5b7f3eaf77`.

This is a vulnerability reproducer, not a passing activation gate. A candidate
remediation must make this program fail both equality assertions, then replace
it with inverse no-collision regressions before any ELF, vkey, proof, release,
or launch-authorization regeneration.
