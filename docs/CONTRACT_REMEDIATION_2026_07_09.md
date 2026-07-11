# Contract Remediation - Second Acceptance Pass

**Status:** Local source remediated and regression-tested. External audit,
canonical deployment, bytecode reconciliation, and the verifiable-resolver gate
remain open.

## Closed In Local Source

- Full-precision 512-bit `mulDiv` is used for payout, fee, posting-bond, and
  challenge-bond arithmetic. Cumulative credit is explicitly bounded below
  `2^255`; over-bound recorder calls fail with a named error.
- Resolver decisions are rejected at or after the active dispute deadline, and
  their full fraud delay must fit inside the immutable cumulative settlement
  horizon.
- Governance mutations require the higher override threshold. A delayed swap
  of one lost signer may use the base threshold only with independent guardian
  approval for that exact operation, preventing a base quorum from replacing
  the remaining honest signer and manufacturing override control.
- Commits have an immutable reveal expiry. Exact duplicate CIDs are assigned to
  the lowest submission ID that reveals before expiry, so a later copied reveal
  cannot take credit even when it is mined first.
- Every deposit rechecks that the frozen registry still maps the configured
  problem ID to the exact receiving pool.
- `voidFinalize` refuses to run while any submission is Revealed or Challenged;
  explicit lifecycle counters preserve this guard without an unbounded scan.
- Constructor sessions, `setSessionKey`, and explicit session policies all have
  a maximum 30-day lifetime.

## Open Residual

The resolver remains trusted. Solidity checks identity, timing, transcript and
verdict anchors, and bonded delay, but does not verify the transcript's
execution or the owner's slash-proof hash. This is an explicit testnet-only
trust bridge, not a closed oracle finding. Real-value settlement remains gated
on a verifiable/fraud-proof resolver, external contract audit, canonical
deployment, and exact bytecode/evidence reconciliation.
