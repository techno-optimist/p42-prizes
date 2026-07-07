# Mechanism Simulator

`p42_prizes.mechanism` is a small exact arithmetic model of the payout spine:

```text
payout_i = pool_available * improvement_i / sum(improvement_j)
```

It exists to make the red-team invariants executable while the contracts are
still being designed.

Example:

```bash
PYTHONPATH=src python3 -m p42_prizes.cli simulate \
  --pool-wei 1300 \
  --fee-bps 0 \
  --credit alice=6/1 \
  --credit bob=3/1 \
  --credit carol=4/1
```

The result pays Alice `600`, Bob `300`, and Carol `400` wei: exactly their
`6:3:4` share of final frontier distance. No payout is computed against a
temporary denominator.

The model also exposes the red-team guardrails as executable helpers:

- `required_posting_bond(pool_at_submission_wei, alpha_bps, min_bond_wei)`
  fixes the submit bond against the observed pool at commit time.
- `required_finalization_bond(current_entitlement_wei, alpha_bps, ...)` and
  `bond_satisfies_finalization(...)` force a top-up if later funding makes the
  original bond undercollateralized.
- `required_counter_bond(finalizing_entitlement_wei, beta_bps, rerun_cost_wei,
  ...)` prices both challenge-delay value and deterministic rerun cost.
- `required_min_improvement(current_best, optimum, tau_bps, ...)` ratchets the
  threshold from the current remaining gap, not the initial gap.
