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

