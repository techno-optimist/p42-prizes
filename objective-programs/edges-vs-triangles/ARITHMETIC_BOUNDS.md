# Edges Objective Arithmetic Bounds

The guest scales every row to integer coordinates `x/10^6` and `y/10^9`.
For twenty entries in `0..1000` summing to `1000`:

- `sum2 <= 10^6` and `sum3 <= 10^9`;
- `x_numerator = 10^6 - sum2` is in `0..10^6`;
- `y_numerator = 10^9 - 3000*sum2 + 2*sum3` is in `0..10^9`.

`AREA_SCALE = 6*10^18` is a common denominator for every Python
`segment_area` branch. Each segment is at most its width, the sorted widths
sum to one, and the max-gap penalty is at most ten. Therefore:

- `area_scaled <= 6*10^18`;
- `total_scaled <= 66*10^18`;
- `ceil(total_scaled/6) <= 11*10^18`, so the direction-normalized maximize
  score atom fits in `i128` and is encoded as the positive signed ABI `int256`
  word `ceil((-raw_score)*10^18)`;
- the minimum-improvement denominator `10^12` divides `AREA_SCALE`, so the
  comparison is reduced before multiplication; the largest remaining seed
  product is below `2.5*10^35`, while `u128::MAX` is approximately
  `3.4*10^38`.

Every multiplication, addition, subtraction, conversion, and division in the
guest is nevertheless checked and fails closed. These bounds make bigint
arithmetic unnecessary.
