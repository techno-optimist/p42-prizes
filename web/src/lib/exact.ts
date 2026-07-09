export function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) {
    const next = x % y;
    x = y;
    y = next;
  }
  return x === 0n ? 1n : x;
}

export interface Rational {
  num: bigint;
  den: bigint;
}

export function rational(num: bigint | number, den: bigint | number = 1): Rational {
  let n = BigInt(num);
  let d = BigInt(den);
  if (d === 0n) throw new Error("denominator cannot be zero");
  if (d < 0n) {
    n = -n;
    d = -d;
  }
  const g = gcd(n, d);
  return { num: n / g, den: d / g };
}

// Canonical rational grammar shared with the Python parser
// (src/p42_prizes/verdict.py): optional ASCII sign, ASCII digits, optional
// `/denominator`. `\d` matches ASCII digits only, so unicode digits, radix
// prefixes ("0x10"), empty strings, and "1/2/3" are all rejected — keeping the
// portal and the verifier in exact agreement about which strings are valid.
const RATIONAL_PATTERN = /^[+-]?\d+(?:\/[+-]?\d+)?$/;

export function parseRational(value: string): Rational {
  if (typeof value !== "string" || !RATIONAL_PATTERN.test(value)) {
    throw new Error(`invalid rational literal: ${JSON.stringify(value)}`);
  }
  const [rawNum, rawDen = "1"] = value.split("/");
  return rational(BigInt(rawNum), BigInt(rawDen));
}

export function rationalToString(value: Rational): string {
  const normalized = rational(value.num, value.den);
  return `${normalized.num}/${normalized.den}`;
}

export function compareRational(left: Rational, right: Rational): number {
  // Normalize denominator signs first: cross-multiplying when a denominator is
  // negative (constructible via a raw {num, den} object literal that skipped
  // rational()) silently inverts the comparison.
  const ln = left.den < 0n ? -left.num : left.num;
  const ld = left.den < 0n ? -left.den : left.den;
  const rn = right.den < 0n ? -right.num : right.num;
  const rd = right.den < 0n ? -right.den : right.den;
  const delta = ln * rd - rn * ld;
  if (delta < 0n) return -1;
  if (delta > 0n) return 1;
  return 0;
}

export function addRational(left: Rational, right: Rational): Rational {
  return rational(left.num * right.den + right.num * left.den, left.den * right.den);
}

export function subtractRational(left: Rational, right: Rational): Rational {
  return rational(left.num * right.den - right.num * left.den, left.den * right.den);
}

export function absRational(value: Rational): Rational {
  return rational(value.num < 0n ? -value.num : value.num, value.den);
}

export function decimalRational(value: string, digits = 3): string {
  const r = parseRational(value);
  const negative = r.num < 0n;
  const abs = negative ? -r.num : r.num;
  const scale = 10n ** BigInt(digits);
  // Round half-up on the last displayed digit instead of truncating.
  const scaled = (abs * scale + r.den / 2n) / r.den;
  const whole = scaled / scale;
  const frac = scaled % scale;
  const fractional = digits > 0 ? `.${frac.toString().padStart(digits, "0")}` : "";
  // Suppress a "-0.000" sign when the rounded magnitude is zero.
  const sign = negative && scaled !== 0n ? "-" : "";
  return `${sign}${whole}${fractional}`;
}
