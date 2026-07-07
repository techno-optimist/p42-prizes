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

export function parseRational(value: string): Rational {
  const [rawNum, rawDen = "1"] = value.split("/");
  return rational(BigInt(rawNum), BigInt(rawDen));
}

export function rationalToString(value: Rational): string {
  const normalized = rational(value.num, value.den);
  return `${normalized.num}/${normalized.den}`;
}

export function compareRational(left: Rational, right: Rational): number {
  const delta = left.num * right.den - right.num * left.den;
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
  const sign = r.num < 0n ? "-" : "";
  const abs = r.num < 0n ? -r.num : r.num;
  const whole = abs / r.den;
  const scale = 10n ** BigInt(digits);
  const frac = (abs % r.den) * scale / r.den;
  return `${sign}${whole}.${frac.toString().padStart(digits, "0")}`;
}
