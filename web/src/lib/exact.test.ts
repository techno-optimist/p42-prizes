import { describe, expect, it } from "vitest";
import { addRational, compareRational, decimalRational, parseRational, rationalToString } from "@/lib/exact";

describe("exact rational helpers", () => {
  it("normalizes rationals", () => {
    expect(rationalToString(parseRational("6/12"))).toBe("1/2");
  });

  it("compares without floating point", () => {
    expect(compareRational(parseRational("1/3"), parseRational("2/7"))).toBe(1);
  });

  it("adds exact improvement credits", () => {
    expect(rationalToString(addRational(parseRational("1/6"), parseRational("5/6")))).toBe("1/1");
  });

  // These strings parse in JS's lenient BigInt but must be rejected so the
  // portal and the Python verifier agree on which literals are valid.
  it.each(["", "/2", "1/2/3", "0x10", "0b101", "1_0/2", "١/٢", "5/0", " 1/2"])(
    "rejects malformed rational %j",
    (bad) => {
      expect(() => parseRational(bad)).toThrow();
    },
  );

  it("does not invert comparison for negative-denominator rationals", () => {
    // {num:1, den:-2} == -1/2, which is less than 1/2.
    expect(compareRational({ num: 1n, den: -2n }, parseRational("1/2"))).toBe(-1);
  });

  it("rounds decimals half-up and avoids negative zero", () => {
    expect(decimalRational("2/3", 3)).toBe("0.667");
    expect(decimalRational("-1/1000000", 3)).toBe("0.000");
  });
});

