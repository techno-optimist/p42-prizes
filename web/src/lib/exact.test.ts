import { describe, expect, it } from "vitest";
import { addRational, compareRational, parseRational, rationalToString } from "@/lib/exact";

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
});

