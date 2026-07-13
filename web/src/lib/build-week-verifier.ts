export const BUILD_WEEK_FIXTURES = {
  exact: {
    label: "Exact order-4 certificate",
    solution: { n: 4, rows: ["++++", "+-+-", "++--", "+--+"] },
  },
  partial: {
    label: "Partial progress",
    solution: { n: 4, rows: ["++++", "++++", "++--", "+--+"] },
  },
  lying: {
    label: "Lying claimed score",
    solution: {
      n: 4,
      rows: ["++++", "++++", "++++", "++++"],
      claimed_defect: 0,
      claimed_score: "0/1",
      improvement: "1/1",
    },
  },
} as const;

export type BuildWeekVerdict = {
  valid: boolean;
  reason: string;
  score: string;
  improvement: string;
  details: {
    checked_pairs: number;
    defect: number;
    ignored_claims: string[];
    violations: Array<{ rows: [number, number]; dot: number }>;
  };
};

function gcd(left: number, right: number): number {
  let a = Math.abs(left);
  let b = Math.abs(right);
  while (b !== 0) [a, b] = [b, a % b];
  return a || 1;
}

function rational(numerator: number, denominator: number): string {
  const divisor = gcd(numerator, denominator);
  return `${numerator / divisor}/${denominator / divisor}`;
}

export function verifyHadamardMini(raw: string): BuildWeekVerdict {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("MALFORMED_JSON: the candidate must be valid JSON");
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("MALFORMED: the candidate root must be an object");
  }

  const candidate = parsed as Record<string, unknown>;
  if (candidate.n !== 4) throw new Error("WRONG_ORDER: n must equal 4");
  if (!Array.isArray(candidate.rows) || candidate.rows.length !== 4) {
    throw new Error("WRONG_SHAPE: rows must contain exactly four rows");
  }

  const rows = candidate.rows.map((row, rowIndex) => {
    if (typeof row !== "string" || row.length !== 4) {
      throw new Error(`WRONG_SHAPE: row ${rowIndex} must contain four symbols`);
    }
    return [...row].map((symbol, columnIndex) => {
      if (symbol === "+") return 1;
      if (symbol === "-") return -1;
      throw new Error(`BAD_SYMBOL: row ${rowIndex}, col ${columnIndex} is not '+' or '-'`);
    });
  });

  const violations: BuildWeekVerdict["details"]["violations"] = [];
  for (let left = 0; left < rows.length; left += 1) {
    for (let right = left + 1; right < rows.length; right += 1) {
      const dot = rows[left].reduce((sum, value, column) => sum + value * rows[right][column], 0);
      if (dot !== 0) violations.push({ rows: [left, right], dot });
    }
  }

  const defect = violations.length;
  const improvementNumerator = Math.max(0, 6 - defect);
  const valid = improvementNumerator >= 1;
  const ignoredClaims = Object.keys(candidate).filter((key) => !["n", "rows"].includes(key));

  return {
    valid,
    reason: valid ? "" : "NOT_STRICT_IMPROVEMENT",
    score: `${defect}/1`,
    improvement: rational(improvementNumerator, 6),
    details: {
      checked_pairs: 6,
      defect,
      ignored_claims: ignoredClaims,
      violations,
    },
  };
}
