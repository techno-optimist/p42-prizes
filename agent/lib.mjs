// Shared helpers for the P42 agent clients (solver + operator).
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

// Rational "improvement" -> integer atoms over a fixed 1e6 denominator.
// Single-solver-safe; solver and operator MUST agree on this scale so the
// operator can detect an inflated claim.
// NOTE: since the absolute-score frontier landed (audit F1/F6), improvementAtoms
// is informational only — the payout credit is driven by claimedScoreAtoms
// (see atomsFromScore / SCORE_SCALE below), whose 1e18 scale is fine enough for
// every problem's MIN_IMPROVEMENT (the 1e6 scale here was a million x too coarse).
export const IMPROVEMENT_SCALE = 1_000_000n;

export function atomsFromImprovement(improvement) {
  const [num, den = "1"] = String(improvement).split("/");
  return (BigInt(num) * IMPROVEMENT_SCALE) / BigInt(den);
}

// SHARED FIXED-POINT CONVENTION (must match P42SubmissionManager.SCORE_ATOM_SCALE
// and the deploy scripts): every verifier reports an ABSOLUTE minimization score
// (lower is better) as an exact rational; on chain it is encoded as
//   score_atoms = ceil(score * SCORE_SCALE)   (int256)
// CEIL means the score is never under-reported, so the marginal credit
// (previous bestScoreAtoms - new score_atoms) is never over-stated —
// conservative on the money side. For integer scores the encoding is exact.
export const SCORE_SCALE = 1_000_000_000_000_000_000n; // 1e18

// Parse an exact rational string "num/den" (den optional, default 1) into a
// normalized {num, den} with den > 0.
function parseRational(value) {
  const text = String(value).trim();
  const [numStr, denStr = "1"] = text.split("/");
  let num = BigInt(numStr);
  let den = BigInt(denStr);
  if (den === 0n) throw new Error(`rational ${text} has a zero denominator`);
  if (den < 0n) { num = -num; den = -den; }
  return { num, den };
}

// ceil(score_num * SCORE_SCALE / score_den) as a BigInt — the exact ceiling of
// the scaled rational (works for negative scores too: BigInt division truncates
// toward zero, which for negatives IS the ceiling).
export function atomsFromScore(score) {
  const { num, den } = parseRational(score);
  const scaled = num * SCORE_SCALE;
  let q = scaled / den;
  if (scaled % den !== 0n && scaled > 0n) q += 1n;
  return q;
}

// The on-chain frontier is a MINIMIZATION frontier (lower atoms win). Problems
// whose native objective is `maximize` (problem.yaml objective.direction) are
// mapped by negation so both directions share one on-chain convention. ceil of
// the negated rational rounds a maximize score DOWN — still conservative.
export function chainScoreAtoms(score, direction = "minimize") {
  if (direction !== "minimize" && direction !== "maximize") {
    throw new Error(`unknown objective direction: ${direction}`);
  }
  if (direction === "minimize") return atomsFromScore(score);
  const { num, den } = parseRational(score);
  return atomsFromScore(`${-num}/${den}`);
}

// Minimal problem.yaml probe for the fields the agents need. The manifest
// schema is flat enough that a line-oriented parse is exact; no YAML dep.
export function problemObjective(problemDir) {
  // Fail CLOSED: the direction decides whether a score is negated onto the
  // minimization frontier, and the solver + operator SHARE this helper. A silent
  // "minimize" default on an unreadable/renamed manifest would make a maximize
  // problem's claim wrongly beat the frontier AND make the operator compute the
  // same wrong truth (so it would not flag it). Throw instead of guessing (audit
  // F1 review).
  let text = "";
  try {
    text = readFileSync(`${problemDir}/problem.yaml`, "utf8");
  } catch (e) {
    throw new Error(`problemObjective: cannot read ${problemDir}/problem.yaml: ${e.message}`);
  }
  const direction = /^\s*direction:\s*(minimize|maximize)\s*$/m.exec(text)?.[1];
  if (!direction) throw new Error(`problemObjective: no 'direction: minimize|maximize' in ${problemDir}/problem.yaml`);
  const seedScore =
    /^\s*seed_score:\s*"?(-?\d+(?:\/\d+)?)"?\s*$/m.exec(text)?.[1] ??
    /^\s*seed_best:\s*"?(-?\d+(?:\/\d+)?)"?\s*$/m.exec(text)?.[1] ??
    null;
  return { direction, seedScore };
}

// Run the problem's exact verifier on a solution file and return the parsed
// VerdictReport. The verifier exits 1 on an invalid solution but still prints
// the canonical report to stdout, so capture stdout on a non-zero exit too.
export function runVerifier(problemDir, solutionPath, repoRoot) {
  let out;
  try {
    out = execFileSync("python3", [`${problemDir}/verifier/verify.py`, "--solution", solutionPath], {
      encoding: "utf8",
      env: { ...process.env, PYTHONPATH: `${repoRoot}/src` },
    });
  } catch (e) {
    out = e.stdout || "";
  }
  const line = out.trim();
  if (!line) throw new Error("verifier produced no VerdictReport");
  return JSON.parse(line);
}
