// Shared helpers for the P42 agent clients (solver + operator).
import { execFileSync } from "node:child_process";

// Rational "improvement" -> integer atoms over a fixed 1e6 denominator.
// Single-solver-safe; solver and operator MUST agree on this scale so the
// operator can detect an inflated claim.
export const IMPROVEMENT_SCALE = 1_000_000n;

export function atomsFromImprovement(improvement) {
  const [num, den = "1"] = String(improvement).split("/");
  return (BigInt(num) * IMPROVEMENT_SCALE) / BigInt(den);
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
