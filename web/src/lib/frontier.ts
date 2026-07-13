import {
  absRational,
  compareRational,
  parseRational,
  rational,
  rationalToString,
  subtractRational,
} from "@/lib/exact";
import type { Problem, Submission } from "@/lib/types";

function betterForDirection(problem: Problem, left: string, right: string): string {
  const leftScore = parseRational(left);
  const rightScore = parseRational(right);
  const comparison = compareRational(leftScore, rightScore);
  if (problem.direction === "minimize") return comparison < 0 ? left : right;
  return comparison > 0 ? left : right;
}

function scoreDistance(problem: Problem, fromScore: string, toScore: string) {
  const from = parseRational(fromScore);
  const to = parseRational(toScore);
  return problem.direction === "minimize" ? subtractRational(from, to) : subtractRational(to, from);
}

function normalizationScale(problem: Problem) {
  const seedToOptimum = scoreDistance(problem, problem.seedBest, problem.optimum);
  return compareRational(seedToOptimum, rational(0)) > 0 ? seedToOptimum : rational(1);
}

export function frontierBest(problem: Problem, submissions: Submission[]): string {
  return submissions
    .filter((submission) => (
      submission.problemId === problem.id
      && submission.state === "finalized"
      && submission.source === "chain-p42-v1"
      && submission.settlementState === "finalized"
    ))
    .reduce(
      (best, submission) => betterForDirection(problem, submission.score, best),
      betterForDirection(problem, problem.currentBest, problem.seedBest),
    );
}

export function incrementalFrontierCredit(
  problem: Problem,
  candidateScore: string,
  submissions: Submission[],
): { credit: string; priorBest: string; eligible: boolean } {
  const priorBest = frontierBest(problem, submissions);
  const rawDelta = scoreDistance(problem, priorBest, candidateScore);
  if (compareRational(rawDelta, rational(0)) <= 0) {
    return { credit: "0/1", priorBest, eligible: false };
  }

  const credit = rational(rawDelta.num * normalizationScale(problem).den, rawDelta.den * normalizationScale(problem).num);
  const minImprovement = parseRational(problem.minImprovement);
  const eligible = compareRational(absRational(rawDelta), minImprovement) >= 0;
  return { credit: eligible ? rationalToString(credit) : "0/1", priorBest, eligible };
}
