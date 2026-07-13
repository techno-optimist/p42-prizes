import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { problems } from "@/lib/data";
import { compareRational, parseRational } from "@/lib/exact";
import { frontierBest, incrementalFrontierCredit } from "@/lib/frontier";
import type { Problem, Submission } from "@/lib/types";

type FrontierManifest = {
  problem_id: string;
  objective: {
    seed_best: string;
  };
};

const repoRoot = resolve(process.cwd(), "..");

function readFrontierManifest(problem: Problem): FrontierManifest {
  return parse(
    readFileSync(join(repoRoot, problem.repoPath, "problem.yaml"), "utf8"),
  ) as FrontierManifest;
}

const problem: Problem = {
  id: 42,
  slug: "defect-pilot",
  repoId: "defect-pilot",
  title: "Defect Pilot",
  status: "pilot",
  mode: "construction",
  direction: "minimize",
  scoreName: "defect",
  seedBest: "6/1",
  currentBest: "6/1",
  optimum: "0/1",
  // RAW score units (defects) — the manifest/verifier/contract convention,
  // NOT normalized units. See the "min_improvement raw-unit gate" tests below.
  minImprovement: "1/1",
  bountyEth: "0.00",
  challengeWindowHours: 72,
  postingBondEth: "0.00",
  challengeBondEth: "0.00",
  verifierVersion: "test",
  verifierImage: "sha256:test",
  verifierCommand: "make verify",
  repoPath: "problems/defect-pilot",
  poolAddress: null,
  donationWallet: {
    chain: "Base Sepolia",
    asset: "ETH",
    address: "0x0000000000000000000000000000000000000000",
    status: "testnet-only",
    explorerUrl: "https://sepolia.basescan.org/address/0x0000000000000000000000000000000000000000",
    note: "fixture",
  },
  tagline: "fixture",
  description: "fixture",
  verifierStandard: [],
  solutionSchema: {},
  sampleSolution: {},
};

function submission(score: string, state: Submission["state"] = "finalized"): Submission {
  return {
    id: `sub-${score}`,
    problemId: problem.id,
    problemSlug: problem.slug,
    agentName: "agent",
    source: "chain-p42-v1",
    settlementState: state === "finalized" ? "finalized" : "unsettled",
    state,
    score,
    improvement: "0/1",
    credit: "0/1",
    payoutEth: "0.000",
    solutionCid: "bafy",
    commitHash: "0x" + "1".repeat(64),
    submittedAt: "2026-07-07T00:00:00.000Z",
    windowEndsAt: "2026-07-10T00:00:00.000Z",
    transcriptCid: null,
  };
}

describe("incrementalFrontierCredit", () => {
  it("credits the first strict improvement from the seed", () => {
    expect(incrementalFrontierCredit(problem, "5/1", [])).toEqual({
      credit: "1/6",
      priorBest: "6/1",
      eligible: true,
    });
  });

  it("does not credit duplicates, ties, or worse scores", () => {
    const prior = [submission("5/1")];
    expect(incrementalFrontierCredit(problem, "5/1", prior)).toMatchObject({ credit: "0/1", eligible: false });
    expect(incrementalFrontierCredit(problem, "6/1", prior)).toMatchObject({ credit: "0/1", eligible: false });
  });

  it("credits only the incremental move beyond the current frontier", () => {
    expect(incrementalFrontierCredit(problem, "3/1", [submission("5/1")])).toEqual({
      credit: "1/3",
      priorBest: "5/1",
      eligible: true,
    });
  });

  it("ignores every unsettled or local Phase-0 row", () => {
    const revealed = submission("5/1", "revealed");
    const challenged = submission("4/1", "challenged");
    const localFinalized = {
      ...submission("3/1"),
      source: "local-phase-0" as const,
      settlementState: "unsettled" as const,
    };

    expect(frontierBest(problem, [revealed, challenged, localFinalized])).toBe("6/1");
    expect(incrementalFrontierCredit(problem, "5/1", [revealed, challenged, localFinalized])).toMatchObject({
      priorBest: "6/1",
      credit: "1/6",
      eligible: true,
    });
  });
});

describe("min_improvement raw-unit gate (regression: normalized-vs-raw conflation)", () => {
  // Regression for the unit-mismatch defect: the portal normalized credit by
  // the seed->optimum distance and then compared it against min_improvement,
  // which the manifests, verifiers, and P42SubmissionManager.minImprovementAtoms
  // all express in RAW score units. On any board with scale > 1 a genuinely
  // winning raw improvement of exactly min_improvement was marked ineligible.
  type ObjectiveManifest = {
    problem_id: string;
    objective: {
      direction: "minimize" | "maximize";
      seed_best: string;
      optimum: string;
      min_improvement: string;
    };
  };

  function problemFromManifest(repoPath: string): Problem {
    const manifest = parse(
      readFileSync(join(repoRoot, repoPath, "problem.yaml"), "utf8"),
    ) as ObjectiveManifest;
    return {
      ...problem,
      id: 4242,
      slug: manifest.problem_id,
      repoId: manifest.problem_id,
      repoPath,
      direction: manifest.objective.direction,
      seedBest: manifest.objective.seed_best,
      currentBest: manifest.objective.seed_best,
      optimum: manifest.objective.optimum,
      minImprovement: manifest.objective.min_improvement,
    };
  }

  it("b3-ruler-11-marks: a raw improvement of exactly min_improvement is eligible", () => {
    // seed 445/1, optimum 310/1 (scale 135), min_improvement 1/1: a 444 ruler
    // is a genuine record and must be eligible even though its normalized
    // credit is 1/135 < 1.
    const b3 = problemFromManifest("problems/b3-ruler-11-marks");
    const result = incrementalFrontierCredit(b3, "444/1", []);
    expect(result.eligible).toBe(true);
    expect(result.credit).toBe("1/135");
    expect(result.priorBest).toBe("445/1");
  });

  it("b3-ruler-11-marks: matching the seed is not an improvement", () => {
    const b3 = problemFromManifest("problems/b3-ruler-11-marks");
    expect(incrementalFrontierCredit(b3, "445/1", [])).toMatchObject({
      credit: "0/1",
      eligible: false,
    });
  });

  it.each([
    "problems/q6-intersecting-hypergraph",
    "problems/distinct-subset-sums-a11",
    "problems/b3-subset-first-jump-9",
  ] as const)("%s: raw delta of exactly min_improvement is eligible", (repoPath) => {
    const p = problemFromManifest(repoPath);
    const seed = parseRational(p.seedBest);
    const step = parseRational(p.minImprovement);
    const candidate = p.direction === "minimize"
      ? `${seed.num * step.den - step.num * seed.den}/${seed.den * step.den}`
      : `${seed.num * step.den + step.num * seed.den}/${seed.den * step.den}`;
    expect(incrementalFrontierCredit(p, candidate, []).eligible).toBe(true);
  });

  it("gates in raw units, not normalized units", () => {
    // min_improvement 2 raw units on the toy board (scale 6): a raw delta of 1
    // must be ineligible, a raw delta of 2 eligible with normalized display
    // credit 2/6 = 1/3. Under the old normalized gate with these numbers a
    // delta of 1 (credit 1/6 < 2) and a delta of 2 (credit 1/3 < 2) would BOTH
    // have been rejected — including the genuinely winning one.
    const strict: Problem = { ...problem, minImprovement: "2/1" };
    expect(incrementalFrontierCredit(strict, "5/1", [])).toMatchObject({ eligible: false, credit: "0/1" });
    expect(incrementalFrontierCredit(strict, "4/1", [])).toMatchObject({ eligible: true, credit: "1/3" });
  });
});

describe("problem anchor invariants", () => {
  // A seed that is strictly better than the published record makes the launch
  // frontier start at (or past) the record, so no submission can ever be
  // credited. Every board's seedBest must be no better than its currentBest.
  it.each(problems.map((p) => [p.slug, p] as const))("%s: seed is not better than currentBest", (_slug, p) => {
    const seed = parseRational(p.seedBest);
    const current = parseRational(p.currentBest);
    const cmp = compareRational(seed, current);
    if (p.direction === "minimize") {
      expect(cmp).toBeGreaterThanOrEqual(0); // seed >= current (higher is worse)
    } else {
      expect(cmp).toBeLessThanOrEqual(0); // seed <= current (lower is worse)
    }
    // The launch frontier must equal the published record, not something better.
    expect(frontierBest(p, [])).toBe(p.currentBest);
  });

  it.each(problems.filter((p) => p.status === "locked").map((p) => [p.slug, p] as const))(
    "%s: locked board model starts at its manifest frontier",
    (_slug, p) => {
      expect(p.seedBest).toBe(p.currentBest);
    },
  );
});

describe("manifest-backed portal frontier baselines", () => {
  it.each(problems.map((p) => [p.slug, p] as const))(
    "%s: portal seed matches its canonical problem manifest",
    (_slug, p) => {
      const manifest = readFrontierManifest(p);

      expect(p.repoId).toBe(manifest.problem_id);
      expect(p.seedBest).toBe(manifest.objective.seed_best);
      if (p.status === "locked") {
        expect(p.currentBest).toBe(manifest.objective.seed_best);
      }
    },
  );

  it("PNT begins at the certified manifest frontier and awards the seed witness no credit", () => {
    const pnt = problems.find((p) => p.slug === "pnt-sparse-mertens-construction");
    expect(pnt).toBeDefined();
    if (!pnt) return;

    const manifest = readFrontierManifest(pnt);
    expect(pnt.seedBest).toBe(manifest.objective.seed_best);
    expect(pnt.currentBest).toBe(manifest.objective.seed_best);
    expect(frontierBest(pnt, [])).toBe(manifest.objective.seed_best);
    expect(incrementalFrontierCredit(pnt, manifest.objective.seed_best, [])).toEqual({
      credit: "0/1",
      priorBest: manifest.objective.seed_best,
      eligible: false,
    });
  });
});
