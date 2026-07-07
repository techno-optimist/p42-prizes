export type Direction = "minimize" | "maximize";
export type ProblemStatus = "open" | "pilot" | "locked" | "resolved";
export type SubmissionState = "committed" | "revealed" | "challenged" | "finalized" | "rejected";

export interface DonationWallet {
  chain: "Base Sepolia" | "Base";
  asset: "ETH" | "USDC";
  address: string;
  status: "testnet-only" | "mainnet-gated" | "enabled";
  explorerUrl: string;
  note: string;
}

export interface Problem {
  id: number;
  slug: string;
  repoId: string;
  title: string;
  status: ProblemStatus;
  mode: "construction" | "proof" | "hybrid";
  direction: Direction;
  scoreName: string;
  seedBest: string;
  currentBest: string;
  optimum: string;
  minImprovement: string;
  bountyEth: string;
  challengeWindowHours: number;
  postingBondEth: string;
  challengeBondEth: string;
  verifierVersion: string;
  verifierImage: string;
  verifierCommand: string;
  repoPath: string;
  poolAddress: string | null;
  donationWallet: DonationWallet;
  tagline: string;
  description: string;
  verifierStandard: string[];
  solutionSchema: unknown;
  sampleSolution: unknown;
  baselineAgent?: string;
  baselineSource?: string;
  baselineArtifact?: string;
}

export interface Submission {
  id: string;
  problemId: number;
  problemSlug: string;
  agentName: string;
  state: SubmissionState;
  score: string;
  improvement: string;
  credit: string;
  payoutEth: string;
  solutionCid: string;
  commitHash: string;
  submittedAt: string;
  windowEndsAt: string;
  transcriptCid: string | null;
}

export interface ActivityItem {
  id: string;
  type: "submission" | "challenge" | "funding" | "verifier";
  actor: string;
  problemSlug: string;
  problemTitle: string;
  detail: string;
  ts: string;
}

export interface VerdictReport {
  problem_id: string;
  verifier_version: string;
  verifier_image: string;
  solution_hash: string;
  valid: boolean;
  improvement: string;
  score: string;
  reason: string;
  recomputed_at_commit: string;
  details: Record<string, unknown>;
}
