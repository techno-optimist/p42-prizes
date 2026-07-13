export type Direction = "minimize" | "maximize";
export type ProblemStatus = "open" | "pilot" | "locked" | "resolved";
export type SubmissionState = "committed" | "revealed" | "challenged" | "finalized" | "rejected";

export interface DonationWallet {
  chain: "Base Sepolia" | "Base";
  asset: "ETH";
  address: string | null;
  status: "not-deployed" | "testnet-only" | "mainnet-gated" | "enabled";
  explorerUrl: string | null;
  note: string;
}

export interface ChainProvenance {
  settlementState: "local-only" | "manifest-pending" | "testnet-indexed" | "mainnet-indexed";
  chain: "Base Sepolia" | "Base";
  chainId: number;
  donationWalletAddress: string | null;
  poolAddress: string | null;
  poolRuntimeCodeHash: string | null;
  deploymentTransactionHash: string | null;
  registryAddress: string | null;
  problemRegistryId: string | null;
  verifierImageHash: string | null;
  admissionMatrixHash: string | null;
  deploymentCommit: string | null;
  indexedThroughBlock: number | null;
  indexedFrontierAtoms?: string | null;
  checkpointBlock?: number | null;
  fundingAuthorizationDigest: string | null;
  activationCompletionDigest: string | null;
  activationFinalizedBlock: number | null;
  reconciliationOk: boolean;
  source: "static-portal-data" | "deployment-manifest" | "indexer" | "indexer-artifacts-v2";
  note: string;
}

export interface Problem {
  /** Stable portal catalog ID. Production registry IDs are cohort positions
   * 1..10 and must be derived from the frozen ordered deployment manifest. */
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
  /** KaTeX display-mode statement of the board's objective. Omitted when the
   * repo does not yet pin a precise statement (e.g. arithmetic-kakeya). */
  statement?: string;
  /** Honest provenance caveat printed under the statement when the exact
   * functional lives in the external problem spec rather than this repo. */
  statementCaveat?: string;
}

export interface Submission {
  id: string;
  problemId: number;
  problemSlug: string;
  agentName: string;
  /** True for seeded walkthrough fixtures. Rendered with an explicit
   * "worked example" label so sample rows can never read as live traction. */
  sample?: boolean;
  source: "local-phase-0" | "chain-p42-v1";
  settlementState: "unsettled" | "finalized" | "ineligible";
  state: SubmissionState;
  score: string;
  improvement: string;
  provisionalImprovement?: string;
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
