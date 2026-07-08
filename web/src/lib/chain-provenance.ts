import type { ChainProvenance, Problem } from "@/lib/types";

export function chainProvenanceForProblem(problem: Problem): ChainProvenance {
  return {
    settlementState: "local-only",
    chain: "Base Sepolia",
    chainId: 84532,
    donationWalletAddress: problem.donationWallet.address,
    poolAddress: null,
    registryAddress: null,
    problemRegistryId: null,
    verifierImageHash: problem.verifierImage.startsWith("sha256:") ? problem.verifierImage : null,
    admissionMatrixHash: null,
    deploymentCommit: null,
    indexedThroughBlock: null,
    reconciliationOk: false,
    source: "static-portal-data",
    note:
      "Phase 0 portal state only: no deployed registry manifest or indexer reconciliation is attached to this problem yet.",
  };
}
