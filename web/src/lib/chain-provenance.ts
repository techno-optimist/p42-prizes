import type { ChainProvenance, DonationWallet, Problem } from "@/lib/types";
import { loadIndexerProvenance } from "@/lib/indexer-provenance";

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const HASH = /^0x[a-fA-F0-9]{64}$/;
const COMMIT = /^[a-fA-F0-9]{40}$/;
const SYNTHETIC_P42_PLACEHOLDER = /^0x42420{32}[a-fA-F0-9]{4}$/;

export interface DonationTarget {
  address: string;
  asset: "ETH";
  chain: "Base Sepolia" | "Base";
  chainId: number;
  explorerUrl: string;
  walletUri: string;
}

export function chainProvenanceForProblem(problem: Problem): ChainProvenance {
  return loadIndexerProvenance(problem);
}

export function localOnlyChainProvenance(problem: Problem): ChainProvenance {
  return {
    settlementState: "local-only",
    chain: "Base Sepolia",
    chainId: 84532,
    donationWalletAddress: null,
    poolAddress: null,
    poolRuntimeCodeHash: null,
    deploymentTransactionHash: null,
    registryAddress: null,
    problemRegistryId: null,
    verifierImageHash: problem.verifierImage.startsWith("sha256:") ? problem.verifierImage : null,
    admissionMatrixHash: null,
    deploymentCommit: null,
    indexedThroughBlock: null,
    indexedFrontierBlock: null,
    checkpointBlock: null,
    reconciliationOk: false,
    source: "static-portal-data",
    note:
      "Phase 0 portal state only: no deployed registry manifest or indexer reconciliation is attached to this problem yet.",
  };
}

function nonzeroHash(value: string | null): value is string {
  return value !== null && HASH.test(value) && !/^0x0{64}$/i.test(value);
}

export function validatedDonationTarget(provenance: ChainProvenance): DonationTarget | null {
  const address = provenance.poolAddress;
  if (
    provenance.settlementState !== "testnet-indexed"
    && provenance.settlementState !== "mainnet-indexed"
  ) return null;
  const chainMatches = (
    provenance.chain === "Base Sepolia"
    && provenance.chainId === 84532
    && provenance.settlementState === "testnet-indexed"
  ) || (
    provenance.chain === "Base"
    && provenance.chainId === 8453
    && provenance.settlementState === "mainnet-indexed"
  );
  if (!chainMatches) return null;
  if (provenance.source === "static-portal-data" || !provenance.reconciliationOk) return null;
  if (
    !address
    || !ADDRESS.test(address)
    || SYNTHETIC_P42_PLACEHOLDER.test(address)
    || provenance.donationWalletAddress?.toLowerCase() !== address.toLowerCase()
  ) {
    return null;
  }
  if (!nonzeroHash(provenance.poolRuntimeCodeHash) || !nonzeroHash(provenance.deploymentTransactionHash)) return null;
  if (!provenance.registryAddress || !ADDRESS.test(provenance.registryAddress) || !provenance.problemRegistryId) return null;
  if (!provenance.deploymentCommit || !COMMIT.test(provenance.deploymentCommit)) return null;
  if (provenance.indexedThroughBlock === null || provenance.indexedThroughBlock < 0) return null;

  const explorerBase = provenance.chain === "Base"
    ? "https://basescan.org"
    : "https://sepolia.basescan.org";
  return {
    address,
    asset: "ETH",
    chain: provenance.chain,
    chainId: provenance.chainId,
    explorerUrl: `${explorerBase}/address/${address}`,
    walletUri: `ethereum:${address}@${provenance.chainId}`,
  };
}

/**
 * Return a transfer target only when both the reconciled chain evidence and
 * the per-problem funding policy agree that it is publishable. Raw portal
 * metadata is never sufficient to instruct a donor where to send funds.
 */
export function publishedDonationTarget(
  wallet: DonationWallet,
  provenance: ChainProvenance,
): DonationTarget | null {
  const target = validatedDonationTarget(provenance);
  if (!target) return null;
  if (
    wallet.chain !== target.chain
    || wallet.asset !== target.asset
    || wallet.address?.toLowerCase() !== target.address.toLowerCase()
  ) return null;

  const statusAllowsTarget = target.chain === "Base"
    ? wallet.status === "enabled"
    : wallet.status === "testnet-only";
  return statusAllowsTarget ? target : null;
}

/** Return public funding metadata without exposing an unverified address. */
export function publicDonationWallet(
  wallet: DonationWallet,
  provenance: ChainProvenance,
): DonationWallet {
  const target = publishedDonationTarget(wallet, provenance);
  return {
    ...wallet,
    address: target?.address ?? null,
    explorerUrl: target?.explorerUrl ?? null,
  };
}
