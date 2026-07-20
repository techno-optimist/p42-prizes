import type { ChainProvenance, PortalPoolReadModel, PortalProblemReadModel } from "@/lib/types";

export function publicChainProvenance(provenance: ChainProvenance) {
  return {
    settlementState: provenance.settlementState,
    reconciliationOk: provenance.reconciliationOk,
    source: provenance.source,
    note: provenance.note,
    fundingTargetDeployed: provenance.fundingTargetDeployed === true,
  };
}

export function publicPoolSummary(pool: PortalPoolReadModel | null) {
  if (!pool) return null;
  return {
    totalFundedWei: pool.totalFundedWei,
    totalFundedEth: pool.totalFundedEth,
    accountedBalanceWei: pool.accountedBalanceWei,
    accountedBalanceEth: pool.accountedBalanceEth,
    totalClaimedWei: pool.totalClaimedWei,
    totalClaimedEth: pool.totalClaimedEth,
    totalWinningsDonatedWei: pool.totalWinningsDonatedWei,
    totalWinningsDonatedEth: pool.totalWinningsDonatedEth,
    refundableWei: pool.refundableWei,
    refundableEth: pool.refundableEth,
    totalSponsorRefundedWei: pool.totalSponsorRefundedWei,
    totalFeeAccruedWei: pool.totalFeeAccruedWei,
    totalFeePaidWei: pool.totalFeePaidWei,
    totalResidualPaidWei: pool.totalResidualPaidWei,
    closed: pool.closed,
    closedAt: pool.closedAt,
    claimDeadline: pool.claimDeadline,
    totalCredit: pool.totalCredit,
  };
}

export function publicProblemDetail(problem: PortalProblemReadModel) {
  return {
    id: problem.id,
    slug: problem.slug,
    repoId: problem.repoId,
    title: problem.title,
    status: problem.status,
    mode: problem.mode,
    direction: problem.direction,
    scoreName: problem.scoreName,
    seedBest: problem.seedBest,
    currentBest: problem.currentBest,
    optimum: problem.optimum,
    minImprovement: problem.minImprovement,
    bountyEth: problem.bountyEth,
    challengeWindowHours: problem.challengeWindowHours,
    postingBondEth: problem.postingBondEth,
    challengeBondEth: problem.challengeBondEth,
    verifierVersion: problem.verifierVersion,
    verifierImage: problem.verifierImage,
    verifierCommand: problem.verifierCommand,
    repoPath: problem.repoPath,
    tagline: problem.tagline,
    description: problem.description,
    verifierStandard: problem.verifierStandard,
    solutionSchema: problem.solutionSchema,
    sampleSolution: problem.sampleSolution,
    ...(problem.statement === undefined ? {} : { statement: problem.statement }),
    ...(problem.statementCaveat === undefined ? {} : { statementCaveat: problem.statementCaveat }),
    source: problem.source,
    pool: publicPoolSummary(problem.pool),
    funding: problem.funding,
    chainProvenance: publicChainProvenance(problem.chainProvenance),
  };
}
