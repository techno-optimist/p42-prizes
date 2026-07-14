import { chainProvenanceForProblem } from "@/lib/chain-provenance";
import { launchProblems } from "@/lib/data";
import { compareRational, parseRational, rational, rationalToString } from "@/lib/exact";
import { keccak256, toUtf8Bytes } from "ethers";
import {
  loadActivatedIndexerSnapshot,
  type ActivatedIndexerSnapshot,
} from "@/lib/indexer-provenance";
import { allSubmissionsShared } from "@/lib/portal-state";
import type {
  Direction,
  PortalActiveChallenge,
  PortalFundingReadModel,
  PortalPoolReadModel,
  PortalProblemReadModel,
  PortalProvenanceLog,
  PortalReadModel,
  PortalClaimantReadModel,
  Problem,
  Submission,
  SubmissionState,
} from "@/lib/types";

type JsonObject = Record<string, unknown>;

function object(value: unknown, label: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonObject;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function integerString(value: unknown, label: string, unsigned = false): string {
  if (typeof value !== "string" || !(unsigned ? /^(0|[1-9][0-9]*)$/ : /^(0|-?[1-9][0-9]*)$/).test(value)) {
    throw new Error(`${label} must be a canonical integer string`);
  }
  return value;
}

function atomsToRational(atoms: unknown, scale: string, label: string): string {
  const value = integerString(atoms, label);
  return rationalToString(rational(BigInt(value), BigInt(scale)));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const record = value as JsonObject;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, canonicalize(record[key])]));
  }
  return value;
}

function equalRational(left: string, right: string): boolean {
  return compareRational(parseRational(left), parseRational(right)) === 0;
}

function weiToEth(wei: string): string {
  const value = BigInt(integerString(wei, "wei amount", true));
  const whole = value / 10n ** 18n;
  const fraction = (value % 10n ** 18n).toString().padStart(18, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function secondsString(value: unknown, label: string): string {
  if (Number.isSafeInteger(value) && Number(value) >= 0) return String(value);
  return integerString(value, label, true);
}

function unixSecondsToIso(value: unknown, label: string): string {
  const seconds = BigInt(secondsString(value, label));
  if (seconds > BigInt(Math.floor(8.64e15 / 1000))) throw new Error(`${label} is outside the ISO date range`);
  return new Date(Number(seconds) * 1000).toISOString();
}

function provenanceLog(value: unknown): PortalProvenanceLog {
  const log = object(value, "projection provenance log");
  return {
    source: String(log.source),
    eventName: String(log.eventName),
    contractAddress: String(log.contractAddress),
    blockNumber: Number(log.blockNumber),
    blockHash: String(log.blockHash),
    transactionHash: String(log.transactionHash),
    transactionIndex: Number(log.transactionIndex),
    logIndex: Number(log.logIndex),
    blockTimestamp: integerString(log.blockTimestamp, "provenance block timestamp", true),
  };
}

function activeChallenge(value: unknown): PortalActiveChallenge | null {
  if (value === null) return null;
  const challenge = object(value, "active challenge");
  const challengeBondWei = integerString(challenge.challengeBondWei, "challenge bond", true);
  return {
    challenger: String(challenge.challenger).toLowerCase(),
    reasonHash: String(challenge.reasonHash),
    challengeBondWei,
    challengeBondEth: weiToEth(challengeBondWei),
    challengedAt: unixSecondsToIso(challenge.challengedAt, "challenge timestamp"),
    disputeEndsAt: unixSecondsToIso(challenge.disputeEndsAt, "challenge dispute end"),
    resolved: challenge.resolved === true,
    decisionPending: challenge.decisionPending === true,
    challengerWins: challenge.challengerWins === true,
    transcriptHash: String(challenge.transcriptHash),
    transcriptUri: String(challenge.transcriptURI),
    verdictHash: String(challenge.verdictHash),
  };
}

function submissionState(status: unknown): SubmissionState {
  switch (status) {
    case "Committed": return "committed";
    case "Revealed": return "revealed";
    case "Challenged": return "challenged";
    case "Finalized": return "finalized";
    case "Rejected":
    case "Voided": return "rejected";
    default: throw new Error(`unsupported projected submission status ${String(status)}`);
  }
}

function poolReadModel(projection: JsonObject, scale: string): PortalPoolReadModel {
  const pool = object(projection.pool, "portal projection pool");
  const close = object(projection.ledgerClose, "portal projection ledger close");
  const totalFundedWei = integerString(pool.totalFundedWei, "pool total funded", true);
  const accountedBalanceWei = integerString(pool.accountedBalanceWei, "pool accounted balance", true);
  const totalClaimedWei = integerString(pool.totalClaimedWei, "pool total claimed", true);
  const totalWinningsDonatedWei = integerString(pool.totalWinningsDonatedWei, "pool winnings donated", true);
  const refundableWei = integerString(pool.refundableWei, "pool refundable", true);
  return {
    totalFundedWei,
    totalFundedEth: weiToEth(totalFundedWei),
    accountedBalanceWei,
    accountedBalanceEth: weiToEth(accountedBalanceWei),
    totalClaimedWei,
    totalClaimedEth: weiToEth(totalClaimedWei),
    totalWinningsDonatedWei,
    totalWinningsDonatedEth: weiToEth(totalWinningsDonatedWei),
    refundableWei,
    refundableEth: weiToEth(refundableWei),
    totalSponsorRefundedWei: integerString(pool.totalSponsorRefundedWei, "pool sponsor refunded", true),
    totalFeeAccruedWei: integerString(pool.totalFeeAccruedWei, "pool fee accrued", true),
    totalFeePaidWei: integerString(pool.totalFeePaidWei, "pool fee paid", true),
    totalResidualPaidWei: integerString(pool.totalResidualPaidWei, "pool residual paid", true),
    sponsors: array(pool.sponsors, "pool sponsors").map((value) => {
      const sponsor = object(value, "pool sponsor");
      const principalWei = integerString(sponsor.principalWei, "sponsor principal", true);
      return { sponsor: String(sponsor.sponsor).toLowerCase(), principalWei, principalEth: weiToEth(principalWei) };
    }),
    sponsorshipFundings: array(pool.sponsorshipFundings, "sponsorship fundings").map((value) => {
      const funding = object(value, "sponsorship funding");
      const amountWei = integerString(funding.amountWei, "sponsorship amount", true);
      return {
        transactionHash: String(funding.transactionHash),
        payer: String(funding.payer).toLowerCase(),
        sponsor: String(funding.sponsor).toLowerCase(),
        amountWei,
        amountEth: weiToEth(amountWei),
      };
    }),
    winningsDonations: array(pool.winningsDonations, "winnings donations").map((value) => {
      const donation = object(value, "winnings donation");
      const grossAmountWei = integerString(donation.grossAmountWei, "donation gross amount", true);
      const donatedAmountWei = integerString(donation.donatedAmountWei, "donated amount", true);
      const feeAmountWei = integerString(donation.feeAmountWei, "donation fee", true);
      return {
        transactionHash: String(donation.transactionHash),
        solver: String(donation.solver).toLowerCase(),
        destinationPool: String(donation.destinationPool).toLowerCase(),
        grossAmountWei,
        grossAmountEth: weiToEth(grossAmountWei),
        donatedAmountWei,
        donatedAmountEth: weiToEth(donatedAmountWei),
        feeAmountWei,
        feeAmountEth: weiToEth(feeAmountWei),
      };
    }),
    closed: close.closed === true,
    closedAt: close.closedAt === "0" ? null : unixSecondsToIso(close.closedAt, "ledger close timestamp"),
    claimDeadline: close.claimDeadline === "0" ? null : unixSecondsToIso(close.claimDeadline, "claim deadline"),
    totalCredit: atomsToRational(close.totalCreditAtoms, scale, "ledger total credit atoms"),
  };
}

function fundingReadModel(projection: JsonObject, closed: boolean): PortalFundingReadModel {
  const funding = object(projection.funding, "portal projection funding");
  const authorizationExpiresAt = integerString(funding.authorizationExpiresAt, "funding authorization expiry", true);
  const acceptingFunds = funding.acceptingFunds === true;
  const fundingArmed = funding.fundingArmed === true;
  const ledgerPausedNewActions = funding.ledgerPausedNewActions === true;
  const submissionsPausedNewActions = funding.submissionsPausedNewActions === true;
  const submissionsPausedAll = funding.submissionsPausedAll === true;
  const challengesPausedNewActions = funding.challengesPausedNewActions === true;
  return {
    acceptingFunds,
    fundingArmed,
    authorizationExpiresAt: unixSecondsToIso(authorizationExpiresAt, "funding authorization expiry"),
    ledgerPausedNewActions,
    submissionsPausedNewActions,
    submissionsPausedAll,
    challengesPausedNewActions,
    canFund: !closed && fundingArmed && acceptingFunds,
    canSubmit: !closed && fundingArmed && !ledgerPausedNewActions && !submissionsPausedNewActions && !submissionsPausedAll,
    canChallenge: !closed && !challengesPausedNewActions && !submissionsPausedAll,
  };
}

function claimantReadModels(projection: JsonObject, scale: string): PortalClaimantReadModel[] {
  return array(projection.solvers, "portal projection solvers").map((value) => {
    const solver = object(value, "portal claimant");
    const claimedWei = integerString(solver.claimedWei, "claimant claimed amount", true);
    const finalEntitlementWei = integerString(solver.finalEntitlementWei, "claimant final entitlement", true);
    const submissionBondWei = integerString(solver.submissionBondWei, "claimant submission bond", true);
    const challengeBondWei = integerString(solver.challengeBondWei, "claimant challenge bond", true);
    const withdrawableBondWei = integerString(solver.withdrawableBondWei, "claimant withdrawable bond", true);
    return {
      claimant: String(solver.solver).toLowerCase(),
      credit: atomsToRational(solver.creditAtoms, scale, "claimant credit atoms"),
      claimedWei,
      claimedEth: weiToEth(claimedWei),
      finalEntitlementWei,
      finalEntitlementEth: weiToEth(finalEntitlementWei),
      submissionBondWei,
      submissionBondEth: weiToEth(submissionBondWei),
      challengeBondWei,
      challengeBondEth: weiToEth(challengeBondWei),
      withdrawableBondWei,
      withdrawableBondEth: weiToEth(withdrawableBondWei),
    };
  });
}

function projectedSubmission(
  problem: Problem,
  registryId: string,
  scale: string,
  value: unknown,
): Submission {
  const row = object(value, "portal projection submission");
  const state = submissionState(row.status);
  const currentCredit = integerString(row.creditAtoms, "live credit atoms", true);
  if (row.status === "Voided" && currentCredit !== "0") throw new Error("voided submission has nonzero live credit");
  const logs = array(row.sourceLogs, "submission source logs").map(provenanceLog);
  const committed = logs.find((log) => log.source === "submissions" && log.eventName === "Committed");
  if (!committed) throw new Error("projected submission is missing its committed provenance log");
  const submittedSeconds = row.revealedAt === "0" ? row.committedAt : row.revealedAt;
  const submittedAt = unixSecondsToIso(submittedSeconds, "submission timestamp");
  const windowEndsAt = unixSecondsToIso(row.challengeEndsAt, "submission challenge end");
  const solverAddress = String(row.solver).toLowerCase();
  const challenge = activeChallenge(row.activeChallenge);
  return {
    id: `chain:${registryId}:${integerString(row.submissionId, "submission id", true)}`,
    problemId: problem.id,
    problemSlug: problem.slug,
    agentName: solverAddress,
    solverAddress,
    source: "chain-p42-v1",
    settlementState: state === "finalized" ? "finalized" : state === "rejected" ? "ineligible" : "unsettled",
    state,
    score: atomsToRational(row.claimedScoreAtoms, scale, "claimed score atoms"),
    improvement: atomsToRational(row.improvementAtoms, scale, "improvement atoms"),
    credit: atomsToRational(currentCredit, scale, "credit atoms"),
    originalCredit: atomsToRational(row.originalCreditAtoms, scale, "original credit atoms"),
    activeChallenge: challenge,
    payoutEth: "0",
    solutionCid: String(row.solutionCid),
    commitHash: committed.transactionHash,
    submittedAt,
    windowEndsAt,
    transcriptCid: challenge?.transcriptUri || null,
    provenanceLogs: logs,
  };
}

export function portalReadModelFromActivatedSnapshot(
  problems: readonly Problem[],
  snapshot: ActivatedIndexerSnapshot,
): PortalReadModel {
  if (problems.length !== 10) throw new Error("chain portal read model requires the exact-ten cohort");
  const manifest = snapshot.manifest;
  const checkpoint = snapshot.checkpoint;
  if (checkpoint.schema !== "p42-prizes/indexer-checkpoint/v3") {
    throw new Error("chain portal read model requires indexer checkpoint v3");
  }
  const manifestProblems = array(manifest.problems, "manifest problems");
  const boards = array(checkpoint.boards, "checkpoint boards");
  if (manifestProblems.length !== 10 || boards.length !== 10 || snapshot.provenance.size !== 10) {
    throw new Error("chain portal read model requires all ten activated boards");
  }

  const submissions: Submission[] = [];
  const replayEvents: Record<string, { digest: string; total: number }> = {};
  const readProblems: PortalProblemReadModel[] = problems.map((problem, index) => {
    const manifestProblem = object(manifestProblems[index], `manifest problem ${index + 1}`);
    const board = object(boards[index], `checkpoint board ${index + 1}`);
    const registryId = String(index + 1);
    if (manifestProblem.problemId !== registryId || board.problemId !== registryId
      || manifestProblem.problemSlug !== problem.slug || board.problemSlug !== problem.slug) {
      throw new Error(`portal cohort binding mismatch at position ${registryId}`);
    }
    const provenance = snapshot.provenance.get(problem.slug);
    if (!provenance || provenance.problemRegistryId !== registryId || !provenance.reconciliationOk) {
      throw new Error(`activated provenance is incomplete for ${problem.slug}`);
    }
    const objective = object(manifestProblem.certifiedObjective, "certified objective");
    const direction = objective.direction as Direction;
    const scale = integerString(manifestProblem.scoreAtomScale, "score atom scale", true);
    if (BigInt(scale) <= 0n || direction !== problem.direction
      || !equalRational(String(objective.seedBest), problem.seedBest)
      || !equalRational(String(objective.minImprovement), problem.minImprovement)
      || !equalRational(atomsToRational(manifestProblem.seedScoreAtoms, scale, "seed score atoms"), problem.seedBest)) {
      throw new Error(`portal objective binding mismatch for ${problem.slug}`);
    }
    const projection = object(board.portalProjection, "board portal projection");
    if (projection.schema !== "p42-prizes/portal-projection/v2") throw new Error("unsupported portal projection schema");
    const frontier = object(projection.frontier, "portal projection frontier");
    const onchain = object(board.onchain, "checkpoint board onchain state");
    if (frontier.currentAtoms !== onchain.bestScoreAtoms) throw new Error("portal projection frontier mismatch");
    const events = object(board.events, "checkpoint board events");
    const eventProvenance = object(projection.eventProvenance, "portal projection event provenance");
    if (eventProvenance.replayEventsDigest !== events.digest || eventProvenance.total !== events.total) {
      throw new Error("portal projection event provenance mismatch");
    }
    const eventLogs = array(eventProvenance.logs, "portal projection provenance logs");
    for (const value of eventLogs) {
      const log = object(value, "portal projection provenance log");
      const args = object(log.args, "portal projection provenance args");
      const expectedDigest = keccak256(toUtf8Bytes(JSON.stringify(canonicalize(args))));
      if (log.argsDigest !== expectedDigest) throw new Error("portal projection provenance args digest mismatch");
    }
    replayEvents[problem.slug] = { digest: String(events.digest), total: Number(events.total) };
    submissions.push(...array(projection.submissions, "portal projection submissions")
      .map((row) => projectedSubmission(problem, registryId, scale, row)));
    const pool = poolReadModel(projection, scale);
    const checkpointTimestamp = secondsString(object(checkpoint.range, "checkpoint range").toBlockTimestamp, "checkpoint timestamp");
    const funding = fundingReadModel(projection, pool.closed);
    return {
      ...problem,
      status: pool.closed ? "resolved" : "open",
      currentBest: atomsToRational(frontier.currentAtoms, scale, "frontier atoms"),
      bountyEth: pool.totalFundedEth,
      poolAddress: provenance.poolAddress,
      donationWallet: {
        ...problem.donationWallet,
        chain: provenance.chain,
        address: funding.canFund ? provenance.poolAddress : null,
        status: funding.canFund
          ? provenance.chain === "Base" ? "enabled" : "testnet-only"
          : pool.closed ? "closed" : "paused",
        explorerUrl: null,
        note: funding.canFund
          ? "Chain-derived funding target from the activated P42 checkpoint."
          : "The chain pool is not currently actionable for funding.",
      },
      source: "chain-p42-v1",
      chainProvenance: provenance,
      pool,
      funding,
      claimants: claimantReadModels(projection, scale),
    };
  });

  const firstProvenance = readProblems[0].chainProvenance;
  const range = object(checkpoint.range, "checkpoint range");
  return {
    source: "chain-p42-v1",
    problems: readProblems,
    submissions,
    provenance: {
      source: "chain-p42-v1",
      deploymentCommit: firstProvenance.deploymentCommit,
      checkpointBlock: firstProvenance.checkpointBlock ?? null,
      checkpointTimestamp: unixSecondsToIso(range.toBlockTimestamp, "checkpoint timestamp"),
      activationCompletionDigest: firstProvenance.activationCompletionDigest,
      replayEvents,
      note: "All ten rows derive from one activated, freshly attested P42 checkpoint generation.",
    },
  };
}

export function localPortalReadModel(
  problems: readonly Problem[],
  rows: readonly Submission[],
  note: string,
): PortalReadModel {
  const localSubmissions = rows.filter((row) => row.source === "local-phase-0");
  return {
    source: "local-phase-0",
    problems: problems.map((problem) => ({
      ...problem,
      source: "local-phase-0",
      chainProvenance: chainProvenanceForProblem(problem),
      pool: null,
      funding: null,
      claimants: [],
    })),
    submissions: localSubmissions,
    provenance: {
      source: "local-phase-0",
      deploymentCommit: null,
      checkpointBlock: null,
      checkpointTimestamp: null,
      activationCompletionDigest: null,
      replayEvents: {},
      note,
    },
  };
}

export function resolvePortalReadModel(
  problems: readonly Problem[],
  snapshot: ActivatedIndexerSnapshot | null,
  localRows: readonly Submission[],
): PortalReadModel {
  if (!snapshot) {
    return localPortalReadModel(
      problems,
      localRows,
      "The exact-ten activated v3 artifact gate did not pass; serving local-only rows.",
    );
  }
  try {
    return portalReadModelFromActivatedSnapshot(problems, snapshot);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "invalid chain projection";
    return localPortalReadModel(problems, localRows, `Chain projection rejected (${reason}); serving local-only rows.`);
  }
}

export async function loadPortalReadModel(
  problems: readonly Problem[] = launchProblems,
): Promise<PortalReadModel> {
  const snapshot = loadActivatedIndexerSnapshot(problems);
  if (!snapshot) {
    const model = resolvePortalReadModel(problems, null, await allSubmissionsShared());
    console.info("p42.portal.read-model", model.provenance);
    return model;
  }
  const chainCandidate = resolvePortalReadModel(problems, snapshot, []);
  const model = chainCandidate.source === "chain-p42-v1"
    ? chainCandidate
    : resolvePortalReadModel(problems, snapshot, await allSubmissionsShared());
  console.info("p42.portal.read-model", model.provenance);
  return model;
}
