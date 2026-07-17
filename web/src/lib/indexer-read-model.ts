import { chainProvenanceForProblem } from "@/lib/chain-provenance";
import { launchProblems } from "@/lib/data";
import { compareRational, parseRational, rational, rationalToString } from "@/lib/exact";
import { keccak256, toUtf8Bytes } from "ethers";
import {
  loadActivatedIndexerSnapshot,
  type ActivatedIndexerSnapshot,
} from "@/lib/indexer-provenance";
import { enforceIndexerCheckpointHighWater } from "@/lib/indexer-high-water";
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

const DEFAULT_CHECKPOINT_MAX_AGE_SECONDS = 300;
const CHECKPOINT_FUTURE_TOLERANCE_SECONDS = 30;
const FUNDING_WINDOW_BEFORE_CLOSE_SECONDS = 30n * 24n * 60n * 60n;
const SCORE_ATOM_SCALE = 10n ** 18n;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export interface PortalReadModelClock {
  nowSeconds?: number;
  checkpointMaxAgeSeconds?: number;
}

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

function scoreAtomsToRational(atoms: unknown, scale: string, direction: Direction, label: string): string {
  const value = BigInt(integerString(atoms, label));
  return rationalToString(rational(direction === "maximize" ? -value : value, BigInt(scale)));
}

function chainAtomsForScore(score: string, scale: string, direction: Direction): string {
  const value = parseRational(score);
  const scaled = (direction === "maximize" ? -value.num : value.num) * BigInt(scale);
  let quotient = scaled / value.den;
  if (scaled > 0n && scaled % value.den !== 0n) quotient += 1n;
  return quotient.toString();
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
    case "Rejected": return "rejected";
    case "Voided": return "voided";
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

function fundingReadModel(
  projection: JsonObject,
  onchain: JsonObject,
  pool: PortalPoolReadModel,
  fundingCapWei: string,
  closed: boolean,
  fundingDeadline: bigint,
  finalizedTimestamp: number,
  effectiveTimestamp: number,
): PortalFundingReadModel {
  const funding = object(projection.funding, "portal projection funding");
  const authorizationExpiresAt = integerString(funding.authorizationExpiresAt, "funding authorization expiry", true);
  const onchainAuthorizationExpiresAt = integerString(
    onchain.fundingAuthorizationExpiresAt,
    "onchain funding authorization expiry",
    true,
  );
  if (authorizationExpiresAt !== onchainAuthorizationExpiresAt
    || funding.acceptingFunds !== onchain.poolAcceptingFunds
    || funding.fundingArmed !== onchain.fundingArmed) {
    throw new Error("portal projection funding state mismatch");
  }
  const acceptingFunds = funding.acceptingFunds === true;
  const fundingArmed = funding.fundingArmed === true;
  const ledgerPausedNewActions = funding.ledgerPausedNewActions === true;
  const submissionsPausedNewActions = funding.submissionsPausedNewActions === true;
  const submissionsPausedAll = funding.submissionsPausedAll === true;
  const challengesPausedNewActions = funding.challengesPausedNewActions === true;
  const cap = BigInt(fundingCapWei);
  const accountedBalance = BigInt(pool.accountedBalanceWei);
  if (accountedBalance > cap) throw new Error("pool accounted balance exceeds funding cap");
  const remainingFundingCapWei = (cap - accountedBalance).toString();
  const authorizationExpired = BigInt(effectiveTimestamp) > BigInt(authorizationExpiresAt);
  const fundingDeadlineReached = BigInt(effectiveTimestamp) >= fundingDeadline;
  return {
    acceptingFunds,
    fundingArmed,
    authorizationExpiresAt: unixSecondsToIso(authorizationExpiresAt, "funding authorization expiry"),
    authorizationExpired,
    fundingCapWei,
    remainingFundingCapWei,
    fundingDeadline: unixSecondsToIso(fundingDeadline.toString(), "funding deadline"),
    fundingDeadlineReached,
    finalizedObservedAt: unixSecondsToIso(finalizedTimestamp, "funding finalized observation timestamp"),
    publicationObservedAt: unixSecondsToIso(effectiveTimestamp, "funding publication observation timestamp"),
    ledgerPausedNewActions,
    submissionsPausedNewActions,
    submissionsPausedAll,
    challengesPausedNewActions,
    canFund: !closed && !authorizationExpired && !fundingDeadlineReached
      && remainingFundingCapWei !== "0" && fundingArmed && acceptingFunds,
    canSubmit: !closed && fundingArmed && !ledgerPausedNewActions && !submissionsPausedNewActions && !submissionsPausedAll,
    canChallenge: !closed && !challengesPausedNewActions && !submissionsPausedAll,
  };
}

function publicFundingProvenance(
  provenance: PortalProblemReadModel["chainProvenance"],
  canFund: boolean,
): PortalProblemReadModel["chainProvenance"] {
  const fundingTargetDeployed = normalizedAddress(provenance.poolAddress) !== null
    && normalizedAddress(provenance.donationWalletAddress) === normalizedAddress(provenance.poolAddress);
  const publicProvenance = {
    ...provenance,
    fundingTargetDeployed,
  };
  return canFund ? publicProvenance : {
    ...publicProvenance,
    donationWalletAddress: null,
    poolAddress: null,
  };
}

function normalizedAddress(value: unknown): string | null {
  return typeof value === "string" && EVM_ADDRESS.test(value) ? value.toLowerCase() : null;
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
  seedScoreAtoms: string,
  currentScoreAtoms: string,
  direction: Direction,
  value: unknown,
): Submission | null {
  const row = object(value, "portal projection submission");
  const state = submissionState(row.status);
  const currentCredit = integerString(row.creditAtoms, "live credit atoms", true);
  if (row.status === "Voided" && currentCredit !== "0") throw new Error("voided submission has nonzero live credit");
  const claimedScoreAtoms = integerString(row.claimedScoreAtoms, "claimed score atoms");
  const advisoryImprovementAtoms = integerString(row.improvementAtoms, "improvement atoms", true);
  const corroboratedImprovementAtoms = BigInt(seedScoreAtoms) - BigInt(claimedScoreAtoms);
  if (corroboratedImprovementAtoms <= 0n
    || advisoryImprovementAtoms !== corroboratedImprovementAtoms.toString()
    || (state === "finalized" && BigInt(claimedScoreAtoms) < BigInt(currentScoreAtoms))) {
    return null;
  }
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
    settlementState: state === "finalized" ? "finalized" : ["rejected", "voided"].includes(state) ? "ineligible" : "unsettled",
    state,
    score: scoreAtomsToRational(claimedScoreAtoms, scale, direction, "claimed score atoms"),
    improvement: atomsToRational(corroboratedImprovementAtoms.toString(), SCORE_ATOM_SCALE.toString(), "corroborated improvement atoms"),
    provisionalImprovement: atomsToRational(corroboratedImprovementAtoms.toString(), SCORE_ATOM_SCALE.toString(), "corroborated improvement atoms"),
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
  clock: PortalReadModelClock = {},
): PortalReadModel {
  if (problems.length !== 10) throw new Error("chain portal read model requires the exact-ten cohort");
  const manifest = snapshot.manifest;
  const checkpoint = snapshot.checkpoint;
  const nowSeconds = clock.nowSeconds ?? Math.floor(Date.now() / 1000);
  const checkpointMaxAgeSeconds = clock.checkpointMaxAgeSeconds ?? DEFAULT_CHECKPOINT_MAX_AGE_SECONDS;
  if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) throw new Error("portal authoritative timestamp is invalid");
  if (!Number.isSafeInteger(checkpointMaxAgeSeconds) || checkpointMaxAgeSeconds < 1 || checkpointMaxAgeSeconds > 300) {
    throw new Error("portal checkpoint max age is invalid");
  }
  if (checkpoint.schema !== "p42-prizes/indexer-checkpoint/v4") {
    throw new Error("chain portal read model requires activation-bound indexer checkpoint v4");
  }
  const manifestProblems = array(manifest.problems, "manifest problems");
  const boards = array(checkpoint.boards, "checkpoint boards");
  if (manifestProblems.length !== 10 || boards.length !== 10 || snapshot.provenance.size !== 10) {
    throw new Error("chain portal read model requires all ten activated boards");
  }
  const range = object(checkpoint.range, "checkpoint range");
  const checkpointTimestamp = Number(secondsString(range.toBlockTimestamp, "checkpoint timestamp"));
  if (!Number.isSafeInteger(checkpointTimestamp)
    || checkpointTimestamp > nowSeconds + CHECKPOINT_FUTURE_TOLERANCE_SECONDS
    || nowSeconds - checkpointTimestamp > checkpointMaxAgeSeconds) {
    throw new Error("chain portal read model requires a fresh checkpoint timestamp");
  }
  const effectiveTimestamp = Math.max(nowSeconds, checkpointTimestamp);

  const submissions: Submission[] = [];
  const replayEvents: Record<string, { digest: string; total: number }> = {};
  const projectedProblems: PortalProblemReadModel[] = problems.map((problem, index) => {
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
    if (scale !== SCORE_ATOM_SCALE.toString() || direction !== problem.direction
      || !equalRational(String(objective.seedBest), problem.seedBest)
      || !equalRational(String(objective.minImprovement), problem.minImprovement)
      || chainAtomsForScore(problem.seedBest, scale, direction) !== integerString(manifestProblem.seedScoreAtoms, "seed score atoms")) {
      throw new Error(`portal objective binding mismatch for ${problem.slug}`);
    }
    const projection = object(board.portalProjection, "board portal projection");
    if (projection.schema !== "p42-prizes/portal-projection/v2") throw new Error("unsupported portal projection schema");
    const replayConfig = object(projection.replayConfig, "portal projection replay config");
    const fundingCapWei = integerString(manifestProblem.fundingCapWei, "manifest funding cap", true);
    const projectedFundingCapWei = integerString(replayConfig.fundingCapWei, "projected funding cap", true);
    if (fundingCapWei === "0" || projectedFundingCapWei !== fundingCapWei) {
      throw new Error("portal funding cap binding mismatch");
    }
    const closeByTimestamp = BigInt(integerString(replayConfig.closeByTimestamp, "close-by timestamp", true));
    if (closeByTimestamp < FUNDING_WINDOW_BEFORE_CLOSE_SECONDS) {
      throw new Error("close-by timestamp cannot encode the canonical funding deadline");
    }
    const fundingDeadline = closeByTimestamp - FUNDING_WINDOW_BEFORE_CLOSE_SECONDS;
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
      .map((row) => projectedSubmission(
        problem,
        registryId,
        scale,
        integerString(manifestProblem.seedScoreAtoms, "seed score atoms"),
        integerString(frontier.currentAtoms, "frontier atoms"),
        direction,
        row,
      ))
      .filter((row): row is Submission => row !== null));
    const pool = poolReadModel(projection, scale);
    const funding = fundingReadModel(
      projection,
      onchain,
      pool,
      fundingCapWei,
      pool.closed,
      fundingDeadline,
      checkpointTimestamp,
      effectiveTimestamp,
    );
    return {
      ...problem,
      status: pool.closed ? "resolved" : "open",
      currentBest: scoreAtomsToRational(frontier.currentAtoms, scale, direction, "frontier atoms"),
      bountyEth: pool.totalFundedEth,
      poolAddress: funding.canFund ? provenance.poolAddress : null,
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
          : funding.authorizationExpired
            ? `The portal stops publishing funding targets after authorization expiry at ${funding.authorizationExpiresAt}.`
            : funding.remainingFundingCapWei === "0"
              ? "The pool has no remaining funding capacity at the finalized observation."
              : funding.fundingDeadlineReached
                ? `The portal conservatively stops publishing funding targets at ${funding.fundingDeadline}; the contract funding function rejects transactions after that timestamp.`
                : "The chain pool is not currently actionable for funding.",
      },
      source: "chain-p42-v1",
      chainProvenance: provenance,
      pool,
      funding,
      claimants: claimantReadModels(projection, scale),
    };
  });

  const actionablePoolAddresses = new Set(projectedProblems.flatMap((problem) => {
    const address = normalizedAddress(problem.chainProvenance.poolAddress);
    return problem.funding?.canFund && address ? [address] : [];
  }));
  const readProblems = projectedProblems.map((problem): PortalProblemReadModel => ({
    ...problem,
    chainProvenance: publicFundingProvenance(problem.chainProvenance, problem.funding?.canFund === true),
    pool: problem.pool && {
      ...problem.pool,
      winningsDonations: problem.pool.winningsDonations.map((donation) => {
        const destinationPool = normalizedAddress(donation.destinationPool);
        return {
          ...donation,
          destinationPool: destinationPool && actionablePoolAddresses.has(destinationPool)
            ? destinationPool
            : null,
        };
      }),
    },
  }));

  const firstProvenance = readProblems[0].chainProvenance;
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
  clock: PortalReadModelClock = {},
): PortalReadModel {
  if (!snapshot) {
    return localPortalReadModel(
      problems,
      localRows,
      "The exact-ten activation-bound v4 artifact gate did not pass; serving local-only rows.",
    );
  }
  try {
    return portalReadModelFromActivatedSnapshot(problems, snapshot, clock);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "invalid chain projection";
    return localPortalReadModel(problems, localRows, `Chain projection rejected (${reason}); serving local-only rows.`);
  }
}

export async function gateActivatedPortalReadModel(
  problems: readonly Problem[],
  snapshot: ActivatedIndexerSnapshot,
  chainCandidate: PortalReadModel,
): Promise<PortalReadModel> {
  if (chainCandidate.source !== "chain-p42-v1") return chainCandidate;
  try {
    await enforceIndexerCheckpointHighWater(snapshot);
    return chainCandidate;
  } catch (error) {
    const reason = error instanceof Error ? error.message : "durable checkpoint gate failure";
    return localPortalReadModel(
      problems,
      [],
      `Durable checkpoint high-water gate rejected (${reason}); serving local-only rows.`,
    );
  }
}

export async function loadPortalReadModel(
  problems: readonly Problem[] = launchProblems,
): Promise<PortalReadModel> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const snapshot = loadActivatedIndexerSnapshot(problems);
  if (!snapshot) {
    const model = resolvePortalReadModel(problems, null, await allSubmissionsShared(), { nowSeconds });
    console.info("p42.portal.read-model", model.provenance);
    return model;
  }
  const chainCandidate = resolvePortalReadModel(problems, snapshot, [], { nowSeconds });
  const model = chainCandidate.source === "chain-p42-v1"
    ? await gateActivatedPortalReadModel(problems, snapshot, chainCandidate)
    : resolvePortalReadModel(problems, snapshot, await allSubmissionsShared(), { nowSeconds });
  console.info("p42.portal.read-model", model.provenance);
  return model;
}
