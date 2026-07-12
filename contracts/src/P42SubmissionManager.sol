// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {P42Math} from "./P42Math.sol";

interface IP42PoolBalance {
    function funded() external view returns (uint256);
    function fundingCap() external view returns (uint256);
}

interface IP42CreditLedger {
    function recordCredit(address solver, uint256 atoms) external;
    function voidCredit(address solver, uint256 atoms) external;
    function provisionalEntitlement(address solver, uint256 additionalAtoms) external view returns (uint256);
    function closed() external view returns (bool);
    function fundingDeadline() external view returns (uint64);
}

/// @notice Commit/reveal/finalize scaffold for the Phase 1 testnet path.
/// It makes the verifier-adjacent economic invariants executable before the
/// full fraud-proof resolver lands.
contract P42SubmissionManager {
    error P42_NOT_OWNER();
    error P42_PAUSED_NEW_ACTIONS();
    error P42_PAUSED_ALL();
    error P42_NOT_PAUSED_ALL();
    error P42_PAUSED_ALL_RECOVERY_OPEN(uint64 recoveryAt, uint64 nowAt);
    error P42_PAUSED_ALL_REARM_OPEN(uint64 rearmAt, uint64 nowAt);
    error P42_FUNDING_ALREADY_ARMED();
    error P42_FUNDING_AUTHORIZATION_ZERO();
    error P42_FUNDING_AUTHORIZATION_EXPIRED(uint64 expiresAt, uint64 nowAt);
    error P42_NOT_FUNDING_AUTHORIZER();
    error P42_FUNDING_AUTHORIZATION_MISMATCH(bytes32 expected, bytes32 actual);
    error P42_OPEN_WITNESS_WINDOW_OPEN(uint64 armNotBefore, uint64 nowAt);
    error P42_VOID_NOT_ADVANCE(int256 prevBestScoreAtoms, int256 claimedScoreAtoms);
    error P42_VOID_NOT_FRONTIER(int256 bestScoreAtoms, int256 claimedScoreAtoms);
    error P42_BAD_ALPHA();
    error P42_BAD_WINDOW();
    error P42_EMPTY_COMMITMENT();
    error P42_EMPTY_DA_HASH();
    error P42_LEDGER_CLOSED();
    error P42_SUBMISSION_WINDOW_CLOSED(uint64 fundingDeadline, uint64 nowAt);
    error P42_LEDGER_NOT_CLOSED();
    error P42_COMMIT_NOT_MATURE(uint256 eligibleBlock, uint256 currentBlock);
    error P42_COMMIT_EXPIRED(uint64 expiresAt, uint64 nowAt);
    error P42_EMPTY_SOLUTION_CID();
    error P42_BAD_COMMITMENT_REVEAL();
    error P42_NOT_SOLVER();
    error P42_NOT_CHALLENGE_MANAGER();
    error P42_CHALLENGE_MANAGER_ALREADY_SET();
    error P42_BAD_SUBMISSION_STATUS(SubmissionStatus expected, SubmissionStatus actual);
    error P42_NOT_STRICT_IMPROVEMENT(int256 bestScoreAtoms, int256 claimedScoreAtoms);
    error P42_SCORE_ATOMS_OUT_OF_RANGE(int256 scoreAtoms);
    error P42_CHALLENGE_WINDOW_OPEN(uint64 endsAt, uint64 nowAt);
    error P42_CHALLENGE_WINDOW_CLOSED(uint64 endsAt, uint64 nowAt);
    error P42_REVEAL_WINDOW_OPEN(uint64 endsAt, uint64 nowAt);
    error P42_PERMANENCE_GRACE_OPEN(uint64 endsAt, uint64 nowAt);
    error P42_EMPTY_SOLUTION_BYTES();
    error P42_SOLUTION_TOO_LARGE(uint256 cap, uint256 got);
    error P42_SOLUTION_HASH_MISMATCH(bytes32 expected, bytes32 got);
    error P42_UNEXPECTED_ONCHAIN_BYTES();
    error P42_BAD_ONCHAIN_DA_CONFIG();
    error P42_INSUFFICIENT_POSTING_BOND(uint256 required, uint256 received);
    error P42_UNKNOWN_SUBMISSION();
    error P42_BOND_UNDERCOVERS_ENTITLEMENT(uint256 required, uint256 posted);
    error P42_NO_BOND_TO_CLAIM();
    error P42_NO_FINALIZED_BOND();
    error P42_ACTIVE_REVEALS_OR_CHALLENGES(uint256 revealed, uint256 challenged);
    error P42_TRANSFER_FAILED();

    uint16 public constant MAX_ALPHA_BPS = 10_000;
    uint64 public constant MIN_COMMIT_AGE_BLOCKS = 1;
    uint64 public constant MAX_CUMULATIVE_DISPUTE_WINDOWS = 3;
    uint64 public constant MAX_CHALLENGE_WINDOW_SECONDS = 30 days;
    /// @notice A continuous full-pause may not block settlement indefinitely.
    /// Governance has this fixed interval to investigate and, when needed,
    /// call voidFinalize before anyone can resume normal settlement.
    uint64 public constant PAUSED_ALL_RECOVERY_DELAY = 30 days;
    /// @notice Every credit-bearing finalize remains reversible for this full
    /// interval before the ledger may snapshot claims. It is deliberately no
    /// shorter than the permissionless full-pause recovery interval.
    uint64 public constant CREDIT_FINALIZE_RECOVERY_DELAY = PAUSED_ALL_RECOVERY_DELAY;

    /// @notice Hard ceiling on on-chain solution bytes, bounding reveal-tx
    /// calldata gas. Problems whose certificates exceed this (e.g. the
    /// autoconvolution class at multi-MB) deploy with `onchainDa=false` and
    /// keep the bytes in a content-addressed off-chain store gated by the same
    /// on-chain sha256 anchor (`commitDaHash`).
    uint256 public constant MAX_ONCHAIN_SOLUTION_BYTES = 1_048_576; // 1 MiB

    /// @notice Shared fixed-point convention for absolute scores. Verifiers
    /// report an exact rational minimization score (lower is better: a defect
    /// count, a bound value, ...) and every off-chain component encodes it as
    /// score_atoms = ceil(score * SCORE_ATOM_SCALE). CEIL means a score is
    /// never under-reported, so the on-chain marginal credit is never
    /// over-stated (conservative on the payout side); for integer scores the
    /// encoding is exact. The contract itself only compares and subtracts
    /// atoms — the scale is anchored here so all components agree on one
    /// quantization (fine enough for every problem's MIN_IMPROVEMENT).
    uint256 public constant SCORE_ATOM_SCALE = 1e18;

    /// @dev Seeds and claims are confined to (-2^254, 2^254) so any frontier
    /// marginal (bestScoreAtoms - claimedScoreAtoms) always fits in
    /// int256/uint256. Without this bound, a griefing claim near
    /// type(int256).min would make finalize / pendingCreditAtoms /
    /// disputedEntitlementWei panic on checked subtraction, poisoning the
    /// submission into an unfinalizable, unchallengeable state.
    int256 internal constant MIN_SCORE_ATOMS_BOUND = -(2 ** 254);
    int256 internal constant MAX_SCORE_ATOMS_BOUND = 2 ** 254;

    enum SubmissionStatus {
        None,
        Committed,
        Revealed,
        Challenged,
        Finalized,
        Rejected,
        /// A Finalized submission whose frontier advance + ledger credit were
        /// reversed by governance recovery (`voidFinalize`). Appended LAST so
        /// every pre-existing status keeps its numeric value.
        Voided
    }

    /// @notice Frontier snapshot stored at finalization (poisoned-frontier
    /// recovery). `prevBestScoreAtoms` is the live frontier the submission
    /// finalized against; `creditAtoms` is the marginal credit it earned
    /// (0 when superseded, and ALWAYS 0 for open-phase finalizes — witness
    /// postings advance the frontier unpaid). Together they let `voidFinalize`
    /// reverse exactly this finalization — restore the frontier and void any
    /// credit — with no governance-chosen numbers.
    struct FinalizeInfo {
        int256 prevBestScoreAtoms;
        uint256 creditAtoms;
        uint64 prevCreditRecoveryEndsAt;
    }

    struct Submission {
        address solver;
        bytes32 commitment;
        bytes32 commitDaHash;
        uint256 bondWei;
        uint256 poolAtSubmissionWei;
        uint256 requiredBondWei;
        /// Advisory display-only figure supplied at reveal. NEVER drives
        /// payout: credit is derived from claimedScoreAtoms vs the live
        /// frontier at finalization (F1).
        uint256 improvementAtoms;
        /// The submission's ABSOLUTE score in atoms (lower is better).
        int256 claimedScoreAtoms;
        string solutionCid;
        bytes32 permanenceHash;
        uint64 committedAt;
        uint64 revealedAt;
        uint64 challengeEndsAt;
        SubmissionStatus status;
    }

    address public immutable owner;
    address public immutable treasury;
    address public immutable fundingAuthorizer;
    IP42PoolBalance public immutable pool;
    IP42CreditLedger public immutable ledger;
    uint16 public immutable alphaBps;
    uint256 public immutable minPostingBondWei;
    uint64 public immutable challengeWindowSeconds;
    /// @notice Deployment time and the earliest time at which funding may be
    /// armed. The unpaid phase always lasts at least one full configured
    /// challenge window, so the public has a protocol-enforced chance to post
    /// and inspect frontier witnesses before ETH can enter the pool.
    uint64 public immutable deployedAt;
    uint64 public immutable armNotBefore;
    /// @notice When true, the reveal tx must carry the raw solution bytes and
    /// the contract enforces sha256(bytes)==commitDaHash on-chain (data
    /// availability rides the chain itself). When false, this problem's
    /// certificates are too large for calldata; bytes live off-chain and are
    /// verified against the same on-chain `commitDaHash` anchor by any fetcher.
    bool public immutable onchainDa;
    /// @notice Max solution bytes accepted in a reveal tx (only meaningful when
    /// `onchainDa`). Bounds calldata gas and blocks calldata-bomb griefing.
    uint256 public immutable maxSolutionBytes;
    /// @notice OPEN-PHASE loose starting ceiling for the frontier (in score
    /// atoms). This is deliberately NOT a human-attested published record: it
    /// only needs to be loose enough that any real solution strictly beats it.
    /// The TRUE public frontier is then established ON-CHAIN BY CONSTRUCTION
    /// during the unpaid open phase — anyone posts witnesses for free, each
    /// verified strict improvement advances `bestScoreAtoms`, and no credit is
    /// recorded until the funder arms funding (`armFunding`). Paid credit is
    /// always the marginal reduction from the live frontier, never the
    /// seed-relative distance.
    int256 public immutable seedScoreAtoms;
    /// @notice Minimum marginal reduction (in score atoms) that earns credit
    /// at finalization. A finalizing submission whose live marginal is below
    /// this floor is treated as superseded: credit 0, frontier untouched,
    /// bond returned.
    uint256 public immutable minImprovementAtoms;
    address public challengeManager;
    bool public pausedNewActions;
    /// @notice STRONGER pause than `pausedNewActions` (which only gates
    /// commit): while set, commit(), reveal(), AND finalize() all revert, so a
    /// governance recovery (`voidFinalize`) can never race a finalize that
    /// would move `bestScoreAtoms` and stale its frontier-equality check.
    bool public pausedAll;
    /// @notice Earliest wall-clock time at which the current credit stack can
    /// settle. Exact-inverse voids restore the prior stack deadline.
    uint64 public creditRecoveryEndsAt;
    /// @notice Start of the current continuous full-pause episode. Repeated
    /// pause=true calls cannot refresh it, so they cannot postpone the
    /// permissionless recovery deadline.
    uint64 public pausedAllAt;
    /// @notice Total wall-clock seconds spent in completed full-pause episodes.
    /// Commit reveal windows run against active protocol time, which excludes
    /// both this total and the elapsed portion of the current episode.
    uint64 public totalPausedAllSeconds;
    /// @notice OPEN-WITNESS-PHASE gate. While false (deployment default) the
    /// problem is in the unpaid OPEN phase: witness postings advance the
    /// frontier but record ZERO ledger credit, and the bounty pool refuses
    /// deposits (see P42BountyPool.setSubmissionManager). Once the funder
    /// calls `armFunding()` the PAID phase begins: the pool accepts ETH and
    /// finalized improvements earn the marginal over whatever frontier the
    /// open phase established.
    bool public fundingArmed;
    /// @notice Timestamp funding was armed, retained for public chronology.
    /// Economic phase identity is stored directly in paidAtCommit and never
    /// inferred from timestamp ordering.
    uint64 public armedAt;
    /// @notice Canonical production-launch authorization digest consumed by
    /// the one-way OPEN-to-PAID transition.
    bytes32 public fundingAuthorizationDigest;
    bytes32 public authorizedFundingDigest;
    uint64 public fundingAuthorizationExpiresAt;
    /// @notice After a `pausedAll` recovery ends, no submission may be expired
    /// (bond forfeited) until a full fresh challenge window has passed, so an
    /// honest in-flight commit/reveal frozen by the recovery always gets a real
    /// chance to act before its clock is treated as expired.
    uint64 public expiryGraceUntil;
    bool private _claiming;
    uint256 public submissionCount;
    uint256 public openSubmissionCount;
    /// @notice Live per-problem frontier best (absolute score atoms; lower is
    /// better). Initialized to `seedScoreAtoms`; advances ONLY at
    /// finalization, so the challenge window fully guards every advance.
    int256 public bestScoreAtoms;

    mapping(uint256 => Submission) public submissions;
    mapping(uint256 => uint64) public committedBlockOf;
    mapping(uint256 => uint64) public committedActiveAtOf;
    mapping(uint256 => uint64) public maxDisputeEndsAtOf;
    mapping(uint256 => bool) public paidAtCommit;
    /// @notice Immutable fingerprint of the currently revealed claim. Challenge
    /// calls bind this value so a raw transaction signed before a reorg cannot
    /// be replayed against a replacement reveal with the same submission id.
    mapping(uint256 => bytes32) public revealInstanceHashOf;
    mapping(uint256 => bytes32) public solutionCidHashOf;
    mapping(bytes32 => uint256) public prioritySubmissionOf;
    mapping(address => uint256) public claimableBondWei;
    uint256 public revealedSubmissionCount;
    uint256 public challengedSubmissionCount;
    /// @notice Per-submission finalization snapshot (see FinalizeInfo). Only
    /// meaningful once the submission reached Finalized/Voided.
    mapping(uint256 => FinalizeInfo) public finalizeInfo;

    event NewActionsPaused(bool paused);
    event AllActionsPaused(bool paused);
    event AllActionsPauseRecovered(address indexed caller, uint64 recoveryAt);
    event CreditRecoveryWindowAdvanced(
        uint256 indexed submissionId,
        uint64 previousEndsAt,
        uint64 recoveryEndsAt
    );
    event CreditRecoveryWindowRestored(
        uint256 indexed submissionId,
        uint64 previousEndsAt,
        uint64 restoredEndsAt
    );
    event OpenWitnessWindowConfigured(uint64 deployedAt, uint64 armNotBefore);
    event FundingArmed(uint64 at, bytes32 indexed authorizationDigest);
    event FundingAuthorized(bytes32 indexed authorizationDigest, address indexed authorizer, uint64 expiresAt);
    event FinalizeVoided(
        uint256 indexed submissionId,
        address indexed solver,
        uint256 creditAtoms,
        int256 restoredBestScoreAtoms
    );
    event ChallengeManagerSet(address indexed challengeManager);
    event Committed(
        uint256 indexed submissionId,
        address indexed solver,
        bytes32 indexed commitment,
        bytes32 commitDaHash,
        uint256 bondWei,
        uint256 poolAtSubmissionWei,
        uint256 requiredBondWei,
        bool paidAtCommit,
        uint64 committedBlock
    );
    event Revealed(
        uint256 indexed submissionId,
        address indexed solver,
        string solutionCid,
        uint256 improvementAtoms,
        int256 claimedScoreAtoms,
        uint64 challengeEndsAt,
        uint256 solutionBytesLength,
        bytes32 revealInstanceHash
    );
    /// @param creditAtoms The MARGINAL frontier reduction credited to the
    /// solver (previous best - claimed score), 0 when the submission was
    /// superseded by a better finalized score, and always 0 during the unpaid
    /// OPEN phase (before armFunding). This — never a seed-relative
    /// improvement — is what the payout ledger sums.
    /// @param bestScoreAtoms The live frontier after this finalization.
    event Finalized(
        uint256 indexed submissionId,
        address indexed solver,
        uint256 creditAtoms,
        int256 claimedScoreAtoms,
        int256 bestScoreAtoms,
        bytes32 permanenceHash,
        uint256 poolAtFinalizationWei
    );
    event SubmissionChallenged(uint256 indexed submissionId, address indexed challengeManager);
    event SubmissionChallengeResolved(uint256 indexed submissionId, bool challengerWins);
    event SubmissionChallengeCancelled(uint256 indexed submissionId, uint64 challengeEndsAt);
    event SubmissionExpired(uint256 indexed submissionId, SubmissionStatus previousStatus);
    event BondToppedUp(uint256 indexed submissionId, address indexed solver, uint256 amount, uint256 newBondWei);
    event SubmissionBondClaimable(uint256 indexed submissionId, address indexed claimant, uint256 amount);
    event BondClaimed(address indexed claimant, uint256 amount);
    event DuplicatePriorityAssigned(bytes32 indexed solutionCidHash, uint256 indexed submissionId);
    event DuplicateSubmissionRejected(
        bytes32 indexed solutionCidHash,
        uint256 indexed rejectedSubmissionId,
        uint256 indexed prioritySubmissionId
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert P42_NOT_OWNER();
        _;
    }

    modifier onlyChallengeManager() {
        if (msg.sender != challengeManager) revert P42_NOT_CHALLENGE_MANAGER();
        _;
    }

    modifier nonReentrant() {
        require(!_claiming, "P42_REENTRANT_BOND_CLAIM");
        _claiming = true;
        _;
        _claiming = false;
    }

    constructor(
        address pool_,
        address ledger_,
        address owner_,
        address treasury_,
        uint16 alphaBps_,
        uint256 minPostingBondWei_,
        uint64 challengeWindowSeconds_,
        bool onchainDa_,
        uint256 maxSolutionBytes_,
        int256 seedScoreAtoms_,
        uint256 minImprovementAtoms_
    ) {
        require(pool_ != address(0), "P42_POOL_ZERO");
        require(ledger_ != address(0), "P42_LEDGER_ZERO");
        require(owner_ != address(0), "P42_OWNER_ZERO");
        require(treasury_ != address(0), "P42_TREASURY_ZERO");
        require(owner_ != treasury_, "P42_FUNDING_AUTHORITIES_NOT_DISTINCT");
        if (alphaBps_ > MAX_ALPHA_BPS) revert P42_BAD_ALPHA();
        if (challengeWindowSeconds_ == 0 || challengeWindowSeconds_ > MAX_CHALLENGE_WINDOW_SECONDS) {
            revert P42_BAD_WINDOW();
        }
        // On-chain DA needs a positive cap within the calldata-gas ceiling;
        // off-chain problems leave it 0 (unused).
        if (onchainDa_) {
            if (maxSolutionBytes_ == 0 || maxSolutionBytes_ > MAX_ONCHAIN_SOLUTION_BYTES) {
                revert P42_BAD_ONCHAIN_DA_CONFIG();
            }
        }
        pool = IP42PoolBalance(pool_);
        ledger = IP42CreditLedger(ledger_);
        owner = owner_;
        treasury = treasury_;
        fundingAuthorizer = treasury_;
        alphaBps = alphaBps_;
        minPostingBondWei = minPostingBondWei_;
        challengeWindowSeconds = challengeWindowSeconds_;
        uint64 deployedAt_ = uint64(block.timestamp);
        deployedAt = deployedAt_;
        armNotBefore = deployedAt_ + challengeWindowSeconds_;
        onchainDa = onchainDa_;
        maxSolutionBytes = maxSolutionBytes_;
        if (seedScoreAtoms_ <= MIN_SCORE_ATOMS_BOUND || seedScoreAtoms_ >= MAX_SCORE_ATOMS_BOUND) {
            revert P42_SCORE_ATOMS_OUT_OF_RANGE(seedScoreAtoms_);
        }
        seedScoreAtoms = seedScoreAtoms_;
        minImprovementAtoms = minImprovementAtoms_;
        bestScoreAtoms = seedScoreAtoms_;
        emit OpenWitnessWindowConfigured(deployedAt_, deployedAt_ + challengeWindowSeconds_);
    }

    function setPausedNewActions(bool paused) external onlyOwner {
        pausedNewActions = paused;
        emit NewActionsPaused(paused);
    }

    /// @notice Arms/disarms the recovery-grade full pause. Unlike
    /// `pausedNewActions`, this also gates reveal() and finalize(), freezing
    /// the frontier so `voidFinalize` operates on a stable `bestScoreAtoms`.
    function setPausedAll(bool paused) external onlyOwner {
        if (paused) {
            // Keep the first timestamp for this continuous pause episode.
            // Otherwise a compromised owner could refresh the timer forever.
            if (!pausedAll) {
                // Once a full pause is cleared, the protocol must provide a
                // real settlement interval before a new episode can start.
                // This also closes the same-block unpause/re-pause cycle.
                if (block.timestamp < expiryGraceUntil) {
                    revert P42_PAUSED_ALL_REARM_OPEN(expiryGraceUntil, uint64(block.timestamp));
                }
                pausedAll = true;
                pausedAllAt = uint64(block.timestamp);
            }
            emit AllActionsPaused(true);
            return;
        }
        if (!pausedAll) revert P42_NOT_PAUSED_ALL();
        _clearPausedAll();
    }

    /// @notice Permissionlessly ends a continuous full pause after governance
    /// had a fixed interval to execute its exact-inverse recovery. This only
    /// clears `pausedAll`; `pausedNewActions` remains untouched, and the
    /// standard fresh expiry grace protects in-flight submissions.
    function recoverPausedAll() external {
        if (!pausedAll) revert P42_NOT_PAUSED_ALL();
        uint64 recoveryAt = pausedAllAt + PAUSED_ALL_RECOVERY_DELAY;
        if (block.timestamp < recoveryAt) {
            revert P42_PAUSED_ALL_RECOVERY_OPEN(recoveryAt, uint64(block.timestamp));
        }
        _clearPausedAll();
        emit AllActionsPauseRecovered(msg.sender, recoveryAt);
    }

    /// @notice One-way switch from the unpaid OPEN phase to the PAID phase.
    /// Before this call every finalize records ZERO credit (the frontier still
    /// advances — that is the point: free public witness postings establish
    /// the true frontier on-chain), and the wired bounty pool refuses ETH.
    /// After it, finalized improvements earn the marginal over the
    /// open-established frontier and the pool accepts funding — one call is
    /// the single arm authority for both.
    ///
    /// The unpaid OPEN phase is immutable and lasts at least one full challenge
    /// window from deployment. This prevents an owner from deploying and
    /// immediately arming a private paid frontier. A timer does not prove that
    /// a public witness was posted, so the strict open-witness transcript and
    /// arm/fund-boundary evidence remain separate launch gates.
    function authorizeFunding(bytes32 authorizationDigest, uint64 expiresAt) external {
        if (msg.sender != fundingAuthorizer) revert P42_NOT_FUNDING_AUTHORIZER();
        if (authorizationDigest == bytes32(0)) revert P42_FUNDING_AUTHORIZATION_ZERO();
        if (fundingArmed) revert P42_FUNDING_ALREADY_ARMED();
        if (block.timestamp > expiresAt) {
            revert P42_FUNDING_AUTHORIZATION_EXPIRED(expiresAt, uint64(block.timestamp));
        }
        authorizedFundingDigest = authorizationDigest;
        fundingAuthorizationExpiresAt = expiresAt;
        emit FundingAuthorized(authorizationDigest, msg.sender, expiresAt);
    }

    function armFunding(bytes32 authorizationDigest) external onlyOwner {
        if (fundingArmed) revert P42_FUNDING_ALREADY_ARMED();
        if (authorizationDigest == bytes32(0)) revert P42_FUNDING_AUTHORIZATION_ZERO();
        if (authorizationDigest != authorizedFundingDigest) {
            revert P42_FUNDING_AUTHORIZATION_MISMATCH(authorizedFundingDigest, authorizationDigest);
        }
        uint64 expiresAt = fundingAuthorizationExpiresAt;
        if (block.timestamp > expiresAt) {
            revert P42_FUNDING_AUTHORIZATION_EXPIRED(expiresAt, uint64(block.timestamp));
        }
        if (block.timestamp < armNotBefore) {
            revert P42_OPEN_WITNESS_WINDOW_OPEN(armNotBefore, uint64(block.timestamp));
        }
        fundingArmed = true;
        armedAt = uint64(block.timestamp);
        fundingAuthorizationDigest = authorizationDigest;
        emit FundingArmed(uint64(block.timestamp), authorizationDigest);
    }

    function setChallengeManager(address challengeManager_) external onlyOwner {
        require(challengeManager_ != address(0), "P42_CHALLENGE_MANAGER_ZERO");
        if (challengeManager != address(0)) revert P42_CHALLENGE_MANAGER_ALREADY_SET();
        challengeManager = challengeManager_;
        emit ChallengeManagerSet(challengeManager_);
    }

    function requiredPostingBondForPool(uint256 poolWei) public view returns (uint256) {
        uint256 scaled = P42Math.mulDiv(poolWei, alphaBps, 10_000);
        return scaled > minPostingBondWei ? scaled : minPostingBondWei;
    }

    function requiredPostingBondNow() external view returns (uint256) {
        return requiredPostingBondForPool(fundingArmed ? pool.fundingCap() : pool.funded());
    }

    function commit(bytes32 commitment, bytes32 commitDaHash) external payable returns (uint256 submissionId) {
        if (pausedAll) revert P42_PAUSED_ALL();
        if (pausedNewActions) revert P42_PAUSED_NEW_ACTIONS();
        if (ledger.closed()) revert P42_LEDGER_CLOSED();
        uint64 deadline = ledger.fundingDeadline();
        if (block.timestamp > deadline) {
            revert P42_SUBMISSION_WINDOW_CLOSED(deadline, uint64(block.timestamp));
        }
        if (commitment == bytes32(0)) revert P42_EMPTY_COMMITMENT();
        if (commitDaHash == bytes32(0)) revert P42_EMPTY_DA_HASH();

        uint256 poolAtSubmission = pool.funded();
        bool isPaidCommit = fundingArmed;
        uint256 required = requiredPostingBondForPool(isPaidCommit ? pool.fundingCap() : poolAtSubmission);
        if (msg.value < required) revert P42_INSUFFICIENT_POSTING_BOND(required, msg.value);

        submissionId = ++submissionCount;
        Submission storage submission = submissions[submissionId];
        submission.solver = msg.sender;
        submission.commitment = commitment;
        submission.commitDaHash = commitDaHash;
        submission.bondWei = msg.value;
        submission.poolAtSubmissionWei = poolAtSubmission;
        submission.requiredBondWei = required;
        submission.committedAt = uint64(block.timestamp);
        committedBlockOf[submissionId] = uint64(block.number);
        committedActiveAtOf[submissionId] = activeTimestamp();
        paidAtCommit[submissionId] = isPaidCommit;
        submission.status = SubmissionStatus.Committed;
        openSubmissionCount += 1;
        emit Committed(
            submissionId,
            msg.sender,
            commitment,
            commitDaHash,
            msg.value,
            poolAtSubmission,
            required,
            isPaidCommit,
            uint64(block.number)
        );
    }

    function topUpBond(uint256 submissionId) external payable {
        Submission storage submission = _requireSubmission(submissionId);
        if (msg.sender != submission.solver) revert P42_NOT_SOLVER();
        if (
            submission.status != SubmissionStatus.Committed
                && submission.status != SubmissionStatus.Revealed
                && submission.status != SubmissionStatus.Challenged
        ) {
            revert P42_BAD_SUBMISSION_STATUS(SubmissionStatus.Revealed, submission.status);
        }
        require(msg.value > 0, "P42_ZERO_BOND_TOP_UP");
        submission.bondWei += msg.value;
        emit BondToppedUp(submissionId, msg.sender, msg.value, submission.bondWei);
    }

    /// @param claimedScoreAtoms The submission's ABSOLUTE score in atoms
    /// (score_atoms = ceil(score * SCORE_ATOM_SCALE); lower is better). It
    /// must strictly beat the CURRENT frontier (`bestScoreAtoms`) at reveal
    /// time. Credit at finalization is the marginal reduction against the
    /// live frontier, which may have advanced further by then.
    /// @param improvementAtoms Advisory display value only. It does NOT drive
    /// payout — credit is derived on-chain from `claimedScoreAtoms` vs the
    /// live frontier.
    /// @param solution The raw solution bytes. For on-chain-DA problems these
    /// ride this tx's calldata and the contract enforces sha256(solution) equals
    /// the `commitDaHash` anchor bound at commit — a consensus-enforced proof
    /// that the exact committed bytes are available on-chain for the challenge
    /// window (and, via archive nodes/indexer, for later-Δ recomputation). For
    /// off-chain-DA problems this MUST be empty; the anchor still binds the
    /// off-chain bytes, which any fetcher re-checks against `commitDaHash`.
    function reveal(
        uint256 submissionId,
        string calldata solutionCid,
        int256 claimedScoreAtoms,
        uint256 improvementAtoms,
        string calldata salt,
        bytes calldata solution
    ) external {
        if (pausedAll) revert P42_PAUSED_ALL();
        Submission storage submission = _requireSubmission(submissionId);
        if (msg.sender != submission.solver) revert P42_NOT_SOLVER();
        _requireStatus(submission, SubmissionStatus.Committed);
        _requireCommitMature(submissionId);
        _requireCommitOpen(submissionId);
        if (bytes(solutionCid).length == 0) revert P42_EMPTY_SOLUTION_CID();
        // Seed gate (F1): the claimed ABSOLUTE score must strictly beat the
        // IMMUTABLE seed (the starting frontier). We gate on `seedScoreAtoms`,
        // NOT the live `bestScoreAtoms`: the seed is fixed at commit time, so an
        // honest solver whose commit is later superseded (a rival advances
        // `bestScoreAtoms` between this solver's commit and reveal) can still
        // reveal and then finalize with 0 credit and a FULLY reclaimable bond —
        // gating on the moving best would instead brick their submission in
        // Committed and route the bond to the treasury (a front-runnable
        // bond-seizure grief). Worse-than-frontier-but-better-than-seed claims
        // are still harmless: finalize() recomputes against the live best and
        // credits 0.
        if (claimedScoreAtoms >= seedScoreAtoms) {
            revert P42_NOT_STRICT_IMPROVEMENT(seedScoreAtoms, claimedScoreAtoms);
        }
        // Range guard: with the seed bounded above by MAX_SCORE_ATOMS_BOUND
        // and every accepted claim bounded below here, bestScoreAtoms -
        // claimedScoreAtoms can never overflow int256 — finalize and the
        // challenge views stay panic-free for adversarial claims.
        if (claimedScoreAtoms <= MIN_SCORE_ATOMS_BOUND) {
            revert P42_SCORE_ATOMS_OUT_OF_RANGE(claimedScoreAtoms);
        }

        if (
            keccak256(bytes(commitPreimageWithDa(solutionCid, msg.sender, submission.commitDaHash, salt)))
                != submission.commitment
        ) revert P42_BAD_COMMITMENT_REVEAL();

        // Data availability: on-chain problems post the bytes here and prove
        // they hash to the committed anchor; off-chain problems must not bloat
        // calldata (the anchor alone gates their off-chain store).
        _validateSolutionDa(submission.commitDaHash, solution);

        uint64 challengeEndsAt = uint64(block.timestamp) + challengeWindowSeconds;
        submission.solutionCid = solutionCid;
        submission.claimedScoreAtoms = claimedScoreAtoms;
        submission.improvementAtoms = improvementAtoms;
        submission.revealedAt = uint64(block.timestamp);
        submission.challengeEndsAt = challengeEndsAt;
        bytes32 revealInstanceHash = _revealInstanceHash(submissionId, submission);
        revealInstanceHashOf[submissionId] = revealInstanceHash;
        maxDisputeEndsAtOf[submissionId] =
            uint64(block.timestamp) + challengeWindowSeconds * MAX_CUMULATIVE_DISPUTE_WINDOWS;
        _assignDuplicatePriority(submissionId, solutionCid);

        emit Revealed(
            submissionId,
            msg.sender,
            solutionCid,
            improvementAtoms,
            claimedScoreAtoms,
            challengeEndsAt,
            solution.length,
            revealInstanceHash
        );
    }

    /// @param permanenceHash OPTIONAL off-chain-mirror receipt (e.g. an Arweave
    /// txid hash). No longer required: on-chain-DA problems already have the
    /// bytes on-chain (verified at reveal), and off-chain-DA problems are gated
    /// by the `commitDaHash` anchor. Pass 0 unless recording a mirror.
    ///
    /// The marginal is recomputed here against the LIVE frontier (it may have
    /// advanced since reveal): marginal = bestScoreAtoms - claimedScoreAtoms
    /// when that is still >= minImprovementAtoms, else 0 (the submission was
    /// superseded by a better finalized score). The frontier advances on every
    /// non-zero marginal in BOTH phases; ledger credit is recorded ONLY for
    /// submissions COMMITTED after funding was armed (creditAtoms =
    /// paidAtCommit[submissionId] ? marginal : 0) — an
    /// open-phase witness posting establishes the public frontier for free.
    /// The ledger sums the paid marginals, so each solver's pool share is
    /// exactly their marginal frontier reduction over the total reduction — a
    /// free-rider on someone else's frontier is paid only their own small
    /// delta (F1). Either way the submission finalizes and the solver's bond
    /// becomes claimable: an honest solver who was merely beaten is never
    /// bond-slashed.
    function finalize(uint256 submissionId, bytes32 permanenceHash) external {
        if (pausedAll) revert P42_PAUSED_ALL();
        Submission storage submission = _requireSubmission(submissionId);
        if (msg.sender != submission.solver) revert P42_NOT_SOLVER();
        _requireStatus(submission, SubmissionStatus.Revealed);
        if (block.timestamp < submission.challengeEndsAt) {
            revert P42_CHALLENGE_WINDOW_OPEN(submission.challengeEndsAt, uint64(block.timestamp));
        }

        bytes32 solutionCidHash = solutionCidHashOf[submissionId];
        uint256 priorityId = prioritySubmissionOf[solutionCidHash];
        if (priorityId != submissionId) {
            submission.status = SubmissionStatus.Rejected;
            revealedSubmissionCount -= 1;
            _makeBondClaimable(submissionId, submission.solver);
            _decrementOpenSubmission();
            emit DuplicateSubmissionRejected(solutionCidHash, submissionId, priorityId);
            return;
        }

        address solver = submission.solver;
        int256 claimed = submission.claimedScoreAtoms;
        uint256 marginal = 0;
        if (claimed < bestScoreAtoms) {
            uint256 reduction = uint256(bestScoreAtoms - claimed);
            if (reduction >= minImprovementAtoms) {
                marginal = reduction;
            }
        }
        // OPEN phase: the frontier still advances (below) but no credit is
        // recorded — witness postings are free and unpaid by construction.
        // Credit is bound to the COMMIT phase, not the finalize phase: a
        // submission committed before funding was armed earns 0 forever (even
        // if it finalizes post-arm), which is what closes the withhold-across-
        // the-arm leak. The frontier still advances for free (see below, gated
        // on `marginal`), it just never earns.
        uint256 creditAtoms = paidAtCommit[submissionId] ? marginal : 0;

        // A paid finalization is collateralized against the entire immutable
        // funding cap, not the balance that happens to exist today. Future
        // public donations therefore cannot increase the solver's payout above
        // the amount whose fraud risk was bonded.
        if (creditAtoms != 0) {
            uint256 required = requiredPostingBondForPool(pool.fundingCap());
            if (submission.bondWei < required) {
                revert P42_BOND_UNDERCOVERS_ENTITLEMENT(required, submission.bondWei);
            }
        }

        submission.permanenceHash = permanenceHash;
        submission.status = SubmissionStatus.Finalized;
        revealedSubmissionCount -= 1;
        // Recovery snapshot: persist the frontier this finalize advanced from
        // and the marginal it was credited (0 for superseded AND open-phase
        // finalizes), so a fraudulent finalize can later be reversed exactly
        // by voidFinalize.
        uint64 previousRecoveryEndsAt = creditRecoveryEndsAt;
        finalizeInfo[submissionId] = FinalizeInfo({
            prevBestScoreAtoms: bestScoreAtoms,
            creditAtoms: creditAtoms,
            prevCreditRecoveryEndsAt: previousRecoveryEndsAt
        });
        // Credit-bearing collateral remains live until close fixes the final
        // pool and denominator. Superseded and unpaid witness submissions have
        // no economic claim, so their bonds can be returned immediately.
        if (creditAtoms == 0) {
            _makeBondClaimable(submissionId, solver);
        }
        _decrementOpenSubmission();
        if (marginal != 0) {
            bestScoreAtoms = claimed;
        }
        if (creditAtoms != 0) {
            uint64 recoveryEndsAt = uint64(block.timestamp) + CREDIT_FINALIZE_RECOVERY_DELAY;
            creditRecoveryEndsAt = recoveryEndsAt;
            ledger.recordCredit(solver, creditAtoms);
            emit CreditRecoveryWindowAdvanced(submissionId, previousRecoveryEndsAt, recoveryEndsAt);
        }

        emit Finalized(
            submissionId,
            solver,
            creditAtoms,
            claimed,
            bestScoreAtoms,
            permanenceHash,
            pool.funded()
        );
    }

    /// @notice Makes retained paid-finalize collateral claimable once the
    /// ledger is closed and no further legitimate funding can enter the pool.
    /// Permissionless execution avoids turning bond return into a solver
    /// liveness dependency; proceeds always accrue to the recorded solver.
    function releaseFinalizedBond(uint256 submissionId) external {
        if (!ledger.closed()) revert P42_LEDGER_NOT_CLOSED();
        Submission storage submission = _requireSubmission(submissionId);
        _requireStatus(submission, SubmissionStatus.Finalized);
        if (submission.bondWei == 0) revert P42_NO_FINALIZED_BOND();
        _makeBondClaimable(submissionId, submission.solver);
    }

    /// @notice Governance recovery for a POISONED frontier: a fraudulent
    /// unchallenged finalize can set `bestScoreAtoms` unreachably low, so every
    /// honest score thereafter finalizes with 0 credit — bricking the problem.
    /// This reverses EXACTLY one finalize with no governance-chosen numbers:
    /// it restores the stored `prevBestScoreAtoms` and (when the finalize was
    /// paid) voids the stored `creditAtoms` on the ledger.
    ///
    /// BOTH poison classes are recoverable:
    /// - PAID poison (creditAtoms > 0): frontier restored + credit voided.
    /// - OPEN-PHASE poison (creditAtoms == 0): a fraud that advances the
    ///   frontier for free earns no credit, but still bricks honest postings.
    ///   Frontier restored; there is no credit to void. (Gating the void on
    ///   creditAtoms > 0 — the previous behavior — would make an open-phase
    ///   poison UNrecoverable.)
    ///
    /// Safety preconditions:
    /// - `pausedAll` must be set, so no finalize can race the void and move the
    ///   frontier between the checks and the restore.
    /// - The submission must still BE the live frontier
    ///   (`bestScoreAtoms == claimedScoreAtoms`). A poisoned frontier always
    ///   is — nothing can beat it.
    /// - The finalize must have ACTUALLY moved the frontier
    ///   (`prevBestScoreAtoms != claimedScoreAtoms`). A superseded 0-marginal
    ///   finalize (e.g. one that merely tied the live frontier) is refused:
    ///   it advanced nothing and restoring its prevBest would corrupt the
    ///   frontier.
    /// Together these make the void an exact inverse with no double-accounting:
    /// totalCreditAtoms keeps telescoping over the PAID frontier segment.
    ///
    /// Collateral policy: a paid finalize keeps its bond live until close. If
    /// governance voids that credit-bearing poison before close, the still-live
    /// bond is forfeited to treasury. Zero-credit/open-phase finalizes already
    /// made their bond claimable, so their zero stored bond is left idempotently
    /// untouched by the same transition.
    function voidFinalize(uint256 submissionId) external onlyOwner {
        if (!pausedAll) revert P42_NOT_PAUSED_ALL();
        uint256 revealed = revealedSubmissionCount;
        uint256 challenged = challengedSubmissionCount;
        if (revealed != 0 || challenged != 0) {
            revert P42_ACTIVE_REVEALS_OR_CHALLENGES(revealed, challenged);
        }
        Submission storage submission = _requireSubmission(submissionId);
        _requireStatus(submission, SubmissionStatus.Finalized);
        FinalizeInfo storage info = finalizeInfo[submissionId];
        if (bestScoreAtoms != submission.claimedScoreAtoms) {
            revert P42_VOID_NOT_FRONTIER(bestScoreAtoms, submission.claimedScoreAtoms);
        }
        if (info.prevBestScoreAtoms == submission.claimedScoreAtoms) {
            revert P42_VOID_NOT_ADVANCE(info.prevBestScoreAtoms, submission.claimedScoreAtoms);
        }

        uint256 creditAtoms = info.creditAtoms;
        int256 restored = info.prevBestScoreAtoms;
        // Voided (not Finalized) so the same finalize can never be voided twice.
        submission.status = SubmissionStatus.Voided;
        bestScoreAtoms = restored;
        if (creditAtoms > 0) {
            uint64 previousRecoveryEndsAt = creditRecoveryEndsAt;
            creditRecoveryEndsAt = info.prevCreditRecoveryEndsAt;
            ledger.voidCredit(submission.solver, creditAtoms);
            _makeBondClaimable(submissionId, treasury);
            emit CreditRecoveryWindowRestored(
                submissionId,
                previousRecoveryEndsAt,
                info.prevCreditRecoveryEndsAt
            );
        } else {
            _makeBondClaimable(submissionId, submission.solver);
        }
        emit FinalizeVoided(submissionId, submission.solver, creditAtoms, restored);
    }

    function markChallenged(uint256 submissionId) external onlyChallengeManager {
        Submission storage submission = _requireSubmission(submissionId);
        _requireStatus(submission, SubmissionStatus.Revealed);
        if (block.timestamp >= submission.challengeEndsAt) {
            revert P42_CHALLENGE_WINDOW_CLOSED(submission.challengeEndsAt, uint64(block.timestamp));
        }
        submission.status = SubmissionStatus.Challenged;
        revealedSubmissionCount -= 1;
        challengedSubmissionCount += 1;
        emit SubmissionChallenged(submissionId, msg.sender);
    }

    function resolveChallenge(uint256 submissionId, bool challengerWins, address beneficiary)
        external
        onlyChallengeManager
    {
        Submission storage submission = _requireSubmission(submissionId);
        _requireStatus(submission, SubmissionStatus.Challenged);
        challengedSubmissionCount -= 1;
        if (challengerWins) {
            submission.status = SubmissionStatus.Rejected;
            // The rejected solver's forfeited posting bond is routed to the
            // beneficiary chosen by the challenge manager (the winning
            // challenger) so that policing fraud is net-positive (M2).
            require(beneficiary != address(0), "P42_BENEFICIARY_ZERO");
            _makeBondClaimable(submissionId, beneficiary);
            _decrementOpenSubmission();
        } else {
            bytes32 solutionCidHash = solutionCidHashOf[submissionId];
            uint256 priorityId = prioritySubmissionOf[solutionCidHash];
            if (priorityId != submissionId) {
                submission.status = SubmissionStatus.Rejected;
                _makeBondClaimable(submissionId, submission.solver);
                _decrementOpenSubmission();
                emit DuplicateSubmissionRejected(solutionCidHash, submissionId, priorityId);
                emit SubmissionChallengeResolved(submissionId, challengerWins);
                return;
            }
            submission.status = SubmissionStatus.Revealed;
            revealedSubmissionCount += 1;
            // Re-arm a fresh full challenge window. Without this the submission
            // returns to Revealed with the STALE pre-challenge challengeEndsAt,
            // so expireRevealed could immediately strip the prevailing solver's
            // bond before they have any chance to finalize (F5).
            submission.challengeEndsAt = _boundedRearmDeadline(submissionId);
        }
        emit SubmissionChallengeResolved(submissionId, challengerWins);
    }

    /// @notice Cancels a still-pending resolver decision after its bond is
    /// slashed. No verdict is applied; the submission returns to Revealed and
    /// remains challengeable only within its original cumulative horizon.
    function cancelChallenge(uint256 submissionId) external onlyChallengeManager {
        Submission storage submission = _requireSubmission(submissionId);
        _requireStatus(submission, SubmissionStatus.Challenged);
        challengedSubmissionCount -= 1;
        bytes32 solutionCidHash = solutionCidHashOf[submissionId];
        uint256 priorityId = prioritySubmissionOf[solutionCidHash];
        if (priorityId != submissionId) {
            submission.status = SubmissionStatus.Rejected;
            _makeBondClaimable(submissionId, submission.solver);
            _decrementOpenSubmission();
            emit DuplicateSubmissionRejected(solutionCidHash, submissionId, priorityId);
            emit SubmissionChallengeCancelled(submissionId, 0);
            return;
        }
        submission.status = SubmissionStatus.Revealed;
        revealedSubmissionCount += 1;
        submission.challengeEndsAt = _boundedRearmDeadline(submissionId);
        emit SubmissionChallengeCancelled(submissionId, submission.challengeEndsAt);
    }

    function maxDisputeDeadline(uint256 submissionId) external view returns (uint64) {
        _requireSubmission(submissionId);
        return maxDisputeEndsAtOf[submissionId];
    }

    /// @notice The marginal credit (in score atoms) a submission would earn if
    /// it finalized against the CURRENT frontier: bestScoreAtoms -
    /// claimedScoreAtoms when that is >= minImprovementAtoms, else 0. Advisory
    /// for pending submissions — the frontier may still advance before their
    /// finalization.
    function pendingCreditAtoms(uint256 submissionId) public view returns (uint256) {
        Submission storage submission = _requireSubmission(submissionId);
        int256 claimed = submission.claimedScoreAtoms;
        if (claimed >= bestScoreAtoms) return 0;
        uint256 marginal = uint256(bestScoreAtoms - claimed);
        return marginal >= minImprovementAtoms ? marginal : 0;
    }

    /// @notice Ledger-derived entitlement that a Revealed submission is claiming.
    /// The challenge manager sizes its value-proportional counter-bond from this
    /// trusted on-chain figure instead of a caller-supplied argument (H2). It
    /// mirrors the entitlement computation performed at finalization: the
    /// disputed value is the MARGINAL frontier reduction, not the advisory
    /// improvement figure (F1).
    function disputedEntitlementWei(uint256 submissionId) external view returns (uint256) {
        Submission storage submission = _requireSubmission(submissionId);
        _requireStatus(submission, SubmissionStatus.Revealed);
        return ledger.provisionalEntitlement(submission.solver, pendingCreditAtoms(submissionId));
    }

    /// @notice Minimal solver lookup used by the challenge manager to reject
    /// self-challenges (F3). Reverts for unknown submissions.
    function solverOf(uint256 submissionId) external view returns (address) {
        return _requireSubmission(submissionId).solver;
    }

    function expireCommitted(uint256 submissionId) external {
        // The reveal deadline is measured in active protocol time: full-pause
        // intervals are tolled exactly, while a commit already expired when a
        // pause begins remains expired afterwards.
        if (pausedAll) revert P42_PAUSED_ALL();
        Submission storage submission = _requireSubmission(submissionId);
        _requireStatus(submission, SubmissionStatus.Committed);
        uint64 activeNow = activeTimestamp();
        uint64 expiresAt = committedActiveAtOf[submissionId] + challengeWindowSeconds;
        if (activeNow < expiresAt) {
            revert P42_REVEAL_WINDOW_OPEN(_wallTimestampForActive(expiresAt, activeNow), uint64(block.timestamp));
        }
        // Post-recovery grace: a full fresh window after any pausedAll unpause.
        if (block.timestamp < expiryGraceUntil) {
            revert P42_REVEAL_WINDOW_OPEN(expiryGraceUntil, uint64(block.timestamp));
        }
        submission.status = SubmissionStatus.Rejected;
        _makeBondClaimable(submissionId, treasury);
        _decrementOpenSubmission();
        emit SubmissionExpired(submissionId, SubmissionStatus.Committed);
    }

    function expireRevealed(uint256 submissionId) external {
        // Recovery-freeze fairness: while pausedAll is set, finalize() is
        // blocked, so an honest revealed submission CANNOT finalize its way to
        // safety. Same rationale as expireCommitted: no bond forfeiture while
        // the solver is frozen out.
        if (pausedAll) revert P42_PAUSED_ALL();
        Submission storage submission = _requireSubmission(submissionId);
        _requireStatus(submission, SubmissionStatus.Revealed);
        uint64 expiresAt = submission.challengeEndsAt + challengeWindowSeconds;
        if (block.timestamp < expiresAt) {
            revert P42_PERMANENCE_GRACE_OPEN(expiresAt, uint64(block.timestamp));
        }
        // Post-recovery grace: a full fresh window after any pausedAll unpause.
        if (block.timestamp < expiryGraceUntil) {
            revert P42_PERMANENCE_GRACE_OPEN(expiryGraceUntil, uint64(block.timestamp));
        }
        submission.status = SubmissionStatus.Rejected;
        revealedSubmissionCount -= 1;
        _makeBondClaimable(submissionId, treasury);
        _decrementOpenSubmission();
        emit SubmissionExpired(submissionId, SubmissionStatus.Revealed);
    }

    function claimBond() external nonReentrant {
        uint256 amount = claimableBondWei[msg.sender];
        if (amount == 0) revert P42_NO_BOND_TO_CLAIM();
        claimableBondWei[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit BondClaimed(msg.sender, amount);
    }

    function bondCoversEntitlement(uint256 submissionId, uint256 entitlementWei) public view returns (bool) {
        Submission storage submission = _requireSubmission(submissionId);
        uint256 required = requiredPostingBondForPool(entitlementWei);
        return submission.bondWei >= required;
    }

    function requireFinalizeBond(uint256 submissionId, uint256 entitlementWei) external view {
        Submission storage submission = _requireSubmission(submissionId);
        uint256 required = requiredPostingBondForPool(entitlementWei);
        if (submission.bondWei < required) {
            revert P42_BOND_UNDERCOVERS_ENTITLEMENT(required, submission.bondWei);
        }
    }

    function computeCommitment(
        string calldata solutionCid,
        address solver,
        string calldata salt
    ) external pure returns (bytes32) {
        return keccak256(bytes(commitPreimage(solutionCid, solver, salt)));
    }

    function computeCommitment(
        string calldata solutionCid,
        address solver,
        bytes32 commitDaHash,
        string calldata salt
    ) external pure returns (bytes32) {
        return keccak256(bytes(commitPreimageWithDa(solutionCid, solver, commitDaHash, salt)));
    }

    function commitPreimage(
        string calldata solutionCid,
        address solver,
        string calldata salt
    ) public pure returns (string memory) {
        return string.concat(
            "p42:v0|cid:",
            _uintToString(bytes(solutionCid).length),
            ":",
            solutionCid,
            "|solver:",
            _addressToLowerHex(solver),
            "|salt:",
            _uintToString(bytes(salt).length),
            ":",
            salt
        );
    }

    function commitPreimageWithDa(
        string calldata solutionCid,
        address solver,
        bytes32 commitDaHash,
        string calldata salt
    ) public pure returns (string memory) {
        return string.concat(
            "p42:v1|cid:",
            _uintToString(bytes(solutionCid).length),
            ":",
            solutionCid,
            "|solver:",
            _addressToLowerHex(solver),
            "|da:",
            _bytes32ToLowerHex(commitDaHash),
            "|salt:",
            _uintToString(bytes(salt).length),
            ":",
            salt
        );
    }

    function _uintToString(uint256 value) private pure returns (string memory) {
        if (value == 0) return "0";
        uint256 digits;
        uint256 tmp = value;
        while (tmp != 0) {
            digits++;
            tmp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + value % 10));
            value /= 10;
        }
        return string(buffer);
    }

    function _addressToLowerHex(address account) private pure returns (string memory) {
        bytes20 data = bytes20(account);
        bytes16 symbols = "0123456789abcdef";
        bytes memory output = new bytes(42);
        output[0] = bytes1("0");
        output[1] = bytes1("x");
        for (uint256 i = 0; i < 20; i++) {
            uint8 value = uint8(data[i]);
            output[2 + i * 2] = symbols[value >> 4];
            output[3 + i * 2] = symbols[value & 0x0f];
        }
        return string(output);
    }

    function _bytes32ToLowerHex(bytes32 data) private pure returns (string memory) {
        bytes16 symbols = "0123456789abcdef";
        bytes memory output = new bytes(66);
        output[0] = bytes1("0");
        output[1] = bytes1("x");
        for (uint256 i = 0; i < 32; i++) {
            uint8 value = uint8(data[i]);
            output[2 + i * 2] = symbols[value >> 4];
            output[3 + i * 2] = symbols[value & 0x0f];
        }
        return string(output);
    }

    function _requireSubmission(uint256 submissionId) private view returns (Submission storage submission) {
        submission = submissions[submissionId];
        if (submission.solver == address(0)) revert P42_UNKNOWN_SUBMISSION();
    }

    function _requireStatus(Submission storage submission, SubmissionStatus expected) private view {
        if (submission.status != expected) {
            revert P42_BAD_SUBMISSION_STATUS(expected, submission.status);
        }
    }

    function _requireCommitMature(uint256 submissionId) private view {
        uint256 eligibleBlock = uint256(committedBlockOf[submissionId]) + MIN_COMMIT_AGE_BLOCKS;
        if (block.number < eligibleBlock) revert P42_COMMIT_NOT_MATURE(eligibleBlock, block.number);
    }

    function _requireCommitOpen(uint256 submissionId) private view {
        uint64 activeNow = activeTimestamp();
        uint64 commitExpiresAt = committedActiveAtOf[submissionId] + challengeWindowSeconds;
        if (activeNow >= commitExpiresAt) {
            revert P42_COMMIT_EXPIRED(_wallTimestampForActive(commitExpiresAt, activeNow), uint64(block.timestamp));
        }
    }

    function _revealInstanceHash(uint256 submissionId, Submission storage submission) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                address(this),
                block.chainid,
                submissionId,
                submission.solver,
                submission.commitment,
                submission.commitDaHash,
                keccak256(bytes(submission.solutionCid)),
                submission.claimedScoreAtoms,
                submission.improvementAtoms,
                submission.challengeEndsAt
            )
        );
    }

    function _validateSolutionDa(bytes32 expectedHash, bytes calldata solution) private view {
        if (onchainDa) {
            if (solution.length == 0) revert P42_EMPTY_SOLUTION_BYTES();
            if (solution.length > maxSolutionBytes) {
                revert P42_SOLUTION_TOO_LARGE(maxSolutionBytes, solution.length);
            }
            bytes32 got = sha256(solution);
            if (got != expectedHash) revert P42_SOLUTION_HASH_MISMATCH(expectedHash, got);
        } else if (solution.length != 0) {
            revert P42_UNEXPECTED_ONCHAIN_BYTES();
        }
    }

    function _makeBondClaimable(uint256 submissionId, address claimant) private {
        Submission storage submission = submissions[submissionId];
        uint256 bondWei = submission.bondWei;
        if (bondWei == 0) return;
        submission.bondWei = 0;
        claimableBondWei[claimant] += bondWei;
        emit SubmissionBondClaimable(submissionId, claimant, bondWei);
    }

    function _decrementOpenSubmission() private {
        if (openSubmissionCount > 0) openSubmissionCount -= 1;
    }

    function _clearPausedAll() private {
        totalPausedAllSeconds += uint64(block.timestamp) - pausedAllAt;
        pausedAll = false;
        // Grant a full fresh challenge window before any expiry can fire, so a
        // submission frozen out by recovery is not immediately forfeitable.
        // The same boundary is a mandatory usable settlement interval: a new
        // full-pause episode cannot begin before it ends.
        expiryGraceUntil = uint64(block.timestamp) + challengeWindowSeconds;
        emit AllActionsPaused(false);
    }

    /// @notice Protocol time used by commit reveal windows. It advances with
    /// wall time while unpaused and is frozen for every `pausedAll` interval.
    function activeTimestamp() public view returns (uint64) {
        uint256 pausedSeconds = totalPausedAllSeconds;
        if (pausedAll) pausedSeconds += block.timestamp - pausedAllAt;
        return uint64(block.timestamp - pausedSeconds);
    }

    function _wallTimestampForActive(uint64 activeDeadline, uint64 activeNow) private view returns (uint64) {
        if (activeDeadline >= activeNow) {
            return uint64(block.timestamp) + activeDeadline - activeNow;
        }
        return uint64(block.timestamp) - (activeNow - activeDeadline);
    }

    function _boundedRearmDeadline(uint256 submissionId) private view returns (uint64) {
        uint64 deadline = maxDisputeEndsAtOf[submissionId];
        uint64 proposed = uint64(block.timestamp) + challengeWindowSeconds;
        return proposed < deadline ? proposed : deadline;
    }

    function _rejectSupersededIfRevealed(uint256 submissionId, bytes32 solutionCidHash, uint256 priorityId) private {
        Submission storage superseded = submissions[submissionId];
        if (superseded.status != SubmissionStatus.Revealed) return;
        superseded.status = SubmissionStatus.Rejected;
        revealedSubmissionCount -= 1;
        _makeBondClaimable(submissionId, superseded.solver);
        _decrementOpenSubmission();
        emit DuplicateSubmissionRejected(solutionCidHash, submissionId, priorityId);
    }

    function _assignDuplicatePriority(uint256 submissionId, string calldata solutionCid) private {
        bytes32 solutionCidHash = keccak256(bytes(solutionCid));
        solutionCidHashOf[submissionId] = solutionCidHash;
        uint256 priorityId = prioritySubmissionOf[solutionCidHash];
        Submission storage submission = submissions[submissionId];
        if (priorityId == 0 || submissionId < priorityId) {
            prioritySubmissionOf[solutionCidHash] = submissionId;
            submission.status = SubmissionStatus.Revealed;
            revealedSubmissionCount += 1;
            emit DuplicatePriorityAssigned(solutionCidHash, submissionId);
            if (priorityId != 0) _rejectSupersededIfRevealed(priorityId, solutionCidHash, submissionId);
            return;
        }
        submission.status = SubmissionStatus.Rejected;
        _makeBondClaimable(submissionId, submission.solver);
        _decrementOpenSubmission();
        emit DuplicateSubmissionRejected(solutionCidHash, submissionId, priorityId);
    }
}
