// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {P42Math} from "./P42Math.sol";

interface IP42ObjectiveBindingFactory {
    function objectiveBindingOf(address manager)
        external
        view
        returns (address registry, uint256 problemId, bytes32 packageHash, bytes32 programId);
}

interface IP42SubmissionChallengeHook {
    function markChallenged(uint256 submissionId) external;
    function resolveChallenge(uint256 submissionId, bool challengerWins, address beneficiary) external;
    function cancelChallenge(uint256 submissionId) external;
    function resolveObjectiveChallenge(uint256 submissionId, bool challengerWins, address beneficiary) external;
    function disputedEntitlementWei(uint256 submissionId) external view returns (uint256);
    function solverOf(uint256 submissionId) external view returns (address);
    function revealInstanceHashOf(uint256 submissionId) external view returns (bytes32);
    function maxDisputeDeadline(uint256 submissionId) external view returns (uint64);
}

/// @notice Optimistic challenge scaffold for Phase 1.
/// It enforces the economic and transcript gates while the verifier execution
/// proof path remains off-chain/testnet-only.
contract P42ChallengeManager {
    error P42_NOT_OWNER();
    error P42_NOT_RESOLVER();
    error P42_PAUSED_NEW_ACTIONS();
    error P42_BAD_BETA();
    error P42_BAD_SUBMISSION();
    error P42_EMPTY_REASON();
    error P42_ALREADY_CHALLENGED();
    error P42_SELF_CHALLENGE();
    error P42_UNKNOWN_CHALLENGE();
    error P42_ALREADY_RESOLVED();
    error P42_DECISION_PENDING();
    error P42_NO_PENDING_DECISION();
    error P42_INSUFFICIENT_CHALLENGE_BOND(uint256 required, uint256 received);
    error P42_INSUFFICIENT_RESOLVER_BOND(uint256 required, uint256 received);
    error P42_DISPUTE_WINDOW_OPEN(uint64 endsAt, uint64 nowAt);
    error P42_DISPUTE_WINDOW_CLOSED(uint64 endsAt, uint64 nowAt);
    error P42_SETTLEMENT_HORIZON_EXCEEDED(uint64 deadline, uint64 proposedFinality);
    error P42_EMPTY_TRANSCRIPT_HASH();
    error P42_EMPTY_TRANSCRIPT_URI();
    error P42_EMPTY_VERDICT_HASH();
    error P42_NO_BOND_TO_CLAIM();
    error P42_NO_RESOLVER_BOND();
    error P42_RESOLVER_BOND_LOCKED(uint64 releaseAt, uint64 nowAt);
    error P42_RESOLVER_FRAUD_WINDOW_CLOSED(uint64 releaseAt, uint64 nowAt);
    error P42_EMPTY_FRAUD_PROOF_HASH();
    error P42_OBJECTIVE_OUTCOME_NOT_CONTRADICTORY();
    error P42_FRAUD_PROOF_BENEFICIARY_ZERO();
    error P42_EMPTY_REVEAL_INSTANCE_HASH();
    error P42_REVEAL_INSTANCE_MISMATCH(bytes32 expected, bytes32 actual);
    error P42_EMPTY_CHALLENGE_INSTANCE_HASH();
    error P42_CHALLENGE_INSTANCE_MISMATCH(bytes32 expected, bytes32 actual);
    error P42_RESOLVER_BENEFICIARY_ZERO();
    error P42_TRANSFER_FAILED();

    uint16 public constant MAX_BETA_BPS = 10_000;
    uint64 public constant MAX_CHALLENGE_WINDOW_SECONDS = 30 days;

    struct Challenge {
        uint256 submissionId;
        address challenger;
        bytes32 reasonHash;
        uint256 challengeBondWei;
        uint64 challengedAt;
        uint64 disputeEndsAt;
        bool resolved;
        bool decisionPending;
        bool challengerWins;
        bytes32 transcriptHash;
        string transcriptURI;
        bytes32 verdictHash;
    }

    struct ResolverBond {
        uint256 amountWei;
        uint64 releaseAt;
        bytes32 slashProofHash;
    }

    address public immutable owner;
    address public factory;
    address public immutable resolver;
    address public immutable treasury;
    IP42SubmissionChallengeHook public immutable submissionManager;
    uint64 public immutable challengeWindowSeconds;
    uint16 public immutable betaBps;
    uint16 public immutable rerunCostMultiplierBps;
    uint256 public immutable minCounterBondWei;
    uint256 public immutable rerunCostWei;
    uint256 public immutable resolverDecisionBondWei;
    uint64 public immutable resolverFraudWindowSeconds;

    bool public pausedNewActions;
    bool private _claiming;

    mapping(uint256 => Challenge) public challenges;
    /// @notice The reveal fingerprint a challenge was opened against. Retained
    /// after resolution for audit, overwritten only by a new active challenge.
    mapping(uint256 => bytes32) public challengeRevealInstanceHashOf;
    /// @notice Per-dispute fingerprint required by every follow-on action.
    /// This prevents a raw resolver/expiry/slash transaction from an orphaned
    /// branch being applied to a different challenge for the same submission.
    mapping(uint256 => bytes32) public challengeInstanceHashOf;
    mapping(uint256 => ResolverBond) public resolverBonds;
    mapping(uint256 => address) public resolverBondBeneficiaryOf;
    mapping(address => uint256) public claimableBondWei;

    event NewActionsPaused(bool paused);
    event Challenged(
        uint256 indexed submissionId,
        address indexed challenger,
        bytes32 indexed reasonHash,
        uint256 bondWei,
        uint64 disputeEndsAt,
        bytes32 revealInstanceHash,
        bytes32 challengeInstanceHash
    );
    event ResolverTranscriptPosted(
        uint256 indexed submissionId,
        address indexed resolver,
        bytes32 transcriptHash,
        string transcriptURI,
        bytes32 verdictHash,
        address resolverBondBeneficiary,
        uint256 resolverBondWei,
        uint64 resolverBondReleaseAt,
        bool challengerWins,
        bytes32 challengeInstanceHash
    );
    event Resolved(uint256 indexed submissionId, bool challengerWins, bytes32 challengeInstanceHash);
    event ResolverDecisionCancelled(
        uint256 indexed submissionId, address indexed challenger, bytes32 proofHash, bytes32 challengeInstanceHash
    );
    event ChallengeExpired(
        uint256 indexed submissionId, address indexed challenger, uint256 refundedBondWei, bytes32 challengeInstanceHash
    );
    event ResolverBondReleased(
        uint256 indexed submissionId, address indexed resolver, uint256 amount, bytes32 challengeInstanceHash
    );
    event ResolverBondSlashed(
        uint256 indexed submissionId,
        address indexed beneficiary,
        uint256 amount,
        bytes32 proofHash,
        bytes32 challengeInstanceHash
    );
    event ObjectiveFraudProven(
        uint256 indexed submissionId,
        address indexed proofBeneficiary,
        bytes32 indexed proofHash,
        bool correctedChallengerWins,
        uint256 resolverBondRewardWei,
        bytes32 challengeInstanceHash
    );
    event BondClaimed(address indexed claimant, uint256 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert P42_NOT_OWNER();
        _;
    }

    modifier onlyResolver() {
        if (msg.sender != resolver) revert P42_NOT_RESOLVER();
        _;
    }

    modifier nonReentrant() {
        require(!_claiming, "P42_REENTRANT_BOND_CLAIM");
        _claiming = true;
        _;
        _claiming = false;
    }

    constructor(
        address owner_,
        address resolver_,
        address treasury_,
        address submissionManager_,
        uint64 challengeWindowSeconds_,
        uint16 betaBps_,
        uint256 minCounterBondWei_,
        uint256 rerunCostWei_,
        uint16 rerunCostMultiplierBps_,
        uint256 resolverDecisionBondWei_,
        uint64 resolverFraudWindowSeconds_
    ) {
        require(owner_ != address(0), "P42_OWNER_ZERO");
        require(resolver_ != address(0), "P42_RESOLVER_ZERO");
        require(treasury_ != address(0), "P42_TREASURY_ZERO");
        require(submissionManager_ != address(0), "P42_SUBMISSION_MANAGER_ZERO");
        require(
            challengeWindowSeconds_ > 0 && challengeWindowSeconds_ <= MAX_CHALLENGE_WINDOW_SECONDS,
            "P42_BAD_CHALLENGE_WINDOW"
        );
        require(resolverFraudWindowSeconds_ > 0, "P42_FRAUD_WINDOW_ZERO");
        require(resolverFraudWindowSeconds_ <= challengeWindowSeconds_, "P42_FRAUD_WINDOW_TOO_LONG");
        require(resolverDecisionBondWei_ > 0, "P42_RESOLVER_BOND_ZERO");
        if (betaBps_ > MAX_BETA_BPS) revert P42_BAD_BETA();
        owner = owner_;
        factory = msg.sender;
        resolver = resolver_;
        treasury = treasury_;
        submissionManager = IP42SubmissionChallengeHook(submissionManager_);
        challengeWindowSeconds = challengeWindowSeconds_;
        betaBps = betaBps_;
        minCounterBondWei = minCounterBondWei_;
        rerunCostWei = rerunCostWei_;
        rerunCostMultiplierBps = rerunCostMultiplierBps_;
        resolverDecisionBondWei = resolverDecisionBondWei_;
        resolverFraudWindowSeconds = resolverFraudWindowSeconds_;
    }

    function setPausedNewActions(bool paused) external onlyOwner {
        pausedNewActions = paused;
        emit NewActionsPaused(paused);
    }

    function requiredChallengeBond(uint256 disputedEntitlementWei) public view returns (uint256) {
        uint256 scaledDelayValue = P42Math.mulDiv(disputedEntitlementWei, betaBps, 10_000);
        uint256 scaledRerunCost = P42Math.mulDiv(rerunCostWei, rerunCostMultiplierBps, 10_000);
        uint256 required = minCounterBondWei;
        if (scaledDelayValue > required) required = scaledDelayValue;
        if (scaledRerunCost > required) required = scaledRerunCost;
        return required;
    }

    function challenge(
        uint256 submissionId,
        bytes32 expectedRevealInstanceHash,
        bytes32 reasonHash
    ) external payable {
        if (pausedNewActions) revert P42_PAUSED_NEW_ACTIONS();
        if (submissionId == 0) revert P42_BAD_SUBMISSION();
        if (reasonHash == bytes32(0)) revert P42_EMPTY_REASON();

        if (challenges[submissionId].challenger != address(0)) revert P42_ALREADY_CHALLENGED();

        // A solver must not challenge their own submission: a free self-
        // challenge would consume the challenge slot and shield a fraudulent
        // submission for the whole window, then be expired with both bonds
        // refunded (F3). Sock puppets at other addresses are further defused
        // by clearing the slot on expiry (see expireChallenge).
        if (submissionManager.solverOf(submissionId) == msg.sender) revert P42_SELF_CHALLENGE();

        // Size the counter-bond from the ledger-derived disputed entitlement so
        // a caller cannot collapse the value-proportional bond to the floor by
        // under-reporting it (H2). The submission manager is the trusted oracle.
        _requireRevealInstance(submissionId, expectedRevealInstanceHash);
        uint256 required = requiredChallengeBond(submissionManager.disputedEntitlementWei(submissionId));
        if (msg.value < required) revert P42_INSUFFICIENT_CHALLENGE_BOND(required, msg.value);

        submissionManager.markChallenged(submissionId);
        _openChallenge(submissionId, expectedRevealInstanceHash, reasonHash, msg.sender, msg.value);
    }

    function _openChallenge(
        uint256 submissionId,
        bytes32 revealInstanceHash,
        bytes32 reasonHash,
        address challenger,
        uint256 bondWei
    ) private {
        uint64 challengedAt = uint64(block.timestamp);
        uint64 proposedDisputeEndsAt = challengedAt + challengeWindowSeconds;
        uint64 maxDisputeEndsAt = submissionManager.maxDisputeDeadline(submissionId);
        uint64 disputeEndsAt = proposedDisputeEndsAt < maxDisputeEndsAt
            ? proposedDisputeEndsAt
            : maxDisputeEndsAt;
        bytes32 challengeInstanceHash = keccak256(
            abi.encode(
                address(this),
                block.chainid,
                submissionId,
                revealInstanceHash,
                challenger,
                reasonHash,
                challengedAt,
                disputeEndsAt
            )
        );
        challengeRevealInstanceHashOf[submissionId] = revealInstanceHash;
        challengeInstanceHashOf[submissionId] = challengeInstanceHash;
        challenges[submissionId] = Challenge({
            submissionId: submissionId,
            challenger: challenger,
            reasonHash: reasonHash,
            challengeBondWei: bondWei,
            challengedAt: challengedAt,
            disputeEndsAt: disputeEndsAt,
            resolved: false,
            decisionPending: false,
            challengerWins: false,
            transcriptHash: bytes32(0),
            transcriptURI: "",
            verdictHash: bytes32(0)
        });
        emit Challenged(
            submissionId,
            challenger,
            reasonHash,
            bondWei,
            disputeEndsAt,
            revealInstanceHash,
            challengeInstanceHash
        );
    }

    function resolve(
        uint256 submissionId,
        bytes32 expectedChallengeInstanceHash,
        bool challengerWins,
        bytes32 transcriptHash,
        string calldata transcriptURI,
        bytes32 verdictHash
    ) external payable onlyResolver {
        _resolve(
            submissionId,
            expectedChallengeInstanceHash,
            challengerWins,
            transcriptHash,
            transcriptURI,
            verdictHash,
            msg.sender
        );
    }

    function resolveFor(
        uint256 submissionId,
        bytes32 expectedChallengeInstanceHash,
        bool challengerWins,
        bytes32 transcriptHash,
        string calldata transcriptURI,
        bytes32 verdictHash,
        address resolverBondBeneficiary
    ) external payable onlyResolver {
        if (resolverBondBeneficiary == address(0)) revert P42_RESOLVER_BENEFICIARY_ZERO();
        _resolve(
            submissionId,
            expectedChallengeInstanceHash,
            challengerWins,
            transcriptHash,
            transcriptURI,
            verdictHash,
            resolverBondBeneficiary
        );
    }

    function _resolve(
        uint256 submissionId,
        bytes32 expectedChallengeInstanceHash,
        bool challengerWins,
        bytes32 transcriptHash,
        string calldata transcriptURI,
        bytes32 verdictHash,
        address resolverBondBeneficiary
    ) private {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        _requireChallengeInstance(submissionId, expectedChallengeInstanceHash);
        if (current.resolved || current.decisionPending) revert P42_ALREADY_RESOLVED();
        if (block.timestamp >= current.disputeEndsAt) {
            revert P42_DISPUTE_WINDOW_CLOSED(current.disputeEndsAt, uint64(block.timestamp));
        }
        if (msg.value < resolverDecisionBondWei) {
            revert P42_INSUFFICIENT_RESOLVER_BOND(resolverDecisionBondWei, msg.value);
        }
        if (transcriptHash == bytes32(0)) revert P42_EMPTY_TRANSCRIPT_HASH();
        if (bytes(transcriptURI).length == 0) revert P42_EMPTY_TRANSCRIPT_URI();
        if (verdictHash == bytes32(0)) revert P42_EMPTY_VERDICT_HASH();

        current.decisionPending = true;
        current.challengerWins = challengerWins;
        current.transcriptHash = transcriptHash;
        current.transcriptURI = transcriptURI;
        current.verdictHash = verdictHash;
        uint64 resolverBondReleaseAt = _resolverBondReleaseAt(submissionId);
        resolverBonds[submissionId] = ResolverBond({
            amountWei: msg.value,
            releaseAt: resolverBondReleaseAt,
            slashProofHash: bytes32(0)
        });
        resolverBondBeneficiaryOf[submissionId] = resolverBondBeneficiary;

        _emitResolverTranscriptPosted(submissionId, resolverBondReleaseAt);
    }

    /// @notice Applies a resolver decision only after its fraud window has
    /// elapsed unslashed. The resolver bond is released in the same transition,
    /// so a solver-favorable decision cannot occupy the sole challenge slot
    /// after it has returned the submission to Revealed.
    function finalizeResolution(uint256 submissionId, bytes32 expectedChallengeInstanceHash) public {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        _requireChallengeInstance(submissionId, expectedChallengeInstanceHash);
        if (!current.decisionPending) {
            if (current.resolved) revert P42_ALREADY_RESOLVED();
            revert P42_NO_PENDING_DECISION();
        }
        ResolverBond storage decisionBond = resolverBonds[submissionId];
        uint256 resolverBond = decisionBond.amountWei;
        if (resolverBond == 0) revert P42_NO_RESOLVER_BOND();
        if (block.timestamp < decisionBond.releaseAt) {
            revert P42_RESOLVER_BOND_LOCKED(decisionBond.releaseAt, uint64(block.timestamp));
        }

        address challenger = current.challenger;
        uint256 challengeBond = current.challengeBondWei;
        bool challengerWins = current.challengerWins;
        current.decisionPending = false;
        current.resolved = true;
        decisionBond.amountWei = 0;

        if (challengerWins) {
            claimableBondWei[challenger] += challengeBond;
        } else {
            claimableBondWei[treasury] += challengeBond;
        }
        address resolverBondBeneficiary = resolverBondBeneficiaryOf[submissionId];
        if (resolverBondBeneficiary == address(0)) revert P42_RESOLVER_BENEFICIARY_ZERO();
        delete resolverBondBeneficiaryOf[submissionId];
        claimableBondWei[resolverBondBeneficiary] += resolverBond;

        // On a challenger win the rejected solver's forfeited posting bond is
        // routed to the challenger. On a solver win, rearming is bounded by the
        // submission's immutable cumulative dispute deadline.
        submissionManager.resolveChallenge(submissionId, challengerWins, challenger);

        // A final solver-favorable verdict must not permanently consume the
        // challenge slot. The evidence remains in events; storage is cleared so
        // a fresh challenge can open only if the bounded window remains.
        if (!challengerWins) {
            delete challenges[submissionId];
        }

        emit ResolverBondReleased(submissionId, resolverBondBeneficiary, resolverBond, expectedChallengeInstanceHash);
        emit Resolved(submissionId, challengerWins, expectedChallengeInstanceHash);
    }

    /// @notice Permissionless timeout resolving a stalled challenge in the
    /// solver's favor once the dispute window closes without a resolver decision.
    /// Without this an offline or colluding resolver could freeze a Challenged
    /// submission forever, which also blocks the payout ledger's close() and
    /// therefore locks the whole pool (M1). Because no adjudication took place,
    /// the challenger's posted bond is returned to them.
    function expireChallenge(uint256 submissionId, bytes32 expectedChallengeInstanceHash) external {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        _requireChallengeInstance(submissionId, expectedChallengeInstanceHash);
        if (current.resolved) revert P42_ALREADY_RESOLVED();
        if (current.decisionPending) revert P42_DECISION_PENDING();
        if (block.timestamp < current.disputeEndsAt) {
            revert P42_DISPUTE_WINDOW_OPEN(current.disputeEndsAt, uint64(block.timestamp));
        }

        address challenger = current.challenger;
        uint256 refund = current.challengeBondWei;
        claimableBondWei[challenger] += refund;
        // Clear the challenge slot instead of marking it resolved: the
        // submission returns to Revealed with a re-armed window (see
        // P42SubmissionManager.resolveChallenge), so a DIFFERENT party can
        // still post a fresh challenge. Without this, a sock-puppet challenge
        // left to expire would burn the one-shot slot and permanently immunize
        // a fraudulent submission (F3). No resolver bond can exist on this
        // path (resolve() was never called), so deleting the record cannot
        // orphan resolverBonds accounting.
        delete challenges[submissionId];
        // Return the submission to Revealed so the solver can finalize; the
        // beneficiary argument is unused because the solver prevails by default.
        submissionManager.resolveChallenge(submissionId, false, address(0));

        emit ChallengeExpired(submissionId, challenger, refund, expectedChallengeInstanceHash);
        emit Resolved(submissionId, false, expectedChallengeInstanceHash);
    }

    function releaseResolverBond(uint256 submissionId, bytes32 expectedChallengeInstanceHash) external {
        finalizeResolution(submissionId, expectedChallengeInstanceHash);
    }

    function slashResolverBond(uint256 submissionId, bytes32 expectedChallengeInstanceHash, bytes32 proofHash)
        external
        onlyResolver
    {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        _requireChallengeInstance(submissionId, expectedChallengeInstanceHash);
        if (!current.decisionPending) revert P42_NO_PENDING_DECISION();
        if (proofHash == bytes32(0)) revert P42_EMPTY_FRAUD_PROOF_HASH();
        ResolverBond storage decisionBond = resolverBonds[submissionId];
        uint256 amount = decisionBond.amountWei;
        if (amount == 0) revert P42_NO_RESOLVER_BOND();
        if (block.timestamp >= decisionBond.releaseAt) {
            revert P42_RESOLVER_FRAUD_WINDOW_CLOSED(decisionBond.releaseAt, uint64(block.timestamp));
        }

        decisionBond.amountWei = 0;
        decisionBond.slashProofHash = proofHash;
        delete resolverBondBeneficiaryOf[submissionId];
        claimableBondWei[treasury] += amount;
        address challenger = current.challenger;
        uint256 challengeBond = current.challengeBondWei;
        claimableBondWei[challenger] += challengeBond;
        delete challenges[submissionId];
        submissionManager.cancelChallenge(submissionId);
        emit ResolverBondSlashed(submissionId, treasury, amount, proofHash, expectedChallengeInstanceHash);
        emit ResolverDecisionCancelled(submissionId, challenger, proofHash, expectedChallengeInstanceHash);
    }

    /// @notice Applies an objectively proven correction to a pending resolver
    /// decision. The resolver adapter may call this only after its immutable
    /// verifier gateway accepts a proof bound to this exact challenge instance.
    function applyObjectiveResolution(
        uint256 submissionId,
        bytes32 expectedChallengeInstanceHash,
        bool correctedChallengerWins,
        bytes32 proofHash,
        address proofBeneficiary
    ) external onlyResolver {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        _requireChallengeInstance(submissionId, expectedChallengeInstanceHash);
        if (!current.decisionPending) revert P42_NO_PENDING_DECISION();
        if (proofHash == bytes32(0)) revert P42_EMPTY_FRAUD_PROOF_HASH();
        if (proofBeneficiary == address(0)) revert P42_FRAUD_PROOF_BENEFICIARY_ZERO();
        if (correctedChallengerWins == current.challengerWins) {
            revert P42_OBJECTIVE_OUTCOME_NOT_CONTRADICTORY();
        }

        ResolverBond storage decisionBond = resolverBonds[submissionId];
        uint256 resolverBond = decisionBond.amountWei;
        if (resolverBond == 0) revert P42_NO_RESOLVER_BOND();
        if (block.timestamp >= decisionBond.releaseAt) {
            revert P42_RESOLVER_FRAUD_WINDOW_CLOSED(decisionBond.releaseAt, uint64(block.timestamp));
        }

        address challenger = current.challenger;
        uint256 challengeBond = current.challengeBondWei;
        current.decisionPending = false;
        current.resolved = true;
        current.challengerWins = correctedChallengerWins;
        decisionBond.amountWei = 0;
        decisionBond.slashProofHash = proofHash;
        delete resolverBondBeneficiaryOf[submissionId];

        // The proof beneficiary is journal-bound by the adapter, preventing a
        // mempool observer from redirecting the resolver-bond reward.
        claimableBondWei[proofBeneficiary] += resolverBond;
        if (correctedChallengerWins) {
            claimableBondWei[challenger] += challengeBond;
        } else {
            claimableBondWei[treasury] += challengeBond;
        }

        submissionManager.resolveObjectiveChallenge(submissionId, correctedChallengerWins, challenger);
        if (!correctedChallengerWins) delete challenges[submissionId];

        emit ResolverBondSlashed(
            submissionId, proofBeneficiary, resolverBond, proofHash, expectedChallengeInstanceHash
        );
        emit ObjectiveFraudProven(
            submissionId,
            proofBeneficiary,
            proofHash,
            correctedChallengerWins,
            resolverBond,
            expectedChallengeInstanceHash
        );
        emit Resolved(submissionId, correctedChallengerWins, expectedChallengeInstanceHash);
    }

    /// @notice Canonical public input for an objective verifier proof. The
    /// reveal fingerprint binds the solver, commitment, solution hash/CID,
    /// claimed score, and challenge deadline in P42SubmissionManager.
    function objectiveProofContext(uint256 submissionId, bytes32 expectedChallengeInstanceHash)
        external
        view
        returns (bytes32 contextHash, bool pendingChallengerWins)
    {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        _requireChallengeInstance(submissionId, expectedChallengeInstanceHash);
        if (!current.decisionPending) revert P42_NO_PENDING_DECISION();
        bytes32 pendingDecisionContext = keccak256(
            abi.encode(
                expectedChallengeInstanceHash,
                challengeRevealInstanceHashOf[submissionId],
                current.challenger,
                current.reasonHash,
                current.challengerWins,
                current.transcriptHash,
                keccak256(bytes(current.transcriptURI)),
                current.verdictHash
            )
        );
        contextHash = keccak256(
            abi.encode(
                "P42_OBJECTIVE_CHALLENGE_CONTEXT_V1",
                block.chainid,
                address(this),
                address(submissionManager),
                _objectiveBindingContext(),
                submissionId,
                pendingDecisionContext
            )
        );
        pendingChallengerWins = current.challengerWins;
    }

    function objectiveBinding()
        public
        view
        returns (address registry, uint256 problemId, bytes32 packageHash, bytes32 programId)
    {
        return IP42ObjectiveBindingFactory(factory).objectiveBindingOf(address(this));
    }

    function _objectiveBindingContext() private view returns (bytes32) {
        (address registry, uint256 problemId, bytes32 packageHash, bytes32 programId) = objectiveBinding();
        return keccak256(abi.encode(registry, problemId, packageHash, programId));
    }

    function claimBond() external nonReentrant {
        uint256 amount = claimableBondWei[msg.sender];
        if (amount == 0) revert P42_NO_BOND_TO_CLAIM();
        claimableBondWei[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit BondClaimed(msg.sender, amount);
    }

    function _resolverBondReleaseAt(uint256 submissionId) private view returns (uint64) {
        uint256 proposedReleaseAt = block.timestamp + resolverFraudWindowSeconds;
        uint64 settlementDeadline = submissionManager.maxDisputeDeadline(submissionId);
        if (proposedReleaseAt > settlementDeadline) {
            revert P42_SETTLEMENT_HORIZON_EXCEEDED(settlementDeadline, uint64(proposedReleaseAt));
        }
        return uint64(proposedReleaseAt);
    }

    function _requireChallengeInstance(uint256 submissionId, bytes32 expectedChallengeInstanceHash) private view {
        if (expectedChallengeInstanceHash == bytes32(0)) revert P42_EMPTY_CHALLENGE_INSTANCE_HASH();
        bytes32 actualChallengeInstanceHash = challengeInstanceHashOf[submissionId];
        if (actualChallengeInstanceHash != expectedChallengeInstanceHash) {
            revert P42_CHALLENGE_INSTANCE_MISMATCH(expectedChallengeInstanceHash, actualChallengeInstanceHash);
        }
    }

    function _requireRevealInstance(uint256 submissionId, bytes32 expectedRevealInstanceHash) private view {
        if (expectedRevealInstanceHash == bytes32(0)) revert P42_EMPTY_REVEAL_INSTANCE_HASH();
        bytes32 actualRevealInstanceHash = submissionManager.revealInstanceHashOf(submissionId);
        if (actualRevealInstanceHash != expectedRevealInstanceHash) {
            revert P42_REVEAL_INSTANCE_MISMATCH(expectedRevealInstanceHash, actualRevealInstanceHash);
        }
    }

    function _emitResolverTranscriptPosted(uint256 submissionId, uint64 releaseAt) private {
        Challenge storage current = challenges[submissionId];
        emit ResolverTranscriptPosted(
            submissionId,
            msg.sender,
            current.transcriptHash,
            current.transcriptURI,
            current.verdictHash,
            resolverBondBeneficiaryOf[submissionId],
            resolverBonds[submissionId].amountWei,
            releaseAt,
            current.challengerWins,
            challengeInstanceHashOf[submissionId]
        );
    }
}
