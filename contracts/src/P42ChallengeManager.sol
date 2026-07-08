// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42SubmissionChallengeHook {
    function markChallenged(uint256 submissionId) external;
    function resolveChallenge(uint256 submissionId, bool challengerWins, address beneficiary) external;
    function disputedEntitlementWei(uint256 submissionId) external view returns (uint256);
    function solverOf(uint256 submissionId) external view returns (address);
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
    error P42_INSUFFICIENT_CHALLENGE_BOND(uint256 required, uint256 received);
    error P42_INSUFFICIENT_RESOLVER_BOND(uint256 required, uint256 received);
    error P42_DISPUTE_WINDOW_OPEN(uint64 endsAt, uint64 nowAt);
    error P42_EMPTY_TRANSCRIPT_HASH();
    error P42_EMPTY_TRANSCRIPT_URI();
    error P42_EMPTY_VERDICT_HASH();
    error P42_NO_BOND_TO_CLAIM();
    error P42_NO_RESOLVER_BOND();
    error P42_RESOLVER_BOND_LOCKED(uint64 releaseAt, uint64 nowAt);
    error P42_EMPTY_FRAUD_PROOF_HASH();
    error P42_TRANSFER_FAILED();

    uint16 public constant MAX_BETA_BPS = 10_000;

    struct Challenge {
        uint256 submissionId;
        address challenger;
        bytes32 reasonHash;
        uint256 challengeBondWei;
        uint64 challengedAt;
        uint64 disputeEndsAt;
        bool resolved;
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
    mapping(uint256 => ResolverBond) public resolverBonds;
    mapping(address => uint256) public claimableBondWei;

    event NewActionsPaused(bool paused);
    event Challenged(
        uint256 indexed submissionId,
        address indexed challenger,
        bytes32 indexed reasonHash,
        uint256 bondWei,
        uint64 disputeEndsAt
    );
    event ResolverTranscriptPosted(
        uint256 indexed submissionId,
        address indexed resolver,
        bytes32 transcriptHash,
        string transcriptURI,
        bytes32 verdictHash,
        uint256 resolverBondWei,
        uint64 resolverBondReleaseAt
    );
    event Resolved(uint256 indexed submissionId, bool challengerWins);
    event ChallengeExpired(uint256 indexed submissionId, address indexed challenger, uint256 refundedBondWei);
    event ResolverBondReleased(uint256 indexed submissionId, address indexed resolver, uint256 amount);
    event ResolverBondSlashed(uint256 indexed submissionId, address indexed treasury, uint256 amount, bytes32 proofHash);
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
        require(challengeWindowSeconds_ > 0, "P42_WINDOW_ZERO");
        require(resolverFraudWindowSeconds_ > 0, "P42_FRAUD_WINDOW_ZERO");
        if (betaBps_ > MAX_BETA_BPS) revert P42_BAD_BETA();
        owner = owner_;
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
        uint256 scaledDelayValue = disputedEntitlementWei * betaBps / 10_000;
        uint256 scaledRerunCost = rerunCostWei * rerunCostMultiplierBps / 10_000;
        uint256 required = minCounterBondWei;
        if (scaledDelayValue > required) required = scaledDelayValue;
        if (scaledRerunCost > required) required = scaledRerunCost;
        return required;
    }

    function challenge(
        uint256 submissionId,
        bytes32 reasonHash
    ) external payable {
        if (pausedNewActions) revert P42_PAUSED_NEW_ACTIONS();
        if (submissionId == 0) revert P42_BAD_SUBMISSION();
        if (reasonHash == bytes32(0)) revert P42_EMPTY_REASON();

        Challenge storage existing = challenges[submissionId];
        if (existing.challenger != address(0)) revert P42_ALREADY_CHALLENGED();

        // A solver must not challenge their own submission: a free self-
        // challenge would consume the challenge slot and shield a fraudulent
        // submission for the whole window, then be expired with both bonds
        // refunded (F3). Sock puppets at other addresses are further defused
        // by clearing the slot on expiry (see expireChallenge).
        if (submissionManager.solverOf(submissionId) == msg.sender) revert P42_SELF_CHALLENGE();

        // Size the counter-bond from the ledger-derived disputed entitlement so
        // a caller cannot collapse the value-proportional bond to the floor by
        // under-reporting it (H2). The submission manager is the trusted oracle.
        uint256 disputedEntitlementWei = submissionManager.disputedEntitlementWei(submissionId);
        uint256 required = requiredChallengeBond(disputedEntitlementWei);
        if (msg.value < required) revert P42_INSUFFICIENT_CHALLENGE_BOND(required, msg.value);

        submissionManager.markChallenged(submissionId);

        uint64 disputeEndsAt = uint64(block.timestamp) + challengeWindowSeconds;
        challenges[submissionId] = Challenge({
            submissionId: submissionId,
            challenger: msg.sender,
            reasonHash: reasonHash,
            challengeBondWei: msg.value,
            challengedAt: uint64(block.timestamp),
            disputeEndsAt: disputeEndsAt,
            resolved: false,
            challengerWins: false,
            transcriptHash: bytes32(0),
            transcriptURI: "",
            verdictHash: bytes32(0)
        });
        emit Challenged(submissionId, msg.sender, reasonHash, msg.value, disputeEndsAt);
    }

    function resolve(
        uint256 submissionId,
        bool challengerWins,
        bytes32 transcriptHash,
        string calldata transcriptURI,
        bytes32 verdictHash
    ) external payable onlyResolver {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        if (current.resolved) revert P42_ALREADY_RESOLVED();
        if (msg.value < resolverDecisionBondWei) {
            revert P42_INSUFFICIENT_RESOLVER_BOND(resolverDecisionBondWei, msg.value);
        }
        if (transcriptHash == bytes32(0)) revert P42_EMPTY_TRANSCRIPT_HASH();
        if (bytes(transcriptURI).length == 0) revert P42_EMPTY_TRANSCRIPT_URI();
        if (verdictHash == bytes32(0)) revert P42_EMPTY_VERDICT_HASH();

        current.resolved = true;
        current.challengerWins = challengerWins;
        current.transcriptHash = transcriptHash;
        current.transcriptURI = transcriptURI;
        current.verdictHash = verdictHash;
        uint64 resolverBondReleaseAt = uint64(block.timestamp) + resolverFraudWindowSeconds;
        resolverBonds[submissionId] = ResolverBond({
            amountWei: msg.value,
            releaseAt: resolverBondReleaseAt,
            slashProofHash: bytes32(0)
        });

        if (challengerWins) {
            claimableBondWei[current.challenger] += current.challengeBondWei;
        } else {
            claimableBondWei[treasury] += current.challengeBondWei;
        }
        // On a challenger win the rejected solver's forfeited posting bond is
        // routed to the challenger (not treasury) so a successful challenge is
        // net-positive; the beneficiary is ignored when the solver prevails (M2).
        submissionManager.resolveChallenge(submissionId, challengerWins, current.challenger);

        emit ResolverTranscriptPosted(
            submissionId,
            msg.sender,
            transcriptHash,
            transcriptURI,
            verdictHash,
            msg.value,
            resolverBondReleaseAt
        );
        emit Resolved(submissionId, challengerWins);
    }

    /// @notice Permissionless timeout resolving a stalled challenge in the
    /// solver's favor once the dispute window closes without a resolver decision.
    /// Without this an offline or colluding resolver could freeze a Challenged
    /// submission forever, which also blocks the payout ledger's close() and
    /// therefore locks the whole pool (M1). Because no adjudication took place,
    /// the challenger's posted bond is returned to them.
    function expireChallenge(uint256 submissionId) external {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        if (current.resolved) revert P42_ALREADY_RESOLVED();
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

        emit ChallengeExpired(submissionId, challenger, refund);
        emit Resolved(submissionId, false);
    }

    function releaseResolverBond(uint256 submissionId) external {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        ResolverBond storage decisionBond = resolverBonds[submissionId];
        uint256 amount = decisionBond.amountWei;
        if (amount == 0) revert P42_NO_RESOLVER_BOND();
        if (block.timestamp < decisionBond.releaseAt) {
            revert P42_RESOLVER_BOND_LOCKED(decisionBond.releaseAt, uint64(block.timestamp));
        }

        decisionBond.amountWei = 0;
        claimableBondWei[resolver] += amount;
        emit ResolverBondReleased(submissionId, resolver, amount);
    }

    function slashResolverBond(uint256 submissionId, bytes32 proofHash) external onlyOwner {
        Challenge storage current = challenges[submissionId];
        if (current.challenger == address(0)) revert P42_UNKNOWN_CHALLENGE();
        if (proofHash == bytes32(0)) revert P42_EMPTY_FRAUD_PROOF_HASH();
        ResolverBond storage decisionBond = resolverBonds[submissionId];
        uint256 amount = decisionBond.amountWei;
        if (amount == 0) revert P42_NO_RESOLVER_BOND();

        decisionBond.amountWei = 0;
        decisionBond.slashProofHash = proofHash;
        claimableBondWei[treasury] += amount;
        emit ResolverBondSlashed(submissionId, treasury, amount, proofHash);
    }

    function claimBond() external nonReentrant {
        uint256 amount = claimableBondWei[msg.sender];
        if (amount == 0) revert P42_NO_BOND_TO_CLAIM();
        claimableBondWei[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit BondClaimed(msg.sender, amount);
    }
}
