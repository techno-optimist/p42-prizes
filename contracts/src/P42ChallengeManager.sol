// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42SubmissionChallengeHook {
    function markChallenged(uint256 submissionId) external;
    function resolveChallenge(uint256 submissionId, bool challengerWins) external;
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
    error P42_UNKNOWN_CHALLENGE();
    error P42_ALREADY_RESOLVED();
    error P42_INSUFFICIENT_CHALLENGE_BOND(uint256 required, uint256 received);
    error P42_INSUFFICIENT_RESOLVER_BOND(uint256 required, uint256 received);
    error P42_EMPTY_TRANSCRIPT_HASH();
    error P42_EMPTY_TRANSCRIPT_URI();
    error P42_EMPTY_VERDICT_HASH();
    error P42_NO_BOND_TO_CLAIM();
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
        uint256 resolverBondWei;
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

    bool public pausedNewActions;
    bool private _claiming;

    mapping(uint256 => Challenge) public challenges;
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
        uint256 resolverBondWei
    );
    event Resolved(uint256 indexed submissionId, bool challengerWins);
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
        uint256 resolverDecisionBondWei_
    ) {
        require(owner_ != address(0), "P42_OWNER_ZERO");
        require(resolver_ != address(0), "P42_RESOLVER_ZERO");
        require(treasury_ != address(0), "P42_TREASURY_ZERO");
        require(submissionManager_ != address(0), "P42_SUBMISSION_MANAGER_ZERO");
        require(challengeWindowSeconds_ > 0, "P42_WINDOW_ZERO");
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
    }

    function setPausedNewActions(bool paused) external onlyOwner {
        pausedNewActions = paused;
        emit NewActionsPaused(paused);
    }

    function requiredChallengeBond(uint256 finalizingEntitlementWei) public view returns (uint256) {
        uint256 scaledDelayValue = finalizingEntitlementWei * betaBps / 10_000;
        uint256 scaledRerunCost = rerunCostWei * rerunCostMultiplierBps / 10_000;
        uint256 required = minCounterBondWei;
        if (scaledDelayValue > required) required = scaledDelayValue;
        if (scaledRerunCost > required) required = scaledRerunCost;
        return required;
    }

    function challenge(
        uint256 submissionId,
        bytes32 reasonHash,
        uint256 finalizingEntitlementWei
    ) external payable {
        if (pausedNewActions) revert P42_PAUSED_NEW_ACTIONS();
        if (submissionId == 0) revert P42_BAD_SUBMISSION();
        if (reasonHash == bytes32(0)) revert P42_EMPTY_REASON();

        Challenge storage existing = challenges[submissionId];
        if (existing.challenger != address(0)) revert P42_ALREADY_CHALLENGED();

        uint256 required = requiredChallengeBond(finalizingEntitlementWei);
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
            verdictHash: bytes32(0),
            resolverBondWei: 0
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
        current.resolverBondWei = msg.value;

        if (challengerWins) {
            claimableBondWei[current.challenger] += current.challengeBondWei;
        } else {
            claimableBondWei[treasury] += current.challengeBondWei;
        }
        claimableBondWei[msg.sender] += msg.value;
        submissionManager.resolveChallenge(submissionId, challengerWins);

        emit ResolverTranscriptPosted(
            submissionId,
            msg.sender,
            transcriptHash,
            transcriptURI,
            verdictHash,
            msg.value
        );
        emit Resolved(submissionId, challengerWins);
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
