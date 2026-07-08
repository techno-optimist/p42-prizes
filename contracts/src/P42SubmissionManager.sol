// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42PoolBalance {
    function funded() external view returns (uint256);
}

interface IP42CreditLedger {
    function recordCredit(address solver, uint256 atoms) external;
}

/// @notice Commit/reveal/finalize scaffold for the Phase 1 testnet path.
/// It makes the verifier-adjacent economic invariants executable before the
/// full fraud-proof resolver lands.
contract P42SubmissionManager {
    error P42_NOT_OWNER();
    error P42_PAUSED_NEW_ACTIONS();
    error P42_BAD_ALPHA();
    error P42_BAD_WINDOW();
    error P42_EMPTY_COMMITMENT();
    error P42_EMPTY_DA_HASH();
    error P42_EMPTY_SOLUTION_CID();
    error P42_BAD_COMMITMENT_REVEAL();
    error P42_NOT_SOLVER();
    error P42_BAD_SUBMISSION_STATUS(SubmissionStatus expected, SubmissionStatus actual);
    error P42_ZERO_IMPROVEMENT();
    error P42_CHALLENGE_WINDOW_OPEN(uint64 endsAt, uint64 nowAt);
    error P42_EMPTY_PERMANENCE_HASH();
    error P42_INSUFFICIENT_POSTING_BOND(uint256 required, uint256 received);
    error P42_UNKNOWN_SUBMISSION();
    error P42_BOND_UNDERCOVERS_ENTITLEMENT(uint256 required, uint256 posted);

    uint16 public constant MAX_ALPHA_BPS = 10_000;

    enum SubmissionStatus {
        None,
        Committed,
        Revealed,
        Finalized
    }

    struct Submission {
        address solver;
        bytes32 commitment;
        bytes32 commitDaHash;
        uint256 bondWei;
        uint256 poolAtSubmissionWei;
        uint256 requiredBondWei;
        uint256 improvementAtoms;
        int256 claimedScoreAtoms;
        string solutionCid;
        bytes32 permanenceHash;
        uint64 committedAt;
        uint64 revealedAt;
        uint64 challengeEndsAt;
        SubmissionStatus status;
    }

    address public immutable owner;
    IP42PoolBalance public immutable pool;
    IP42CreditLedger public immutable ledger;
    uint16 public immutable alphaBps;
    uint256 public immutable minPostingBondWei;
    uint64 public immutable challengeWindowSeconds;
    bool public pausedNewActions;
    uint256 public submissionCount;

    mapping(uint256 => Submission) public submissions;

    event NewActionsPaused(bool paused);
    event Committed(
        uint256 indexed submissionId,
        address indexed solver,
        bytes32 indexed commitment,
        bytes32 commitDaHash,
        uint256 bondWei,
        uint256 poolAtSubmissionWei,
        uint256 requiredBondWei
    );
    event Revealed(
        uint256 indexed submissionId,
        address indexed solver,
        string solutionCid,
        uint256 improvementAtoms,
        int256 claimedScoreAtoms,
        uint64 challengeEndsAt
    );
    event Finalized(
        uint256 indexed submissionId,
        address indexed solver,
        uint256 improvementAtoms,
        bytes32 permanenceHash,
        uint256 poolAtFinalizationWei
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert P42_NOT_OWNER();
        _;
    }

    constructor(
        address pool_,
        address ledger_,
        address owner_,
        uint16 alphaBps_,
        uint256 minPostingBondWei_,
        uint64 challengeWindowSeconds_
    ) {
        require(pool_ != address(0), "P42_POOL_ZERO");
        require(ledger_ != address(0), "P42_LEDGER_ZERO");
        require(owner_ != address(0), "P42_OWNER_ZERO");
        if (alphaBps_ > MAX_ALPHA_BPS) revert P42_BAD_ALPHA();
        if (challengeWindowSeconds_ == 0) revert P42_BAD_WINDOW();
        pool = IP42PoolBalance(pool_);
        ledger = IP42CreditLedger(ledger_);
        owner = owner_;
        alphaBps = alphaBps_;
        minPostingBondWei = minPostingBondWei_;
        challengeWindowSeconds = challengeWindowSeconds_;
    }

    function setPausedNewActions(bool paused) external onlyOwner {
        pausedNewActions = paused;
        emit NewActionsPaused(paused);
    }

    function requiredPostingBondForPool(uint256 poolWei) public view returns (uint256) {
        uint256 scaled = poolWei * alphaBps / 10_000;
        return scaled > minPostingBondWei ? scaled : minPostingBondWei;
    }

    function requiredPostingBondNow() external view returns (uint256) {
        return requiredPostingBondForPool(pool.funded());
    }

    function commit(bytes32 commitment, bytes32 commitDaHash) external payable returns (uint256 submissionId) {
        if (pausedNewActions) revert P42_PAUSED_NEW_ACTIONS();
        if (commitment == bytes32(0)) revert P42_EMPTY_COMMITMENT();
        if (commitDaHash == bytes32(0)) revert P42_EMPTY_DA_HASH();

        uint256 poolAtSubmission = pool.funded();
        uint256 required = requiredPostingBondForPool(poolAtSubmission);
        if (msg.value < required) revert P42_INSUFFICIENT_POSTING_BOND(required, msg.value);

        submissionId = ++submissionCount;
        submissions[submissionId] = Submission({
            solver: msg.sender,
            commitment: commitment,
            commitDaHash: commitDaHash,
            bondWei: msg.value,
            poolAtSubmissionWei: poolAtSubmission,
            requiredBondWei: required,
            improvementAtoms: 0,
            claimedScoreAtoms: 0,
            solutionCid: "",
            permanenceHash: bytes32(0),
            committedAt: uint64(block.timestamp),
            revealedAt: 0,
            challengeEndsAt: 0,
            status: SubmissionStatus.Committed
        });
        emit Committed(submissionId, msg.sender, commitment, commitDaHash, msg.value, poolAtSubmission, required);
    }

    function reveal(
        uint256 submissionId,
        string calldata solutionCid,
        int256 claimedScoreAtoms,
        uint256 improvementAtoms,
        string calldata salt
    ) external {
        Submission storage submission = _requireSubmission(submissionId);
        if (msg.sender != submission.solver) revert P42_NOT_SOLVER();
        _requireStatus(submission, SubmissionStatus.Committed);
        if (bytes(solutionCid).length == 0) revert P42_EMPTY_SOLUTION_CID();
        if (improvementAtoms == 0) revert P42_ZERO_IMPROVEMENT();

        bytes32 revealedCommitment = keccak256(bytes(commitPreimage(solutionCid, msg.sender, salt)));
        if (revealedCommitment != submission.commitment) revert P42_BAD_COMMITMENT_REVEAL();

        uint64 challengeEndsAt = uint64(block.timestamp) + challengeWindowSeconds;
        submission.solutionCid = solutionCid;
        submission.claimedScoreAtoms = claimedScoreAtoms;
        submission.improvementAtoms = improvementAtoms;
        submission.revealedAt = uint64(block.timestamp);
        submission.challengeEndsAt = challengeEndsAt;
        submission.status = SubmissionStatus.Revealed;

        emit Revealed(submissionId, msg.sender, solutionCid, improvementAtoms, claimedScoreAtoms, challengeEndsAt);
    }

    function finalize(uint256 submissionId, bytes32 permanenceHash) external {
        Submission storage submission = _requireSubmission(submissionId);
        if (msg.sender != submission.solver) revert P42_NOT_SOLVER();
        _requireStatus(submission, SubmissionStatus.Revealed);
        if (permanenceHash == bytes32(0)) revert P42_EMPTY_PERMANENCE_HASH();
        if (block.timestamp < submission.challengeEndsAt) {
            revert P42_CHALLENGE_WINDOW_OPEN(submission.challengeEndsAt, uint64(block.timestamp));
        }

        uint256 poolAtFinalization = pool.funded();
        uint256 required = requiredPostingBondForPool(poolAtFinalization);
        if (submission.bondWei < required) {
            revert P42_BOND_UNDERCOVERS_ENTITLEMENT(required, submission.bondWei);
        }

        submission.permanenceHash = permanenceHash;
        submission.status = SubmissionStatus.Finalized;
        ledger.recordCredit(submission.solver, submission.improvementAtoms);

        emit Finalized(
            submissionId,
            submission.solver,
            submission.improvementAtoms,
            permanenceHash,
            poolAtFinalization
        );
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

    function _requireSubmission(uint256 submissionId) private view returns (Submission storage submission) {
        submission = submissions[submissionId];
        if (submission.solver == address(0)) revert P42_UNKNOWN_SUBMISSION();
    }

    function _requireStatus(Submission storage submission, SubmissionStatus expected) private view {
        if (submission.status != expected) {
            revert P42_BAD_SUBMISSION_STATUS(expected, submission.status);
        }
    }
}
