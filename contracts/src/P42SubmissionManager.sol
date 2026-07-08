// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42PoolBalance {
    function funded() external view returns (uint256);
}

/// @notice Commit/bond scaffold for the Phase 1 testnet path.
/// It does not finalize verifier results yet; it makes the bond and commitment
/// invariants executable before the full challenge manager lands.
contract P42SubmissionManager {
    error P42_NOT_OWNER();
    error P42_PAUSED_NEW_ACTIONS();
    error P42_BAD_ALPHA();
    error P42_EMPTY_COMMITMENT();
    error P42_INSUFFICIENT_POSTING_BOND(uint256 required, uint256 received);
    error P42_UNKNOWN_SUBMISSION();
    error P42_BOND_UNDERCOVERS_ENTITLEMENT(uint256 required, uint256 posted);

    uint16 public constant MAX_ALPHA_BPS = 10_000;

    struct Submission {
        address solver;
        bytes32 commitment;
        uint256 bondWei;
        uint256 poolAtSubmissionWei;
        uint256 requiredBondWei;
        uint64 committedAt;
    }

    address public immutable owner;
    IP42PoolBalance public immutable pool;
    uint16 public immutable alphaBps;
    uint256 public immutable minPostingBondWei;
    bool public pausedNewActions;
    uint256 public submissionCount;

    mapping(uint256 => Submission) public submissions;

    event NewActionsPaused(bool paused);
    event Committed(
        uint256 indexed submissionId,
        address indexed solver,
        bytes32 indexed commitment,
        uint256 bondWei,
        uint256 poolAtSubmissionWei,
        uint256 requiredBondWei
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert P42_NOT_OWNER();
        _;
    }

    constructor(address pool_, address owner_, uint16 alphaBps_, uint256 minPostingBondWei_) {
        require(pool_ != address(0), "P42_POOL_ZERO");
        require(owner_ != address(0), "P42_OWNER_ZERO");
        if (alphaBps_ > MAX_ALPHA_BPS) revert P42_BAD_ALPHA();
        pool = IP42PoolBalance(pool_);
        owner = owner_;
        alphaBps = alphaBps_;
        minPostingBondWei = minPostingBondWei_;
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

    function commit(bytes32 commitment) external payable returns (uint256 submissionId) {
        if (pausedNewActions) revert P42_PAUSED_NEW_ACTIONS();
        if (commitment == bytes32(0)) revert P42_EMPTY_COMMITMENT();

        uint256 poolAtSubmission = pool.funded();
        uint256 required = requiredPostingBondForPool(poolAtSubmission);
        if (msg.value < required) revert P42_INSUFFICIENT_POSTING_BOND(required, msg.value);

        submissionId = ++submissionCount;
        submissions[submissionId] = Submission({
            solver: msg.sender,
            commitment: commitment,
            bondWei: msg.value,
            poolAtSubmissionWei: poolAtSubmission,
            requiredBondWei: required,
            committedAt: uint64(block.timestamp)
        });
        emit Committed(submissionId, msg.sender, commitment, msg.value, poolAtSubmission, required);
    }

    function bondCoversEntitlement(uint256 submissionId, uint256 entitlementWei) public view returns (bool) {
        Submission storage submission = submissions[submissionId];
        if (submission.solver == address(0)) revert P42_UNKNOWN_SUBMISSION();
        uint256 required = requiredPostingBondForPool(entitlementWei);
        return submission.bondWei >= required;
    }

    function requireFinalizeBond(uint256 submissionId, uint256 entitlementWei) external view {
        Submission storage submission = submissions[submissionId];
        if (submission.solver == address(0)) revert P42_UNKNOWN_SUBMISSION();
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
}
