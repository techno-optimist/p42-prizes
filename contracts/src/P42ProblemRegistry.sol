// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42RegisteredPool {
    function everFunded() external view returns (bool);
}

/// @notice Catalog and metadata anchor for Phase 1 problems.
/// Problem metadata is editable while unfunded, then immutable as soon as the
/// pool receives funds or the owner explicitly freezes it.
contract P42ProblemRegistry {
    error P42_NOT_OWNER();
    error P42_ZERO_HASH();
    error P42_EMPTY_URI();
    error P42_ZERO_ADDRESS();
    error P42_BAD_WINDOW();
    error P42_ALREADY_FROZEN();
    error P42_NOT_FUNDED();
    error P42_UNKNOWN_PROBLEM();

    struct ProblemConfig {
        bytes32 specHash;
        bytes32 verifierSourceHash;
        bytes32 verifierImageHash;
        bytes32 admissionMatrixHash;
        string metadataURI;
        address pool;
        address ledger;
        address submissionManager;
        address challengeManager;
        uint64 challengeWindowSeconds;
        uint256 minImprovementAtoms;
    }

    struct Problem {
        bytes32 specHash;
        bytes32 verifierSourceHash;
        bytes32 verifierImageHash;
        bytes32 admissionMatrixHash;
        string metadataURI;
        address pool;
        address ledger;
        address submissionManager;
        address challengeManager;
        uint64 challengeWindowSeconds;
        uint256 minImprovementAtoms;
        bool frozen;
    }

    address public immutable owner;
    uint256 public problemCount;

    mapping(uint256 => Problem) public problems;

    event ProblemRegistered(
        uint256 indexed problemId,
        bytes32 indexed specHash,
        bytes32 indexed verifierImageHash,
        address pool,
        string metadataURI
    );
    event ProblemUpdated(uint256 indexed problemId, bytes32 indexed specHash, bytes32 indexed verifierImageHash);
    event ProblemFrozen(uint256 indexed problemId);

    modifier onlyOwner() {
        if (msg.sender != owner) revert P42_NOT_OWNER();
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert P42_ZERO_ADDRESS();
        owner = owner_;
    }

    function register(ProblemConfig calldata config) external onlyOwner returns (uint256 problemId) {
        _validateConfig(config);
        problemId = ++problemCount;
        _store(problemId, config, false);
        emit ProblemRegistered(problemId, config.specHash, config.verifierImageHash, config.pool, config.metadataURI);
    }

    function updateBeforeFunding(uint256 problemId, ProblemConfig calldata config) external onlyOwner {
        _requireExisting(problemId);
        if (isFrozen(problemId)) revert P42_ALREADY_FROZEN();
        _validateConfig(config);
        _store(problemId, config, false);
        emit ProblemUpdated(problemId, config.specHash, config.verifierImageHash);
    }

    function freeze(uint256 problemId) external onlyOwner {
        Problem storage problem = _requireExisting(problemId);
        if (problem.frozen) revert P42_ALREADY_FROZEN();
        problem.frozen = true;
        emit ProblemFrozen(problemId);
    }

    /// @notice Permissionless one-way latch that persists the explicit freeze
    /// after the pool has accepted legitimate funding. Forced ETH does not set
    /// everFunded and therefore cannot freeze a draft registry entry.
    function latchFrozen(uint256 problemId) external {
        Problem storage problem = _requireExisting(problemId);
        if (problem.frozen) revert P42_ALREADY_FROZEN();
        if (!IP42RegisteredPool(problem.pool).everFunded()) revert P42_NOT_FUNDED();
        problem.frozen = true;
        emit ProblemFrozen(problemId);
    }

    function isFrozen(uint256 problemId) public view returns (bool) {
        Problem storage problem = _requireExistingView(problemId);
        if (problem.frozen) return true;
        return IP42RegisteredPool(problem.pool).everFunded();
    }

    function explicitlyFrozen(uint256 problemId) external view returns (bool) {
        return _requireExistingView(problemId).frozen;
    }

    function problemPool(uint256 problemId) external view returns (address) {
        return _requireExistingView(problemId).pool;
    }

    function problemHashes(uint256 problemId) external view returns (
        bytes32 specHash,
        bytes32 verifierSourceHash,
        bytes32 verifierImageHash,
        bytes32 admissionMatrixHash
    ) {
        Problem storage problem = _requireExistingView(problemId);
        return (
            problem.specHash,
            problem.verifierSourceHash,
            problem.verifierImageHash,
            problem.admissionMatrixHash
        );
    }

    function _store(uint256 problemId, ProblemConfig calldata config, bool frozen) private {
        Problem storage problem = problems[problemId];
        problem.specHash = config.specHash;
        problem.verifierSourceHash = config.verifierSourceHash;
        problem.verifierImageHash = config.verifierImageHash;
        problem.admissionMatrixHash = config.admissionMatrixHash;
        problem.metadataURI = config.metadataURI;
        problem.pool = config.pool;
        problem.ledger = config.ledger;
        problem.submissionManager = config.submissionManager;
        problem.challengeManager = config.challengeManager;
        problem.challengeWindowSeconds = config.challengeWindowSeconds;
        problem.minImprovementAtoms = config.minImprovementAtoms;
        problem.frozen = frozen;
    }

    function _validateConfig(ProblemConfig calldata config) private pure {
        if (
            config.specHash == bytes32(0)
                || config.verifierSourceHash == bytes32(0)
                || config.verifierImageHash == bytes32(0)
                || config.admissionMatrixHash == bytes32(0)
        ) {
            revert P42_ZERO_HASH();
        }
        if (bytes(config.metadataURI).length == 0) revert P42_EMPTY_URI();
        if (
            config.pool == address(0)
                || config.ledger == address(0)
                || config.submissionManager == address(0)
                || config.challengeManager == address(0)
        ) {
            revert P42_ZERO_ADDRESS();
        }
        if (config.challengeWindowSeconds == 0) revert P42_BAD_WINDOW();
    }

    function _requireExisting(uint256 problemId) private view returns (Problem storage problem) {
        problem = problems[problemId];
        if (problem.pool == address(0)) revert P42_UNKNOWN_PROBLEM();
    }

    function _requireExistingView(uint256 problemId) private view returns (Problem storage problem) {
        problem = problems[problemId];
        if (problem.pool == address(0)) revert P42_UNKNOWN_PROBLEM();
    }
}
