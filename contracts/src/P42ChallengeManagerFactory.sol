// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {P42ChallengeManager} from "./P42ChallengeManager.sol";

interface IP42CanonicalSubmissionManagerFactory {
    function isCanonicalSubmissionManager(address submissionManager) external view returns (bool);
    function configurationHashOf(address submissionManager) external view returns (bytes32);
}

interface IP42CanonicalSubmissionManager {
    function owner() external view returns (address);
    function treasury() external view returns (address);
    function fundingAuthorizer() external view returns (address);
    function pool() external view returns (address);
    function ledger() external view returns (address);
    function challengeWindowSeconds() external view returns (uint64);
}

interface IP42CanonicalPool {
    function owner() external view returns (address);
    function ledger() external view returns (address);
}

interface IP42CanonicalLedger {
    function owner() external view returns (address);
    function pool() external view returns (address);
    function treasury() external view returns (address);
}

/// @notice Canonical CREATE2 origin for P42 challenge managers. The resolver
/// quorum pins this factory's immutable runtime code hash and accepts only
/// instances recorded by this implementation.
contract P42ChallengeManagerFactory {
    struct Parameters {
        address owner;
        address resolver;
        address treasury;
        address submissionManager;
        uint64 challengeWindowSeconds;
        uint16 betaBps;
        uint256 minCounterBondWei;
        uint256 rerunCostWei;
        uint16 rerunCostMultiplierBps;
        uint256 resolverDecisionBondWei;
        uint64 resolverFraudWindowSeconds;
        address problemRegistry;
        uint256 problemId;
        bytes32 objectivePackageHash;
        bytes32 objectiveGuestElfSha256;
        bytes32 objectiveProgramVKey;
    }

    error P42_FACTORY_MANAGER_EXISTS();
    error P42_FACTORY_BAD_SUBMISSION_MANAGER();
    error P42_FACTORY_BAD_SUBMISSION_CONFIGURATION();

    bytes32 public constant CANONICAL_SUBMISSION_MANAGER_FACTORY_CODEHASH =
        0x8eff5a60b0927a18821917992d29b4197435cec411c0116292a3a7bd5ea0aa26;

    mapping(address => bool) public isCanonicalManager;
    mapping(address => bytes32) public pairConfigurationHashOf;
    mapping(address => address) public objectiveRegistryOf;
    mapping(address => uint256) public objectiveProblemIdOf;
    mapping(address => bytes32) public objectivePackageHashOf;
    mapping(address => bytes32) public objectiveGuestElfSha256Of;
    mapping(address => bytes32) public objectiveProgramVKeyOf;

    event CanonicalManagerDeployed(address indexed manager, bytes32 indexed salt);
    event ObjectiveBindingRecorded(
        address indexed manager,
        address indexed registry,
        uint256 indexed problemId,
        bytes32 packageHash,
        bytes32 guestElfSha256,
        bytes32 programVKey
    );

    function effectiveSalt(bytes32 requestedSalt, address submissionManagerFactory, Parameters calldata parameters)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                "P42_CHALLENGE_MANAGER_CREATE2_V3",
                requestedSalt,
                submissionManagerFactory,
                parameters
            )
        );
    }

    function deployManager(bytes32 salt, address submissionManagerFactory, Parameters calldata parameters)
        external
        returns (address manager)
    {
        if (
            submissionManagerFactory.codehash != CANONICAL_SUBMISSION_MANAGER_FACTORY_CODEHASH
                || !IP42CanonicalSubmissionManagerFactory(submissionManagerFactory)
                    .isCanonicalSubmissionManager(parameters.submissionManager)
        ) revert P42_FACTORY_BAD_SUBMISSION_MANAGER();
        bytes32 submissionConfigurationHash = IP42CanonicalSubmissionManagerFactory(submissionManagerFactory)
            .configurationHashOf(parameters.submissionManager);
        _requireCanonicalTopology(parameters, submissionConfigurationHash);
        if (
            parameters.problemRegistry == address(0) || parameters.problemId == 0
                || parameters.objectivePackageHash == bytes32(0)
                || parameters.objectiveGuestElfSha256 == bytes32(0)
                || parameters.objectiveProgramVKey == bytes32(0)
        ) revert P42_FACTORY_BAD_SUBMISSION_CONFIGURATION();
        bytes32 boundSalt = effectiveSalt(salt, submissionManagerFactory, parameters);
        manager = address(new P42ChallengeManager{salt: boundSalt}(
            parameters.owner,
            parameters.resolver,
            parameters.treasury,
            parameters.submissionManager,
            parameters.challengeWindowSeconds,
            parameters.betaBps,
            parameters.minCounterBondWei,
            parameters.rerunCostWei,
            parameters.rerunCostMultiplierBps,
            parameters.resolverDecisionBondWei,
            parameters.resolverFraudWindowSeconds
        ));
        if (isCanonicalManager[manager]) revert P42_FACTORY_MANAGER_EXISTS();
        isCanonicalManager[manager] = true;
        pairConfigurationHashOf[manager] = keccak256(
            abi.encode(submissionConfigurationHash, parameters)
        );
        objectiveRegistryOf[manager] = parameters.problemRegistry;
        objectiveProblemIdOf[manager] = parameters.problemId;
        objectivePackageHashOf[manager] = parameters.objectivePackageHash;
        objectiveGuestElfSha256Of[manager] = parameters.objectiveGuestElfSha256;
        objectiveProgramVKeyOf[manager] = parameters.objectiveProgramVKey;
        emit CanonicalManagerDeployed(manager, boundSalt);
        emit ObjectiveBindingRecorded(
            manager,
            parameters.problemRegistry,
            parameters.problemId,
            parameters.objectivePackageHash,
            parameters.objectiveGuestElfSha256,
            parameters.objectiveProgramVKey
        );
    }

    function objectiveBindingOf(address manager)
        external
        view
        returns (
            address registry,
            uint256 problemId,
            bytes32 packageHash,
            bytes32 guestElfSha256,
            bytes32 programVKey
        )
    {
        if (!isCanonicalManager[manager]) revert P42_FACTORY_BAD_SUBMISSION_MANAGER();
        return (
            objectiveRegistryOf[manager],
            objectiveProblemIdOf[manager],
            objectivePackageHashOf[manager],
            objectiveGuestElfSha256Of[manager],
            objectiveProgramVKeyOf[manager]
        );
    }

    function _requireCanonicalTopology(Parameters calldata parameters, bytes32 submissionConfigurationHash)
        private
        view
    {
        IP42CanonicalSubmissionManager submissions =
            IP42CanonicalSubmissionManager(parameters.submissionManager);
        address pool = submissions.pool();
        address ledger = submissions.ledger();
        if (
            submissionConfigurationHash == bytes32(0)
                || submissions.owner() != parameters.owner
                || submissions.fundingAuthorizer() != parameters.treasury
                || submissions.treasury() != parameters.treasury
                || submissions.challengeWindowSeconds() != parameters.challengeWindowSeconds
                || pool.code.length == 0 || ledger.code.length == 0
                || IP42CanonicalPool(pool).owner() != parameters.owner
                || IP42CanonicalPool(pool).ledger() != ledger
                || IP42CanonicalLedger(ledger).owner() != parameters.owner
                || IP42CanonicalLedger(ledger).pool() != pool
                || IP42CanonicalLedger(ledger).treasury() != parameters.treasury
        ) revert P42_FACTORY_BAD_SUBMISSION_CONFIGURATION();
    }
}
