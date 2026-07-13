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
    }

    error P42_FACTORY_MANAGER_EXISTS();
    error P42_FACTORY_BAD_SUBMISSION_MANAGER();
    error P42_FACTORY_BAD_SUBMISSION_CONFIGURATION();

    bytes32 public constant CANONICAL_SUBMISSION_MANAGER_FACTORY_CODEHASH =
        0xf704e1641a6f1712793a30639f3b4c3412b51909d38d2a56ec3b01d3e34d4d2a;

    mapping(address => bool) public isCanonicalManager;
    mapping(address => bytes32) public pairConfigurationHashOf;

    event CanonicalManagerDeployed(address indexed manager, bytes32 indexed salt);

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
        manager = address(new P42ChallengeManager{salt: salt}(
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
        emit CanonicalManagerDeployed(manager, salt);
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
