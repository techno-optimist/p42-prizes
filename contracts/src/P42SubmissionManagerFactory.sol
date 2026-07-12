// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {P42SubmissionManager} from "./P42SubmissionManager.sol";

/// @notice Canonical CREATE2 origin for P42 submission managers.
contract P42SubmissionManagerFactory {
    struct Parameters {
        address pool;
        address ledger;
        address owner;
        address treasury;
        uint16 alphaBps;
        uint256 minPostingBondWei;
        uint64 challengeWindowSeconds;
        bool onchainDa;
        uint256 maxSolutionBytes;
        int256 seedScoreAtoms;
        uint256 minImprovementAtoms;
    }

    mapping(address => bool) public isCanonicalSubmissionManager;
    mapping(address => bytes32) public configurationHashOf;

    event CanonicalSubmissionManagerDeployed(address indexed submissionManager, bytes32 indexed salt);

    function deploySubmissionManager(bytes32 salt, Parameters calldata parameters)
        external
        returns (address submissionManager)
    {
        submissionManager = address(new P42SubmissionManager{salt: salt}(
            parameters.pool,
            parameters.ledger,
            parameters.owner,
            parameters.treasury,
            parameters.alphaBps,
            parameters.minPostingBondWei,
            parameters.challengeWindowSeconds,
            parameters.onchainDa,
            parameters.maxSolutionBytes,
            parameters.seedScoreAtoms,
            parameters.minImprovementAtoms
        ));
        isCanonicalSubmissionManager[submissionManager] = true;
        configurationHashOf[submissionManager] = keccak256(abi.encode(parameters));
        emit CanonicalSubmissionManagerDeployed(submissionManager, salt);
    }
}
