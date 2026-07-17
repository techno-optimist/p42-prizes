// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {P42SubmissionManager} from "./P42SubmissionManager.sol";

/// @notice Canonical CREATE2 origin for P42 submission managers.
contract P42SubmissionManagerFactory {
    error P42_FACTORY_BAD_MANAGER_CREATION_CODE();
    error P42_FACTORY_DEPLOYMENT_FAILED();

    struct Parameters {
        P42SubmissionManager.DeploymentConfig deployment;
        P42SubmissionManager.FundingAuthorizationConfig fundingAuthorization;
    }

    mapping(address => bool) public isCanonicalSubmissionManager;
    mapping(address => bytes32) public configurationHashOf;
    bytes32 public constant MANAGER_CREATION_CODE_HASH =
        0x27d00201922627ab5878c009a1ededa0a59c29581a2b7dca47576db3b7b532d2;

    event CanonicalSubmissionManagerDeployed(address indexed submissionManager, bytes32 indexed salt);

    /// @notice The caller supplies creation code so this factory does not embed
    /// the large manager init code in runtime bytecode. The immutable hash pins
    /// the exact compiler artifact while keeping the factory below EIP-170.
    function deploySubmissionManager(
        bytes32 salt,
        Parameters calldata parameters,
        bytes calldata managerCreationCode
    )
        external
        returns (address submissionManager)
    {
        if (keccak256(managerCreationCode) != MANAGER_CREATION_CODE_HASH) {
            revert P42_FACTORY_BAD_MANAGER_CREATION_CODE();
        }
        bytes memory constructorArguments = abi.encode(parameters.deployment, parameters.fundingAuthorization);
        bytes memory initCode = bytes.concat(managerCreationCode, constructorArguments);
        assembly ("memory-safe") {
            submissionManager := create2(0, add(initCode, 32), mload(initCode), salt)
        }
        if (submissionManager == address(0)) revert P42_FACTORY_DEPLOYMENT_FAILED();
        isCanonicalSubmissionManager[submissionManager] = true;
        configurationHashOf[submissionManager] = keccak256(abi.encode(parameters));
        emit CanonicalSubmissionManagerDeployed(submissionManager, salt);
    }
}
