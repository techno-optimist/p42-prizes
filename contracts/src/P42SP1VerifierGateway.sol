// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISP1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

abstract contract P42SP1VerifierGatewayBase {
    error BadSP1VerifierRuntime();
    error ObjectiveProofCapabilityInactive();

    function _sp1Verifier() internal view virtual returns (address);
    function _sp1VerifierCodehash() internal view virtual returns (bytes32);
    function _objectiveProofsActive() internal view virtual returns (bool);

    function sp1Verifier() external view returns (address) {
        return _sp1Verifier();
    }

    function sp1VerifierCodehash() external view returns (bytes32) {
        return _sp1VerifierCodehash();
    }

    function objectiveProofsActive() public view returns (bool) {
        return _objectiveProofsActive();
    }

    function verify(bytes32 programVKey, bytes32 journalDigest, bytes calldata proof)
        external
        view
        returns (bool)
    {
        if (!_objectiveProofsActive()) revert ObjectiveProofCapabilityInactive();
        address verifier = _sp1Verifier();
        if (verifier.codehash != _sp1VerifierCodehash()) revert BadSP1VerifierRuntime();
        ISP1Verifier(verifier).verifyProof(programVKey, abi.encode(journalDigest), proof);
        return true;
    }
}

/// @notice Immutable P42 adapter for Succinct's direct SP1 V6.1.0 Groth16 verifier.
/// The exact verifier runtime is identical at this address on Base and Base Sepolia.
contract P42SP1VerifierGateway is P42SP1VerifierGatewayBase {
    address public constant SP1_VERIFIER = 0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2;
    bytes32 public constant SP1_VERIFIER_CODEHASH =
        0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd;

    function _sp1Verifier() internal pure override returns (address) {
        return SP1_VERIFIER;
    }

    function _sp1VerifierCodehash() internal pure override returns (bytes32) {
        return SP1_VERIFIER_CODEHASH;
    }

    /// @dev A later version may return true only after the exact guest ELF,
    /// program verification key, reproducible SP1 toolchain, and genuine proof
    /// vector are admitted as one release. This version is deliberately inert.
    function _objectiveProofsActive() internal pure override returns (bool) {
        return false;
    }
}
