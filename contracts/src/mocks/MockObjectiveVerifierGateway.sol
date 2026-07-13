// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Test-only verifier gateway. A proof is accepted only when it is the
/// ABI encoding of the requested program and journal digest.
contract MockObjectiveVerifierGateway {
    function verify(bytes32 programId, bytes32 journalDigest, bytes calldata proof) external pure returns (bool) {
        return keccak256(proof) == keccak256(abi.encode(programId, journalDigest));
    }
}
