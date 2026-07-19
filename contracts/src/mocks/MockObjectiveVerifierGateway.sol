// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Test-only verifier gateway. A proof is accepted only when it is the
/// ABI encoding of the requested program and journal digest.
contract MockObjectiveVerifierGateway {
    bool public objectiveProofsActive = true;

    function setObjectiveProofsActive(bool active) external {
        objectiveProofsActive = active;
    }

    function verify(bytes32 programId, bytes32 journalDigest, bytes calldata proof) external pure returns (bool) {
        return keccak256(proof) == keccak256(abi.encode(programId, journalDigest));
    }
}

contract RevertingObjectiveProofCapability {
    function objectiveProofsActive() external pure returns (bool) {
        revert("CAPABILITY_UNAVAILABLE");
    }
}

contract MalformedObjectiveProofCapability {
    fallback() external {
        assembly ("memory-safe") {
            mstore(0, 1)
            return(31, 1)
        }
    }
}
