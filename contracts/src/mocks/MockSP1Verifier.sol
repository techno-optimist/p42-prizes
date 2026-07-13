// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {P42SP1VerifierGatewayBase} from "../P42SP1VerifierGateway.sol";

contract MockSP1Verifier {
    error InvalidSP1Proof();

    bytes32 public immutable expectedProgramVKey;
    bytes32 public immutable expectedJournalDigest;
    bytes32 public immutable expectedProofHash;

    constructor(bytes32 programVKey_, bytes32 journalDigest_, bytes32 proofHash_) {
        expectedProgramVKey = programVKey_;
        expectedJournalDigest = journalDigest_;
        expectedProofHash = proofHash_;
    }

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes)
        external
        view
    {
        if (
            programVKey != expectedProgramVKey
                || keccak256(publicValues) != keccak256(abi.encode(expectedJournalDigest))
                || keccak256(proofBytes) != expectedProofHash
        ) revert InvalidSP1Proof();
    }
}

contract MockP42SP1VerifierGateway is P42SP1VerifierGatewayBase {
    address private immutable verifier;
    bytes32 private immutable verifierCodehash;

    constructor(address verifier_, bytes32 verifierCodehash_) {
        verifier = verifier_;
        verifierCodehash = verifierCodehash_;
    }

    function _sp1Verifier() internal view override returns (address) {
        return verifier;
    }

    function _sp1VerifierCodehash() internal view override returns (bytes32) {
        return verifierCodehash;
    }

    function _objectiveProofsActive() internal pure override returns (bool) {
        return true;
    }
}
