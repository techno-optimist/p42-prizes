// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42AtomicSubmissions {
    function commit(bytes32 commitment, bytes32 commitDaHash) external payable returns (uint256);
    function reveal(
        uint256 submissionId,
        string calldata solutionCid,
        int256 claimedScoreAtoms,
        uint256 improvementAtoms,
        string calldata salt,
        bytes calldata solution
    ) external;
    function finalize(uint256 submissionId, bytes32 permanenceHash) external;
}

interface IP42AtomicLedger {
    function close() external;
}

interface IP42AtomicPool {
    function claim() external;
}

contract AtomicSettlementAttacker {
    receive() external payable {}

    function commit(address submissions, bytes32 commitment, bytes32 commitDaHash) external payable {
        IP42AtomicSubmissions(submissions).commit{value: msg.value}(commitment, commitDaHash);
    }

    function reveal(
        address submissions,
        uint256 submissionId,
        string calldata solutionCid,
        int256 claimedScoreAtoms,
        uint256 improvementAtoms,
        string calldata salt
    ) external {
        IP42AtomicSubmissions(submissions).reveal(
            submissionId, solutionCid, claimedScoreAtoms, improvementAtoms, salt, ""
        );
    }

    function finalizeCloseClaim(address submissions, address ledger, address pool, uint256 submissionId) external {
        IP42AtomicSubmissions(submissions).finalize(submissionId, bytes32(0));
        IP42AtomicLedger(ledger).close();
        IP42AtomicPool(pool).claim();
    }

    function finalize(address submissions, uint256 submissionId) external {
        IP42AtomicSubmissions(submissions).finalize(submissionId, bytes32(0));
    }
}
