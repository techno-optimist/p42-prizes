// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42MockCreditLedger {
    function recordCredit(address solver, uint256 atoms) external;
}

/// @notice Test double for P42BountyPool's ISubmissionManagerArmed funding
/// gate: a stand-in submission manager whose `fundingArmed` flag is directly
/// settable, for fixtures that exercise the pool/ledger without deploying the
/// full submission stack.
contract MockFundingArmed {
    bool public fundingArmed;
    bool public objectiveProofCapabilityActive = true;
    uint64 public fundingAuthorizationExpiresAt = type(uint64).max;

    constructor(bool armed) {
        fundingArmed = armed;
    }

    function setFundingArmed(bool armed) external {
        fundingArmed = armed;
    }

    function setObjectiveProofCapabilityActive(bool active) external {
        objectiveProofCapabilityActive = active;
    }

    function setFundingAuthorizationExpiresAt(uint64 expiresAt) external {
        fundingAuthorizationExpiresAt = expiresAt;
    }

    function openSubmissionCount() external pure returns (uint256) {
        return 0;
    }

    function pausedAll() external pure returns (bool) {
        return false;
    }

    function creditRecoveryEndsAt() external pure returns (uint64) {
        return 0;
    }

    function recordCredit(address ledger, address solver, uint256 atoms) external {
        IP42MockCreditLedger(ledger).recordCredit(solver, atoms);
    }
}
