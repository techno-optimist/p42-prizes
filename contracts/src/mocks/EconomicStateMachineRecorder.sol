// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IEconomicStateMachineLedger {
    function recordCredit(address solver, uint256 atoms) external;
    function voidCredit(address solver, uint256 atoms) external;
}

/// @notice Test-only credit recorder with explicit close-guard controls.
contract EconomicStateMachineRecorder {
    bool public fundingArmed = true;
    bool public pausedAll;
    uint64 public creditRecoveryEndsAt;
    uint256 public openSubmissionCount;

    function setFundingArmed(bool armed) external {
        fundingArmed = armed;
    }

    function setCloseGuard(uint256 openCount, bool allPaused, uint64 recoveryEndsAt) external {
        openSubmissionCount = openCount;
        pausedAll = allPaused;
        creditRecoveryEndsAt = recoveryEndsAt;
    }

    function recordCredit(address ledger, address solver, uint256 atoms) external {
        IEconomicStateMachineLedger(ledger).recordCredit(solver, atoms);
    }

    function voidCredit(address ledger, address solver, uint256 atoms) external {
        IEconomicStateMachineLedger(ledger).voidCredit(solver, atoms);
    }
}
