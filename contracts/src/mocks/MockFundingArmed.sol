// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Test double for P42BountyPool's ISubmissionManagerArmed funding
/// gate: a stand-in submission manager whose `fundingArmed` flag is directly
/// settable, for fixtures that exercise the pool/ledger without deploying the
/// full submission stack.
contract MockFundingArmed {
    bool public fundingArmed;

    constructor(bool armed) {
        fundingArmed = armed;
    }

    function setFundingArmed(bool armed) external {
        fundingArmed = armed;
    }
}
