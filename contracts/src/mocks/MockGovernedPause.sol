// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockGovernedPause {
    bool public pausedNewActions;
    bool public pausedAll;
    uint256 public value;

    function setPausedNewActions(bool paused) external {
        pausedNewActions = paused;
    }

    function setPausedAll(bool paused) external {
        pausedAll = paused;
    }

    function setValue(uint256 value_) external {
        value = value_;
    }
}
