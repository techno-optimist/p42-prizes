// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42PayoutPoolClaimer {
    function claim() external;
    function claimTo(address payable recipient) external;
}

/// @notice Solver that cannot receive ETH but can redirect a pool claim.
contract RejectingPayoutSolver {
    error P42_REJECT_ETH();

    receive() external payable {
        revert P42_REJECT_ETH();
    }

    function claim(address pool) external {
        IP42PayoutPoolClaimer(pool).claim();
    }

    function claimTo(address pool, address payable recipient) external {
        IP42PayoutPoolClaimer(pool).claimTo(recipient);
    }
}

/// @notice Sends ETH without calling the recipient's receive or fallback path.
contract ForceEther {
    constructor() payable {}

    function force(address payable recipient) external {
        selfdestruct(recipient);
    }
}
