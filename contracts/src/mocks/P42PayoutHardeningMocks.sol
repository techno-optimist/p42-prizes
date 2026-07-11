// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42PayoutPoolClaimer {
    function claim() external;
    function claimTo(address payable recipient) external;
    function claimFeesTo(address payable recipient) external;
}

interface IP42PayoutPoolSponsor {
    function fund() external payable;
    function sponsorRefund() external;
    function sponsorRefundTo(address payable recipient) external;
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

/// @notice Rejects direct ETH while retaining the treasury's explicit right to
/// redirect accrued fees to a payable recipient.
contract RejectingTreasury {
    error P42_REJECT_ETH();

    receive() external payable {
        revert P42_REJECT_ETH();
    }

    function claimFeesTo(address pool, address payable recipient) external {
        IP42PayoutPoolClaimer(pool).claimFeesTo(recipient);
    }
}

/// @notice Deliberately mimics the retired vault marker while retaining an
/// arbitrary transfer path. Ledger runtime-code pinning must reject it.
contract MarkerSpoofRolloverDestination {
    function isP42RolloverDestination() external pure returns (bool) {
        return true;
    }

    function withdraw(address payable recipient) external {
        (bool ok,) = recipient.call{value: address(this).balance}("");
        require(ok, "P42_WITHDRAW_FAILED");
    }

    receive() external payable {}
}

contract RejectingSponsor {
    error P42_REJECT_ETH();

    receive() external payable {
        revert P42_REJECT_ETH();
    }

    function fundPool(address pool) external payable {
        IP42PayoutPoolSponsor(pool).fund{value: msg.value}();
    }

    function refund(address pool) external {
        IP42PayoutPoolSponsor(pool).sponsorRefund();
    }

    function refundTo(address pool, address payable recipient) external {
        IP42PayoutPoolSponsor(pool).sponsorRefundTo(recipient);
    }
}

contract ReentrantSponsor {
    address private _pool;
    bool public reentryAttempted;

    receive() external payable {
        reentryAttempted = true;
        try IP42PayoutPoolSponsor(_pool).sponsorRefund() {} catch {}
    }

    function fundPool(address pool) external payable {
        _pool = pool;
        IP42PayoutPoolSponsor(pool).fund{value: msg.value}();
    }

    function refund(address pool) external {
        _pool = pool;
        IP42PayoutPoolSponsor(pool).sponsorRefund();
    }
}
