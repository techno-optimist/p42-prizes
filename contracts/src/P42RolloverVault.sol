// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42RolloverRegistry {
    function problemPool(uint256 problemId) external view returns (address);
}

interface IP42RegisteredPool {
    function registry() external view returns (address);
    function problemId() external view returns (uint256);
    function fund() external payable;
    function sponsorRefundTo(address payable recipient) external;
}

/// @notice Ownerless sink for expired positive-credit awards and floor dust.
/// It has no withdrawal function: ETH can leave only by funding a pool bound to
/// the immutable canonical registry. Calls are permissionless so no operator
/// can redirect or indefinitely gate the future-prize use of rollover funds.
contract P42RolloverVault {
    error P42_REGISTRY_ZERO();
    error P42_INVALID_REGISTERED_POOL();
    error P42_INVALID_ROLLOVER_AMOUNT();
    error P42_ROLLOVER_FUNDING_FAILED();

    /// @dev Never mutated after construction. Storage, rather than an immutable,
    /// keeps every vault instance on the same runtime bytecode pinned by ledger.
    address public registry;

    event RolloverReceived(address indexed from, uint256 amount);
    event FuturePoolFunded(address indexed caller, address indexed pool, uint256 amount);
    event ZeroCreditRefundReclaimed(address indexed caller, address indexed pool);

    constructor(address registry_) {
        if (registry_ == address(0)) revert P42_REGISTRY_ZERO();
        registry = registry_;
    }

    receive() external payable {
        emit RolloverReceived(msg.sender, msg.value);
    }

    function isP42RolloverDestination() external pure returns (bool) {
        return true;
    }

    function fundRegisteredPool(address payable pool, uint256 amount) external {
        if (amount == 0 || amount > address(this).balance) revert P42_INVALID_ROLLOVER_AMOUNT();
        IP42RegisteredPool target = _registeredPool(pool);
        try target.fund{value: amount}() {
            emit FuturePoolFunded(msg.sender, pool, amount);
        } catch {
            revert P42_ROLLOVER_FUNDING_FAILED();
        }
    }

    /// @notice Returns this vault's own sponsorship when a future pool closes
    /// with no credit. The pool sends it straight back here; this is not an
    /// arbitrary withdrawal and the value remains rollover-only.
    function reclaimZeroCreditSponsorRefund(address payable pool) external {
        IP42RegisteredPool target = _registeredPool(pool);
        try target.sponsorRefundTo(payable(address(this))) {
            emit ZeroCreditRefundReclaimed(msg.sender, pool);
        } catch {
            revert P42_ROLLOVER_FUNDING_FAILED();
        }
    }

    function _registeredPool(address payable pool) private view returns (IP42RegisteredPool target) {
        if (pool.code.length == 0) revert P42_INVALID_REGISTERED_POOL();
        target = IP42RegisteredPool(pool);
        uint256 targetProblemId = target.problemId();
        if (targetProblemId == 0 || target.registry() != registry || IP42RolloverRegistry(registry).problemPool(targetProblemId) != pool) {
            revert P42_INVALID_REGISTERED_POOL();
        }
    }
}
