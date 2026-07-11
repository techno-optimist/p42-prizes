// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42RolloverRegistry {
    function problemPool(uint256 problemId) external view returns (address);
}

interface IP42RegisteredPool {
    function owner() external view returns (address);
    function registry() external view returns (address);
    function problemId() external view returns (uint256);
    function ledger() external view returns (address);
    function submissionManager() external view returns (address);
    function fund() external payable;
    function sponsorRefundTo(address payable recipient) external;
}

interface IP42RegisteredLedger {
    function owner() external view returns (address);
    function pool() external view returns (address);
    function creditRecorder() external view returns (address);
}

interface IP42RegisteredSubmissionManager {
    function owner() external view returns (address);
    function pool() external view returns (address);
    function ledger() external view returns (address);
}

/// @notice Restricted future-prize vault. Only the immutable canonical
/// timelock may allocate explicit quotas to fully wired canonical pool stacks.
contract P42RolloverVault {
    error P42_REGISTRY_ZERO();
    error P42_ALLOCATOR_ZERO();
    error P42_NOT_ALLOCATOR();
    error P42_INVALID_REGISTERED_POOL();
    error P42_CODEHASH_MISMATCH(bytes32 expected, bytes32 actual);
    error P42_INVALID_ROLLOVER_AMOUNT();
    error P42_ALLOCATION_EXCEEDS_BALANCE(uint256 allocated, uint256 balance);
    error P42_ROLLOVER_FUNDING_FAILED();

    address public registry;
    address public allocator;
    uint256 public totalAllocated;
    mapping(address => uint256) public allocationOf;
    mapping(address => bytes32) public allocationCodehashOf;

    event RolloverReceived(address indexed from, uint256 amount);
    event PoolAllocationSet(address indexed pool, bytes32 indexed codehash, uint256 previousAmount, uint256 amount);
    event FuturePoolFunded(address indexed allocator, address indexed pool, uint256 amount, uint256 remainingAllocation);
    event ZeroCreditRefundReclaimed(address indexed caller, address indexed pool);

    modifier onlyAllocator() {
        if (msg.sender != allocator) revert P42_NOT_ALLOCATOR();
        _;
    }

    constructor(address registry_, address allocator_) {
        if (registry_ == address(0)) revert P42_REGISTRY_ZERO();
        if (allocator_ == address(0)) revert P42_ALLOCATOR_ZERO();
        registry = registry_;
        allocator = allocator_;
    }

    receive() external payable {
        emit RolloverReceived(msg.sender, msg.value);
    }

    function isP42RolloverDestination() external pure returns (bool) {
        return true;
    }

    function setPoolAllocation(address payable pool, bytes32 expectedCodehash, uint256 amount) external onlyAllocator {
        uint256 previous = allocationOf[pool];
        bytes32 allocationCodehash = allocationCodehashOf[pool];
        if (amount != 0) {
            _registeredPool(pool, expectedCodehash);
            allocationCodehash = expectedCodehash;
        }
        uint256 allocated = totalAllocated - previous + amount;
        if (allocated > address(this).balance) revert P42_ALLOCATION_EXCEEDS_BALANCE(allocated, address(this).balance);
        allocationOf[pool] = amount;
        if (amount == 0) {
            delete allocationCodehashOf[pool];
        } else {
            allocationCodehashOf[pool] = expectedCodehash;
        }
        totalAllocated = allocated;
        emit PoolAllocationSet(pool, allocationCodehash, previous, amount);
    }

    function fundRegisteredPool(address payable pool, uint256 amount) external onlyAllocator {
        if (amount == 0 || amount > allocationOf[pool] || amount > address(this).balance) {
            revert P42_INVALID_ROLLOVER_AMOUNT();
        }
        IP42RegisteredPool target = _registeredPool(pool, allocationCodehashOf[pool]);
        allocationOf[pool] -= amount;
        totalAllocated -= amount;
        if (allocationOf[pool] == 0) delete allocationCodehashOf[pool];
        try target.fund{value: amount}() {
            emit FuturePoolFunded(msg.sender, pool, amount, allocationOf[pool]);
        } catch {
            revert P42_ROLLOVER_FUNDING_FAILED();
        }
    }

    function reclaimZeroCreditSponsorRefund(address payable pool) external {
        IP42RegisteredPool target = _registeredPool(pool, pool.codehash);
        try target.sponsorRefundTo(payable(address(this))) {
            emit ZeroCreditRefundReclaimed(msg.sender, pool);
        } catch {
            revert P42_ROLLOVER_FUNDING_FAILED();
        }
    }

    function _registeredPool(address payable pool, bytes32 expectedCodehash)
        private
        view
        returns (IP42RegisteredPool target)
    {
        bytes32 actualCodehash = pool.codehash;
        if (pool.code.length == 0 || actualCodehash != expectedCodehash) {
            revert P42_CODEHASH_MISMATCH(expectedCodehash, actualCodehash);
        }
        target = IP42RegisteredPool(pool);
        uint256 targetProblemId = target.problemId();
        address targetLedger = target.ledger();
        address targetManager = target.submissionManager();
        if (
            targetProblemId == 0 || target.owner() != allocator || target.registry() != registry
                || IP42RolloverRegistry(registry).problemPool(targetProblemId) != pool || targetLedger.code.length == 0
                || targetManager.code.length == 0
        ) revert P42_INVALID_REGISTERED_POOL();
        IP42RegisteredLedger ledger_ = IP42RegisteredLedger(targetLedger);
        IP42RegisteredSubmissionManager manager_ = IP42RegisteredSubmissionManager(targetManager);
        if (
            ledger_.owner() != allocator || ledger_.pool() != pool || ledger_.creditRecorder() != targetManager
                || manager_.owner() != allocator || manager_.pool() != pool || manager_.ledger() != targetLedger
        ) revert P42_INVALID_REGISTERED_POOL();
    }
}
