// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42PayoutLedger {
    function consumeClaim(address solver) external returns (uint256);
    function closed() external view returns (bool);
}

/// @notice Per-problem ETH escrow. It holds funds under fixed rules and lets the
/// payout ledger compute claim amounts. `claim()` is deliberately not pausable.
contract P42BountyPool {
    error P42_NOT_OWNER();
    error P42_NOT_LEDGER();
    error P42_LEDGER_ALREADY_SET();
    error P42_LEDGER_NOT_SET();
    error P42_NOTHING_TO_CLAIM();
    error P42_POOL_CLOSED();
    error P42_TRANSFER_FAILED();

    address public immutable owner;
    address public ledger;
    uint256 public totalFunded;
    uint256 public totalClaimed;
    uint256 public totalFeePaid;
    uint256 public totalResidualPaid;

    bool private _claiming;

    event LedgerSet(address indexed ledger);
    event Funded(address indexed from, uint256 amount, uint256 newBalance);
    event Claimed(address indexed solver, uint256 amount);
    event FeePaid(address indexed to, uint256 amount);
    event ResidualPaid(address indexed to, uint256 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert P42_NOT_OWNER();
        _;
    }

    modifier nonReentrant() {
        require(!_claiming, "P42_REENTRANT_CLAIM");
        _claiming = true;
        _;
        _claiming = false;
    }

    constructor(address owner_) payable {
        require(owner_ != address(0), "P42_OWNER_ZERO");
        owner = owner_;
        if (msg.value > 0) {
            totalFunded = msg.value;
            emit Funded(msg.sender, msg.value, address(this).balance);
        }
    }

    receive() external payable {
        _fund();
    }

    function setLedger(address ledger_) external onlyOwner {
        if (ledger != address(0)) revert P42_LEDGER_ALREADY_SET();
        require(ledger_ != address(0), "P42_LEDGER_ZERO");
        ledger = ledger_;
        emit LedgerSet(ledger_);
    }

    function fund() external payable {
        _fund();
    }

    function funded() external view returns (uint256) {
        return address(this).balance;
    }

    function claim() external nonReentrant {
        address ledger_ = ledger;
        if (ledger_ == address(0)) revert P42_LEDGER_NOT_SET();
        uint256 amount = IP42PayoutLedger(ledger_).consumeClaim(msg.sender);
        if (amount == 0) revert P42_NOTHING_TO_CLAIM();
        totalClaimed += amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit Claimed(msg.sender, amount);
    }

    /// @notice Pays the ledger-computed protocol fee out of escrow (L1). Callable
    /// only by the ledger, which enforces after-close and single-use semantics.
    /// CEI + nonReentrant: fee accounting is updated before the external transfer.
    function payFee(address to, uint256 amount) external nonReentrant {
        if (msg.sender != ledger) revert P42_NOT_LEDGER();
        require(to != address(0), "P42_FEE_SINK_ZERO");
        totalFeePaid += amount;
        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit FeePaid(to, amount);
    }

    /// @notice Pays the post-deadline residual sweep out of escrow (F15).
    /// Callable only by the ledger, which enforces closed + deadline-elapsed +
    /// single-use semantics. Deliberately a DEDICATED path — reusing payFee
    /// here would pollute the totalFeePaid counter with non-fee outflows.
    /// CEI + nonReentrant: accounting is updated before the external transfer.
    function payResidual(address to, uint256 amount) external nonReentrant {
        if (msg.sender != ledger) revert P42_NOT_LEDGER();
        require(to != address(0), "P42_RESIDUAL_SINK_ZERO");
        totalResidualPaid += amount;
        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit ResidualPaid(to, amount);
    }

    function _fund() private {
        require(msg.value > 0, "P42_ZERO_FUNDING");
        // Post-close deposits would be stranded (finalEntitlement is snapshotted
        // at close), so reject them once the ledger has closed the pool (L2).
        address ledger_ = ledger;
        if (ledger_ != address(0) && IP42PayoutLedger(ledger_).closed()) revert P42_POOL_CLOSED();
        totalFunded += msg.value;
        emit Funded(msg.sender, msg.value, address(this).balance);
    }
}
