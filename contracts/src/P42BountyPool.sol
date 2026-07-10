// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42PayoutLedger {
    function consumeClaim(address solver) external returns (uint256);
    function creditRecorder() external view returns (address);
    function closed() external view returns (bool);
    function earliestCloseTimestamp() external view returns (uint64);
    function effectiveEarliestCloseTimestamp() external view returns (uint64);
    function fundingDeadline() external view returns (uint64);
    function closeByTimestamp() external view returns (uint64);
}

/// @dev Minimal view of the submission manager's OPEN-WITNESS-PHASE gate:
/// deposits are refused until the funder arms funding there (armFunding is the
/// SINGLE arm authority for both ledger credit and pool deposits).
interface ISubmissionManagerArmed {
    function fundingArmed() external view returns (bool);
}

interface IP42ProblemFreezeRegistry {
    function explicitlyFrozen(uint256 problemId) external view returns (bool);
    function problemPool(uint256 problemId) external view returns (address);
}

/// @notice Per-problem ETH escrow. It holds funds under fixed rules and lets the
/// payout ledger compute claim amounts. `claim()` is deliberately not pausable.
contract P42BountyPool {
    error P42_NOT_OWNER();
    error P42_NOT_LEDGER();
    error P42_LEDGER_ALREADY_SET();
    error P42_LEDGER_NOT_SET();
    error P42_SUBMISSION_MANAGER_ALREADY_SET();
    error P42_REGISTRY_ALREADY_SET();
    error P42_REGISTRY_NOT_SET();
    error P42_BAD_PROBLEM_BINDING();
    error P42_FUNDING_NOT_ARMED();
    error P42_CREDIT_RECORDER_MISMATCH(address creditRecorder, address submissionManager);
    error P42_NOT_ACCEPTING_FUNDS();
    error P42_PROBLEM_NOT_FROZEN();
    error P42_FUNDING_WINDOW_CLOSED(uint64 fundingDeadline, uint64 nowAt);
    error P42_FUNDING_CAP_EXCEEDED(uint256 cap, uint256 attemptedTotal);
    error P42_NOTHING_TO_CLAIM();
    error P42_RECIPIENT_ZERO();
    error P42_POOL_CLOSED();
    error P42_ACCOUNTING_UNDERFLOW(uint256 available, uint256 requested);
    error P42_TRANSFER_FAILED();

    address public immutable owner;
    uint256 public immutable fundingCap;
    address public ledger;
    /// @notice Submission manager wired for the OPEN-WITNESS-PHASE funding
    /// gate: fund()/receive() revert P42_FUNDING_NOT_ARMED until this is set
    /// AND its fundingArmed() is true. Safety rail — a funder cannot strand
    /// ETH in a pool whose problem is still in the unpaid open phase.
    address public submissionManager;
    address public registry;
    uint256 public problemId;
    bool public acceptingFunds;
    bool public everFunded;
    uint64 public firstFundedAt;
    uint256 public accountedBalance;
    uint256 public totalFunded;
    uint256 public totalClaimed;
    uint256 public totalFeePaid;
    uint256 public totalResidualPaid;

    bool private _claiming;

    event LedgerSet(address indexed ledger);
    event SubmissionManagerSet(address indexed submissionManager);
    event RegistrySet(address indexed registry, uint256 indexed problemId);
    event AcceptingFundsSet(bool acceptingFunds);
    event Funded(
        address indexed from,
        uint256 amount,
        uint256 newBalance,
        uint256 fundingCap,
        uint64 earliestCloseTimestamp,
        uint64 closeByTimestamp
    );
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

    /// @dev Deliberately NOT payable: the submission manager cannot be wired
    /// yet at construction (it needs this pool's address), so any
    /// construction-time deposit would be un-armed open-phase funding — the
    /// exact thing the P42_FUNDING_NOT_ARMED rail exists to prevent.
    constructor(address owner_, uint256 fundingCap_) {
        require(owner_ != address(0), "P42_OWNER_ZERO");
        require(fundingCap_ > 0, "P42_FUNDING_CAP_ZERO");
        owner = owner_;
        fundingCap = fundingCap_;
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

    /// @notice One-time wiring of the submission manager whose `fundingArmed`
    /// flag gates deposits (mirrors setLedger). Until it is set and armed,
    /// fund()/receive() revert: the problem is in its unpaid OPEN witness
    /// phase and ETH must not be strandable in escrow.
    function setSubmissionManager(address submissionManager_) external onlyOwner {
        if (submissionManager != address(0)) revert P42_SUBMISSION_MANAGER_ALREADY_SET();
        require(submissionManager_ != address(0), "P42_SUBMISSION_MANAGER_ZERO");
        submissionManager = submissionManager_;
        emit SubmissionManagerSet(submissionManager_);
    }

    /// @notice One-time binding to the canonical registry entry whose explicit
    /// freeze gates deposits. The pool address is checked in the registry so a
    /// different problem cannot be used as a freeze oracle.
    function setRegistry(address registry_, uint256 problemId_) external onlyOwner {
        if (registry != address(0)) revert P42_REGISTRY_ALREADY_SET();
        require(registry_ != address(0), "P42_REGISTRY_ZERO");
        if (problemId_ == 0 || IP42ProblemFreezeRegistry(registry_).problemPool(problemId_) != address(this)) {
            revert P42_BAD_PROBLEM_BINDING();
        }
        registry = registry_;
        problemId = problemId_;
        emit RegistrySet(registry_, problemId_);
    }

    /// @notice Governance funding switch, independent from the one-way
    /// OPEN-to-PAID phase transition. Re-enabling still requires the submission
    /// manager to be armed and the registered problem to be explicitly frozen.
    function setAcceptingFunds(bool accepting) external onlyOwner {
        if (accepting) {
            if (ledger == address(0)) revert P42_LEDGER_NOT_SET();
            uint64 deadline = IP42PayoutLedger(ledger).fundingDeadline();
            if (block.timestamp > deadline) {
                revert P42_FUNDING_WINDOW_CLOSED(deadline, uint64(block.timestamp));
            }
            address registry_ = registry;
            if (registry_ == address(0)) revert P42_REGISTRY_NOT_SET();
            _requireFrozenRegistryBinding(registry_);
            address manager = submissionManager;
            address recorder = IP42PayoutLedger(ledger).creditRecorder();
            if (recorder != manager) {
                revert P42_CREDIT_RECORDER_MISMATCH(recorder, manager);
            }
            if (manager == address(0) || !ISubmissionManagerArmed(manager).fundingArmed()) {
                revert P42_FUNDING_NOT_ARMED();
            }
        }
        acceptingFunds = accepting;
        emit AcceptingFundsSet(accepting);
    }

    function fund() external payable {
        _fund();
    }

    function funded() external view returns (uint256) {
        return accountedBalance;
    }

    function claim() external nonReentrant {
        _claimTo(msg.sender, payable(msg.sender));
    }

    /// @notice Lets a solver redirect its own entitlement to a payable recipient.
    /// The ledger debit remains keyed to msg.sender, never the recipient.
    function claimTo(address payable recipient) external nonReentrant {
        if (recipient == address(0)) revert P42_RECIPIENT_ZERO();
        _claimTo(msg.sender, recipient);
    }

    function _claimTo(address solver, address payable recipient) private {
        address ledger_ = ledger;
        if (ledger_ == address(0)) revert P42_LEDGER_NOT_SET();
        uint256 amount = IP42PayoutLedger(ledger_).consumeClaim(solver);
        if (amount == 0) revert P42_NOTHING_TO_CLAIM();
        _debitAccounted(amount);
        totalClaimed += amount;
        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit Claimed(solver, amount);
    }

    /// @notice Pays the ledger-computed protocol fee out of escrow (L1). Callable
    /// only by the ledger, which enforces after-close and single-use semantics.
    /// CEI + nonReentrant: fee accounting is updated before the external transfer.
    function payFee(address to, uint256 amount) external nonReentrant {
        if (msg.sender != ledger) revert P42_NOT_LEDGER();
        require(to != address(0), "P42_FEE_SINK_ZERO");
        _debitAccounted(amount);
        totalFeePaid += amount;
        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit FeePaid(to, amount);
    }

    /// @notice Pays the post-deadline residual sweep out of escrow (F15).
    /// Callable only by the ledger, which enforces closed + deadline-elapsed +
    /// residual-sweep semantics. Deliberately a DEDICATED path — reusing payFee
    /// here would pollute the totalFeePaid counter with non-fee outflows.
    /// CEI + nonReentrant: accounting is updated before the external transfer.
    function payResidual(address to, uint256 amount) external nonReentrant {
        if (msg.sender != ledger) revert P42_NOT_LEDGER();
        require(to != address(0), "P42_RESIDUAL_SINK_ZERO");
        // The claim deadline is the one point where unaccounted forced ETH is
        // deliberately recoverable. It never affected funding/freeze/payout
        // math, but the final treasury sweep may clear the raw balance.
        uint256 legitimate = amount < accountedBalance ? amount : accountedBalance;
        accountedBalance -= legitimate;
        totalResidualPaid += amount;
        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit ResidualPaid(to, amount);
    }

    function _fund() private {
        require(msg.value > 0, "P42_ZERO_FUNDING");
        // OPEN-WITNESS-PHASE rail: deposits are refused until the submission
        // manager is wired AND its funder has called armFunding(). One call
        // (armFunding) is the single arm authority opening both ledger credit
        // and pool deposits — a pool funded before arming is impossible, so a
        // funder can never strand ETH in an unpaid open phase.
        address manager = submissionManager;
        if (manager == address(0) || !ISubmissionManagerArmed(manager).fundingArmed()) {
            revert P42_FUNDING_NOT_ARMED();
        }
        if (!acceptingFunds) revert P42_NOT_ACCEPTING_FUNDS();
        address registry_ = registry;
        if (registry_ == address(0)) revert P42_REGISTRY_NOT_SET();
        _requireFrozenRegistryBinding(registry_);
        // Post-close deposits would be stranded (finalEntitlement is snapshotted
        // at close), so reject them once the ledger has closed the pool (L2).
        address ledger_ = ledger;
        if (ledger_ != address(0) && IP42PayoutLedger(ledger_).closed()) revert P42_POOL_CLOSED();
        uint64 deadline = IP42PayoutLedger(ledger_).fundingDeadline();
        if (block.timestamp > deadline) {
            revert P42_FUNDING_WINDOW_CLOSED(deadline, uint64(block.timestamp));
        }
        uint256 currentBalance = accountedBalance;
        if (msg.value > fundingCap - currentBalance) {
            revert P42_FUNDING_CAP_EXCEEDED(fundingCap, msg.value);
        }
        uint256 newBalance = currentBalance + msg.value;
        accountedBalance = newBalance;
        if (!everFunded) firstFundedAt = uint64(block.timestamp);
        everFunded = true;
        totalFunded += msg.value;
        uint64 earliestClose = IP42PayoutLedger(ledger_).effectiveEarliestCloseTimestamp();
        uint64 closeBy = ledger_ == address(0) ? 0 : IP42PayoutLedger(ledger_).closeByTimestamp();
        emit Funded(msg.sender, msg.value, newBalance, fundingCap, earliestClose, closeBy);
    }

    function _debitAccounted(uint256 amount) private {
        uint256 available = accountedBalance;
        if (amount > available) revert P42_ACCOUNTING_UNDERFLOW(available, amount);
        accountedBalance = available - amount;
    }

    function _requireFrozenRegistryBinding(address registry_) private view {
        uint256 problemId_ = problemId;
        if (IP42ProblemFreezeRegistry(registry_).problemPool(problemId_) != address(this)) {
            revert P42_BAD_PROBLEM_BINDING();
        }
        if (!IP42ProblemFreezeRegistry(registry_).explicitlyFrozen(problemId_)) {
            revert P42_PROBLEM_NOT_FROZEN();
        }
    }
}
