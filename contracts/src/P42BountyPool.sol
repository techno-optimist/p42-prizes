// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42PayoutLedger {
    function consumeClaim(address solver) external returns (uint256 grossAmount, uint256 feeAmount);
    function creditRecorder() external view returns (address);
    function closed() external view returns (bool);
    function sponsorRefundsEnabled() external view returns (bool);
    function rolloverDestination() external view returns (address);
    function treasury() external view returns (address);
    function effectiveEarliestCloseTimestamp() external view returns (uint64);
    function fundingDeadline() external view returns (uint64);
    function closeByTimestamp() external view returns (uint64);
}

interface ISubmissionManagerArmed {
    function fundingArmed() external view returns (bool);
    function fundingAuthorizationExpiresAt() external view returns (uint64);
    function objectiveProofCapabilityActive() external view returns (bool);
}

interface IP42DonationPool {
    function fundFor(address sponsor) external payable;
    function registry() external view returns (address);
    function problemId() external view returns (uint256);
    function acceptingFunds() external view returns (bool);
}

interface IP42ProblemFreezeRegistry {
    function explicitlyFrozen(uint256 problemId) external view returns (bool);
    function problemPool(uint256 problemId) external view returns (address);
}

/// @notice Per-problem ETH escrow with separate sponsor, solver, rollover, and
/// forced-ETH accounting. `claim()` and `claimTo()` retain their public shape.
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
    error P42_FUNDING_AUTHORIZATION_EXPIRED(uint64 expiresAt, uint64 nowAt);
    error P42_OBJECTIVE_PROOF_CAPABILITY_INACTIVE();
    error P42_ROLLOVER_DESTINATION_NOT_SET();
    error P42_CREDIT_RECORDER_MISMATCH(address creditRecorder, address submissionManager);
    error P42_NOT_ACCEPTING_FUNDS();
    error P42_PROBLEM_NOT_FROZEN();
    error P42_FUNDING_WINDOW_CLOSED(uint64 fundingDeadline, uint64 nowAt);
    error P42_FUNDING_CAP_EXCEEDED(uint256 cap, uint256 attemptedTotal);
    error P42_NOTHING_TO_CLAIM();
    error P42_RECIPIENT_ZERO();
    error P42_INVALID_DONATION_POOL();
    error P42_POOL_CLOSED();
    error P42_ACCOUNTING_UNDERFLOW(uint256 available, uint256 requested);
    error P42_TRANSFER_FAILED();
    error P42_SPONSOR_REFUNDS_DISABLED();
    error P42_NOTHING_TO_REFUND();
    error P42_FORCED_ETH_EXCEEDS_AVAILABLE(uint256 available, uint256 requested);
    error P42_FORCED_ETH_RECOVERY_NOT_CLOSED();
    error P42_FORCED_ETH_ROLLOVER_NOT_SET();
    error P42_FEE_CLAIM_ONLY();
    error P42_RESIDUAL_DISABLED();

    address public immutable owner;
    uint256 public immutable fundingCap;
    address public ledger;
    address public submissionManager;
    address public registry;
    uint256 public problemId;
    bool public acceptingFunds;
    bool public everFunded;
    uint64 public firstFundedAt;
    /// @notice Legitimate, accounted ETH only. Forced ETH is never included.
    uint256 public accountedBalance;
    uint256 public totalFunded;
    /// @notice Net ETH paid or directed by solvers after individual claim fees.
    uint256 public totalClaimed;
    uint256 public totalWinningsDonated;
    uint256 public totalGrossClaimed;
    uint256 public totalFeeAccrued;
    uint256 public totalFeePaid;
    uint256 public accruedFeeBalance;
    uint256 public totalSponsorRefunded;
    uint256 public totalRolloverPaid;
    uint256 public totalForcedEthRecovered;
    /// @dev Legacy public counter; residuals are now rollover outflows only.
    uint256 public totalResidualPaid;
    mapping(address => uint256) public sponsorshipOf;

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
    event SponsorshipFunded(
        address indexed payer,
        address indexed sponsor,
        uint256 amount,
        uint256 sponsorPrincipal,
        uint256 accountedBalance
    );
    event SponsorRefunded(address indexed sponsor, address indexed recipient, uint256 principal);
    event Claimed(address indexed solver, uint256 amount);
    event ClaimedTo(address indexed solver, address indexed recipient, uint256 amount);
    event SolverClaimSettled(
        address indexed solver,
        address indexed recipient,
        uint256 grossAmount,
        uint256 solverPayment,
        uint256 feeAmount
    );
    event WinningsDonated(
        address indexed solver,
        address indexed destinationPool,
        uint256 grossAmount,
        uint256 donatedAmount,
        uint256 feeAmount
    );
    event FeePaid(address indexed to, uint256 amount);
    event FeeAccrued(address indexed solver, uint256 amount, uint256 accruedFeeBalance);
    event FeeClaimed(address indexed treasury, address indexed recipient, uint256 amount);
    event RolloverPaid(address indexed to, uint256 amount);
    event ForcedEthRecovered(address indexed to, uint256 amount, uint256 remainingForcedEth);
    event ForcedEthSwept(
        address indexed caller,
        address indexed destination,
        uint256 amount,
        uint256 remainingForcedEth
    );

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

    constructor(address owner_, uint256 fundingCap_) {
        require(owner_ != address(0), "P42_OWNER_ZERO");
        require(fundingCap_ > 0, "P42_FUNDING_CAP_ZERO");
        owner = owner_;
        fundingCap = fundingCap_;
    }

    receive() external payable {
        _fund(msg.sender);
    }

    function setLedger(address ledger_) external onlyOwner {
        if (ledger != address(0)) revert P42_LEDGER_ALREADY_SET();
        require(ledger_ != address(0), "P42_LEDGER_ZERO");
        ledger = ledger_;
        emit LedgerSet(ledger_);
    }

    function setSubmissionManager(address submissionManager_) external onlyOwner {
        if (submissionManager != address(0)) revert P42_SUBMISSION_MANAGER_ALREADY_SET();
        require(submissionManager_ != address(0), "P42_SUBMISSION_MANAGER_ZERO");
        submissionManager = submissionManager_;
        emit SubmissionManagerSet(submissionManager_);
    }

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

    function setAcceptingFunds(bool accepting) external onlyOwner {
        if (accepting) {
            if (ledger == address(0)) revert P42_LEDGER_NOT_SET();
            if (IP42PayoutLedger(ledger).rolloverDestination() == address(0)) {
                revert P42_ROLLOVER_DESTINATION_NOT_SET();
            }
            uint64 deadline = IP42PayoutLedger(ledger).fundingDeadline();
            if (block.timestamp > deadline) revert P42_FUNDING_WINDOW_CLOSED(deadline, uint64(block.timestamp));
            address registry_ = registry;
            if (registry_ == address(0)) revert P42_REGISTRY_NOT_SET();
            _requireFrozenRegistryBinding(registry_);
            address manager = submissionManager;
            address recorder = IP42PayoutLedger(ledger).creditRecorder();
            if (recorder != manager) revert P42_CREDIT_RECORDER_MISMATCH(recorder, manager);
            if (manager == address(0) || !ISubmissionManagerArmed(manager).fundingArmed()) {
                revert P42_FUNDING_NOT_ARMED();
            }
            if (!ISubmissionManagerArmed(manager).objectiveProofCapabilityActive()) {
                revert P42_OBJECTIVE_PROOF_CAPABILITY_INACTIVE();
            }
            uint64 authorizationExpiresAt = ISubmissionManagerArmed(manager).fundingAuthorizationExpiresAt();
            if (block.timestamp > authorizationExpiresAt) {
                revert P42_FUNDING_AUTHORIZATION_EXPIRED(authorizationExpiresAt, uint64(block.timestamp));
            }
        }
        acceptingFunds = accepting;
        emit AcceptingFundsSet(accepting);
    }

    function fund() external payable {
        _fund(msg.sender);
    }

    function fundFor(address sponsor) external payable {
        if (sponsor == address(0)) revert P42_RECIPIENT_ZERO();
        _fund(sponsor);
    }

    function funded() external view returns (uint256) {
        return accountedBalance;
    }

    function forcedEthAvailable() public view returns (uint256) {
        uint256 rawBalance = address(this).balance;
        uint256 accounted = accountedBalance;
        return rawBalance > accounted ? rawBalance - accounted : 0;
    }

    function rolloverBalance() external view returns (uint256) {
        return accountedBalance - accruedFeeBalance;
    }

    function claim() external nonReentrant {
        _claimTo(msg.sender, payable(msg.sender));
    }

    function claimTo(address payable recipient) external nonReentrant {
        if (recipient == address(0)) revert P42_RECIPIENT_ZERO();
        _claimTo(msg.sender, recipient);
    }

    /// @notice Consume the caller's matured award and atomically sponsor a
    /// different active P42 pool while retaining solver attribution.
    function donateClaimToPool(address destinationPool) external nonReentrant {
        if (destinationPool == address(0) || destinationPool == address(this)) {
            revert P42_INVALID_DONATION_POOL();
        }
        address registry_ = registry;
        if (registry_ == address(0)) revert P42_REGISTRY_NOT_SET();
        IP42DonationPool destination = IP42DonationPool(destinationPool);
        uint256 destinationProblemId = destination.problemId();
        if (
            destination.registry() != registry_ || destinationProblemId == 0
                || IP42ProblemFreezeRegistry(registry_).problemPool(destinationProblemId) != destinationPool
                || !IP42ProblemFreezeRegistry(registry_).explicitlyFrozen(destinationProblemId)
                || !destination.acceptingFunds()
        ) {
            revert P42_INVALID_DONATION_POOL();
        }
        address ledger_ = ledger;
        if (ledger_ == address(0)) revert P42_LEDGER_NOT_SET();
        (uint256 grossAmount, uint256 feeAmount) = IP42PayoutLedger(ledger_).consumeClaim(msg.sender);
        if (grossAmount == 0) revert P42_NOTHING_TO_CLAIM();
        uint256 donatedAmount = grossAmount - feeAmount;
        _debitAccounted(donatedAmount);
        totalGrossClaimed += grossAmount;
        totalClaimed += donatedAmount;
        totalWinningsDonated += donatedAmount;
        totalFeeAccrued += feeAmount;
        accruedFeeBalance += feeAmount;
        if (donatedAmount != 0) {
            destination.fundFor{value: donatedAmount}(msg.sender);
        }
        if (feeAmount != 0) emit FeeAccrued(msg.sender, feeAmount, accruedFeeBalance);
        emit WinningsDonated(msg.sender, destinationPool, grossAmount, donatedAmount, feeAmount);
        emit SolverClaimSettled(msg.sender, destinationPool, grossAmount, donatedAmount, feeAmount);
    }

    function sponsorRefund() external nonReentrant {
        _sponsorRefundTo(msg.sender, payable(msg.sender));
    }

    /// @notice Zero-credit sponsors can redirect only their own recorded
    /// principal. This path has no expiry, fee, or post-deadline diversion.
    function sponsorRefundTo(address payable recipient) external nonReentrant {
        if (recipient == address(0)) revert P42_RECIPIENT_ZERO();
        _sponsorRefundTo(msg.sender, recipient);
    }

    function recoverForcedEth(uint256 amount) external nonReentrant {
        uint256 available = forcedEthAvailable();
        if (amount == 0 || amount > available) revert P42_FORCED_ETH_EXCEEDS_AVAILABLE(available, amount);
        address ledger_ = ledger;
        if (ledger_ == address(0) || !IP42PayoutLedger(ledger_).closed()) {
            revert P42_FORCED_ETH_RECOVERY_NOT_CLOSED();
        }
        address destination = IP42PayoutLedger(ledger_).rolloverDestination();
        if (destination == address(0)) revert P42_FORCED_ETH_ROLLOVER_NOT_SET();
        totalForcedEthRecovered += amount;
        (bool ok,) = payable(destination).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit ForcedEthRecovered(destination, amount, forcedEthAvailable());
        emit ForcedEthSwept(msg.sender, destination, amount, forcedEthAvailable());
    }

    function claimFees() external nonReentrant {
        address ledger_ = ledger;
        if (ledger_ == address(0)) revert P42_LEDGER_NOT_SET();
        _claimFeesTo(payable(IP42PayoutLedger(ledger_).treasury()));
    }

    function claimFeesTo(address payable recipient) external nonReentrant {
        if (recipient == address(0)) revert P42_RECIPIENT_ZERO();
        address ledger_ = ledger;
        if (ledger_ == address(0)) revert P42_LEDGER_NOT_SET();
        if (msg.sender != IP42PayoutLedger(ledger_).treasury()) revert P42_FEE_CLAIM_ONLY();
        _claimFeesTo(recipient);
    }

    function payRollover(address to, uint256 amount) external nonReentrant {
        if (msg.sender != ledger) revert P42_NOT_LEDGER();
        if (to == address(0) || to != IP42PayoutLedger(ledger).rolloverDestination()) revert P42_NOT_LEDGER();
        _debitAccounted(amount);
        totalRolloverPaid += amount;
        totalResidualPaid += amount;
        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit RolloverPaid(to, amount);
    }

    /// @dev Legacy surface retained to make the removed pre-claim fee sweep
    /// fail explicitly rather than silently changing accounting semantics.
    function payFee(address, uint256) external pure {
        revert P42_FEE_CLAIM_ONLY();
    }

    /// @dev Legacy surface retained as an explicit rejection: only the ledger's
    /// positive-credit rollover path can move accounted residuals.
    function payResidual(address, uint256) external pure {
        revert P42_RESIDUAL_DISABLED();
    }

    function _claimTo(address solver, address payable recipient) private {
        address ledger_ = ledger;
        if (ledger_ == address(0)) revert P42_LEDGER_NOT_SET();
        (uint256 grossAmount, uint256 feeAmount) = IP42PayoutLedger(ledger_).consumeClaim(solver);
        if (grossAmount == 0) revert P42_NOTHING_TO_CLAIM();
        uint256 solverPayment = grossAmount - feeAmount;
        _debitAccounted(solverPayment);
        totalGrossClaimed += grossAmount;
        totalClaimed += solverPayment;
        totalFeeAccrued += feeAmount;
        accruedFeeBalance += feeAmount;
        if (solverPayment != 0) {
            (bool paidSolver,) = recipient.call{value: solverPayment}("");
            if (!paidSolver) revert P42_TRANSFER_FAILED();
        }
        if (feeAmount != 0) emit FeeAccrued(solver, feeAmount, accruedFeeBalance);
        emit Claimed(solver, solverPayment);
        emit ClaimedTo(solver, recipient, solverPayment);
        emit SolverClaimSettled(solver, recipient, grossAmount, solverPayment, feeAmount);
    }

    function _sponsorRefundTo(address sponsor, address payable recipient) private {
        address ledger_ = ledger;
        if (ledger_ == address(0)) revert P42_LEDGER_NOT_SET();
        if (!IP42PayoutLedger(ledger_).sponsorRefundsEnabled()) revert P42_SPONSOR_REFUNDS_DISABLED();
        uint256 principal = sponsorshipOf[sponsor];
        if (principal == 0) revert P42_NOTHING_TO_REFUND();
        sponsorshipOf[sponsor] = 0;
        _debitAccounted(principal);
        totalSponsorRefunded += principal;
        (bool ok,) = recipient.call{value: principal}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        emit SponsorRefunded(sponsor, recipient, principal);
    }

    function _claimFeesTo(address payable recipient) private {
        uint256 amount = accruedFeeBalance;
        if (amount == 0) revert P42_NOTHING_TO_CLAIM();
        accruedFeeBalance = 0;
        _debitAccounted(amount);
        totalFeePaid += amount;
        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert P42_TRANSFER_FAILED();
        address treasury_ = IP42PayoutLedger(ledger).treasury();
        emit FeePaid(recipient, amount);
        emit FeeClaimed(treasury_, recipient, amount);
    }

    function _fund(address sponsor) private {
        require(msg.value > 0, "P42_ZERO_FUNDING");
        address manager = submissionManager;
        if (manager == address(0) || !ISubmissionManagerArmed(manager).fundingArmed()) {
            revert P42_FUNDING_NOT_ARMED();
        }
        if (!acceptingFunds) revert P42_NOT_ACCEPTING_FUNDS();
        address registry_ = registry;
        if (registry_ == address(0)) revert P42_REGISTRY_NOT_SET();
        _requireFrozenRegistryBinding(registry_);
        address ledger_ = ledger;
        if (ledger_ != address(0) && IP42PayoutLedger(ledger_).closed()) revert P42_POOL_CLOSED();
        uint64 authorizationExpiresAt = ISubmissionManagerArmed(manager).fundingAuthorizationExpiresAt();
        if (block.timestamp > authorizationExpiresAt) {
            revert P42_FUNDING_AUTHORIZATION_EXPIRED(authorizationExpiresAt, uint64(block.timestamp));
        }
        uint64 deadline = IP42PayoutLedger(ledger_).fundingDeadline();
        if (block.timestamp > deadline) revert P42_FUNDING_WINDOW_CLOSED(deadline, uint64(block.timestamp));
        uint256 currentBalance = accountedBalance;
        if (msg.value > fundingCap - currentBalance) {
            revert P42_FUNDING_CAP_EXCEEDED(fundingCap, currentBalance + msg.value);
        }
        uint256 newBalance = currentBalance + msg.value;
        accountedBalance = newBalance;
        sponsorshipOf[sponsor] += msg.value;
        if (!everFunded) firstFundedAt = uint64(block.timestamp);
        everFunded = true;
        totalFunded += msg.value;
        uint64 earliestClose = IP42PayoutLedger(ledger_).effectiveEarliestCloseTimestamp();
        uint64 closeBy = IP42PayoutLedger(ledger_).closeByTimestamp();
        emit Funded(msg.sender, msg.value, newBalance, fundingCap, earliestClose, closeBy);
        emit SponsorshipFunded(msg.sender, sponsor, msg.value, sponsorshipOf[sponsor], newBalance);
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
