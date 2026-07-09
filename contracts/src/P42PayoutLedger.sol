// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42EscrowPool {
    function funded() external view returns (uint256);
}

interface IP42CreditCloseGuard {
    function openSubmissionCount() external view returns (uint256);
}

interface IP42FeeSink {
    function payFee(address to, uint256 amount) external;
    function payResidual(address to, uint256 amount) external;
}

/// @notice Final-denominator improvement accounting for one problem pool.
/// Credits accrue while the pool is open, but no solver can claim until close.
/// Credited `atoms` are MARGINAL frontier reductions (previous on-chain best
/// score minus the newly finalized score, in score atoms) recorded by the
/// submission manager — never seed-relative distances. Summing marginals
/// telescopes to (seed - final best), so each solver's proportional share
/// credit_i / totalCreditAtoms equals their advertised Delta_i / SigmaDelta_j
/// of the total frontier movement (F1).
contract P42PayoutLedger {
    error P42_NOT_OWNER();
    error P42_NOT_POOL();
    error P42_NOT_CREDIT_RECORDER();
    error P42_CREDIT_RECORDER_ALREADY_SET();
    error P42_CLOSED();
    error P42_NOT_CLOSED();
    error P42_PAUSED_NEW_ACTIONS();
    error P42_ZERO_CREDIT();
    error P42_FEE_TOO_HIGH();
    error P42_OPEN_SUBMISSIONS(uint256 openSubmissionCount);
    error P42_FEE_ALREADY_SWEPT();
    error P42_NO_FEE_TO_SWEEP();
    error P42_VOID_EXCEEDS_CREDIT(uint256 creditedAtoms, uint256 voidAtoms);
    error P42_CLAIMS_EXPIRED(uint64 deadline, uint64 nowAt);
    error P42_CLAIMS_NOT_EXPIRED(uint64 deadline, uint64 nowAt);
    error P42_RESIDUAL_ALREADY_SWEPT();

    uint16 public constant MAX_FEE_BPS = 250;

    /// @notice F15 claim deadline: solvers have this long after close() to
    /// pull their entitlement; afterwards consumeClaim reverts and the
    /// permissionless sweepResidual() sends the pool's FULL remaining balance
    /// (floor dust + never-claimed entitlements) to the treasury. A constant —
    /// published protocol policy, identical for every pool.
    uint64 public constant CLAIM_DEADLINE_SECONDS = 365 days;

    address public immutable owner;
    address public immutable pool;
    address public immutable treasury;
    uint16 public immutable feeBps;

    bool public closed;
    bool public pausedNewActions;
    bool public feeSwept;
    bool public residualSwept;
    /// @notice Timestamp of close(); anchors the F15 claim deadline.
    uint64 public closedAt;
    address public creditRecorder;
    uint256 public closedPoolBalance;
    uint256 public feeReserve;
    uint256 public totalCreditAtoms;

    mapping(address => uint256) public creditAtomsOf;
    mapping(address => uint256) public claimedWeiOf;

    event NewActionsPaused(bool paused);
    event CreditRecorderSet(address indexed recorder);
    event CreditRecorded(address indexed solver, uint256 atoms, uint256 totalCreditAtoms);
    event CreditVoided(address indexed solver, uint256 atoms, uint256 totalCreditAtoms);
    event Closed(uint256 poolBalance, uint256 feeReserve, uint64 closedAt, uint64 claimDeadline);
    event ClaimConsumed(address indexed solver, uint256 amount);
    event FeeSwept(address indexed treasury, uint256 amount);
    event ResidualSwept(address indexed treasury, uint256 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert P42_NOT_OWNER();
        _;
    }

    modifier onlyPool() {
        if (msg.sender != pool) revert P42_NOT_POOL();
        _;
    }

    constructor(address pool_, address owner_, address treasury_, uint16 feeBps_) {
        require(pool_ != address(0), "P42_POOL_ZERO");
        require(owner_ != address(0), "P42_OWNER_ZERO");
        require(treasury_ != address(0), "P42_TREASURY_ZERO");
        if (feeBps_ > MAX_FEE_BPS) revert P42_FEE_TOO_HIGH();
        pool = pool_;
        owner = owner_;
        treasury = treasury_;
        feeBps = feeBps_;
    }

    function setPausedNewActions(bool paused) external onlyOwner {
        pausedNewActions = paused;
        emit NewActionsPaused(paused);
    }

    function setCreditRecorder(address recorder) external onlyOwner {
        require(recorder != address(0), "P42_RECORDER_ZERO");
        if (creditRecorder != address(0)) revert P42_CREDIT_RECORDER_ALREADY_SET();
        creditRecorder = recorder;
        emit CreditRecorderSet(recorder);
    }

    function recordCredit(address solver, uint256 atoms) external {
        if (creditRecorder == address(0)) {
            if (msg.sender != owner) revert P42_NOT_CREDIT_RECORDER();
        } else if (msg.sender != creditRecorder) {
            revert P42_NOT_CREDIT_RECORDER();
        }
        if (closed) revert P42_CLOSED();
        if (pausedNewActions) revert P42_PAUSED_NEW_ACTIONS();
        if (atoms == 0) revert P42_ZERO_CREDIT();
        require(solver != address(0), "P42_SOLVER_ZERO");
        creditAtomsOf[solver] += atoms;
        totalCreditAtoms += atoms;
        emit CreditRecorded(solver, atoms, totalCreditAtoms);
    }

    /// @notice Reverses previously recorded credit during a poisoned-frontier
    /// recovery (the submission manager's voidFinalize). Callable ONLY by the
    /// creditRecorder — the void must be anchored to a specific on-chain
    /// finalize, never a free-standing governance number. Checked subtraction:
    /// a void can never push a balance negative, and it is refused once the
    /// pool is closed (entitlements are already snapshotted/claimable then).
    function voidCredit(address solver, uint256 atoms) external {
        if (msg.sender != creditRecorder) revert P42_NOT_CREDIT_RECORDER();
        if (closed) revert P42_CLOSED();
        if (atoms == 0) revert P42_ZERO_CREDIT();
        uint256 credited = creditAtomsOf[solver];
        if (credited < atoms || totalCreditAtoms < atoms) {
            revert P42_VOID_EXCEEDS_CREDIT(credited, atoms);
        }
        creditAtomsOf[solver] = credited - atoms;
        totalCreditAtoms -= atoms;
        emit CreditVoided(solver, atoms, totalCreditAtoms);
    }

    function provisionalEntitlement(address solver, uint256 additionalAtoms) external view returns (uint256) {
        uint256 denominator = totalCreditAtoms + additionalAtoms;
        if (denominator == 0) return 0;
        uint256 poolBalance = IP42EscrowPool(pool).funded();
        uint256 reserve = poolBalance * feeBps / 10_000;
        uint256 distributable = poolBalance - reserve;
        return distributable * (creditAtomsOf[solver] + additionalAtoms) / denominator;
    }

    function close() external onlyOwner {
        if (closed) revert P42_CLOSED();
        if (creditRecorder != address(0)) {
            uint256 openCount = IP42CreditCloseGuard(creditRecorder).openSubmissionCount();
            if (openCount != 0) revert P42_OPEN_SUBMISSIONS(openCount);
        }
        closed = true;
        closedAt = uint64(block.timestamp);
        closedPoolBalance = IP42EscrowPool(pool).funded();
        feeReserve = closedPoolBalance * feeBps / 10_000;
        emit Closed(closedPoolBalance, feeReserve, closedAt, closedAt + CLAIM_DEADLINE_SECONDS);
    }

    /// @notice The F15 claim deadline: last timestamp (inclusive) at which
    /// consumeClaim still pays. 0 while the pool is open.
    function claimDeadline() public view returns (uint64) {
        if (!closed) return 0;
        return closedAt + CLAIM_DEADLINE_SECONDS;
    }

    function distributablePool() public view returns (uint256) {
        if (!closed) return 0;
        return closedPoolBalance - feeReserve;
    }

    function finalEntitlement(address solver) public view returns (uint256) {
        if (!closed || totalCreditAtoms == 0) return 0;
        return distributablePool() * creditAtomsOf[solver] / totalCreditAtoms;
    }

    function claimable(address solver) public view returns (uint256) {
        uint256 entitlement = finalEntitlement(solver);
        uint256 claimed = claimedWeiOf[solver];
        if (entitlement <= claimed) return 0;
        return entitlement - claimed;
    }

    function consumeClaim(address solver) external onlyPool returns (uint256) {
        if (!closed) revert P42_NOT_CLOSED();
        uint64 deadline = closedAt + CLAIM_DEADLINE_SECONDS;
        if (block.timestamp > deadline) revert P42_CLAIMS_EXPIRED(deadline, uint64(block.timestamp));
        uint256 amount = claimable(solver);
        claimedWeiOf[solver] += amount;
        emit ClaimConsumed(solver, amount);
        return amount;
    }

    /// @notice Pays the withheld protocol fee to the treasury after close (L1).
    /// The destination (treasury) and amount (feeReserve) are fixed at close, so
    /// this is permissionless and single-use. Solver claims are always covered
    /// because Sigma(finalEntitlement) <= distributablePool() = closedPoolBalance
    /// - feeReserve, so the pool retains at least feeReserve for this transfer.
    function sweepFee() external {
        if (!closed) revert P42_NOT_CLOSED();
        if (feeSwept) revert P42_FEE_ALREADY_SWEPT();
        uint256 amount = feeReserve;
        if (amount == 0) revert P42_NO_FEE_TO_SWEEP();
        feeSwept = true;
        IP42FeeSink(pool).payFee(treasury, amount);
        emit FeeSwept(treasury, amount);
    }

    /// @notice F15 residual sweep: once the claim deadline has passed, anyone
    /// may send the pool's ENTIRE remaining balance (flooring dust plus every
    /// never-claimed entitlement, and the whole balance when
    /// totalCreditAtoms == 0) to the treasury. One-shot. Routed through the
    /// dedicated pool.payResidual — NOT payFee — so the fee counter stays
    /// clean; sweepFee remains independently available before this fires (an
    /// unswept feeReserve is simply folded into the full-balance sweep).
    function sweepResidual() external {
        if (!closed) revert P42_NOT_CLOSED();
        uint64 deadline = closedAt + CLAIM_DEADLINE_SECONDS;
        if (block.timestamp <= deadline) {
            revert P42_CLAIMS_NOT_EXPIRED(deadline, uint64(block.timestamp));
        }
        if (residualSwept) revert P42_RESIDUAL_ALREADY_SWEPT();
        residualSwept = true;
        uint256 amount = IP42EscrowPool(pool).funded();
        if (amount != 0) {
            IP42FeeSink(pool).payResidual(treasury, amount);
        }
        emit ResidualSwept(treasury, amount);
    }
}
