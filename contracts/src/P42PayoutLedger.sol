// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {P42Math} from "./P42Math.sol";
import {P42RolloverVault} from "./P42RolloverVault.sol";

interface IP42EscrowPool {
    function funded() external view returns (uint256);
    function firstFundedAt() external view returns (uint64);
    function payRollover(address to, uint256 amount) external;
}

interface IP42CreditCloseGuard {
    function openSubmissionCount() external view returns (uint256);
}

/// @notice Final-denominator improvement accounting for one problem pool.
/// @dev A close has exactly two exclusive economic modes. With no final credit,
/// sponsors retain perpetual pull rights to their recorded principal. With
/// positive credit, solver entitlements are gross and each successful claim
/// atomically pays its own fee; only post-deadline positive-credit residuals
/// can enter the immutable rollover destination.
contract P42PayoutLedger {
    error P42_NOT_OWNER();
    error P42_NOT_POOL();
    error P42_NOT_CREDIT_RECORDER();
    error P42_CREDIT_RECORDER_ALREADY_SET();
    error P42_ROLLOVER_ALREADY_SET();
    error P42_ROLLOVER_DESTINATION_INVALID();
    error P42_ROLLOVER_DESTINATION_NOT_SEPARATE();
    error P42_ROLLOVER_DESTINATION_NOT_SET();
    error P42_CLOSED();
    error P42_NOT_CLOSED();
    error P42_PAUSED_NEW_ACTIONS();
    error P42_ZERO_CREDIT();
    error P42_FEE_TOO_HIGH();
    error P42_OPEN_SUBMISSIONS(uint256 openSubmissionCount);
    error P42_BAD_EARLIEST_CLOSE();
    error P42_BAD_CLOSE_BY();
    error P42_CLOSE_BY_NOT_REACHED(uint64 closeByTimestamp, uint64 nowAt);
    error P42_FEE_CLAIM_ONLY();
    error P42_VOID_EXCEEDS_CREDIT(uint256 creditedAtoms, uint256 voidAtoms);
    error P42_CLAIMS_EXPIRED(uint64 deadline, uint64 nowAt);
    error P42_CLAIMS_NOT_EXPIRED(uint64 deadline, uint64 nowAt);
    error P42_ROLLOVER_ALREADY_SWEPT();
    error P42_ROLLOVER_NOT_AVAILABLE();
    error P42_CREDIT_BOUND_EXCEEDED(uint256 attempted, uint256 maxAllowed);

    uint16 public constant MAX_FEE_BPS = 250;
    uint64 public constant CLAIM_DEADLINE_SECONDS = 365 days;
    uint64 public constant MIN_COMPETITION_SECONDS = 30 days;
    uint64 public constant MIN_CLOSE_DELAY_SECONDS = 180 days;
    uint256 public constant MAX_TOTAL_CREDIT_ATOMS = type(uint256).max >> 1;

    address public immutable owner;
    address public immutable pool;
    address public immutable treasury;
    uint16 public immutable feeBps;
    uint64 public immutable earliestCloseTimestamp;
    uint64 public immutable closeByTimestamp;

    bool public closed;
    bool public pausedNewActions;
    /// @dev Retained for ABI visibility. Fees are no longer swept at close.
    bool public feeSwept;
    bool public rolloverSwept;
    /// @dev Legacy alias for rolloverSwept.
    bool public residualSwept;
    uint64 public closedAt;
    address public creditRecorder;
    /// @notice Set exactly once before close to an ownerless restricted vault.
    address public rolloverDestination;
    uint256 public closedPoolBalance;
    /// @dev Retained for ABI compatibility; always zero in the claim-time-fee model.
    uint256 public feeReserve;
    uint256 public totalCreditAtoms;
    uint256 public totalGrossClaimed;
    uint256 public totalFeeAccrued;

    mapping(address => uint256) public creditAtomsOf;
    /// @notice Gross entitlement consumed by each solver, before claim-time fee.
    mapping(address => uint256) public claimedWeiOf;

    event NewActionsPaused(bool paused);
    event CreditRecorderSet(address indexed recorder);
    event RolloverDestinationSet(address indexed destination);
    event CreditRecorded(address indexed solver, uint256 atoms, uint256 totalCreditAtoms);
    event CreditVoided(address indexed solver, uint256 atoms, uint256 totalCreditAtoms);
    event Closed(
        uint256 poolBalance,
        uint256 feeReserve,
        uint64 closedAt,
        uint64 claimDeadline
    );
    event ClaimConsumed(address indexed solver, uint256 grossAmount, uint256 feeAmount);
    event RolloverSwept(address indexed destination, uint256 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert P42_NOT_OWNER();
        _;
    }

    modifier onlyPool() {
        if (msg.sender != pool) revert P42_NOT_POOL();
        _;
    }

    constructor(
        address pool_,
        address owner_,
        address treasury_,
        uint16 feeBps_,
        uint64 earliestCloseTimestamp_,
        uint64 closeByTimestamp_
    ) {
        require(pool_ != address(0), "P42_POOL_ZERO");
        require(owner_ != address(0), "P42_OWNER_ZERO");
        require(treasury_ != address(0), "P42_TREASURY_ZERO");
        if (feeBps_ > MAX_FEE_BPS) revert P42_FEE_TOO_HIGH();
        if (earliestCloseTimestamp_ < block.timestamp + MIN_COMPETITION_SECONDS) {
            revert P42_BAD_EARLIEST_CLOSE();
        }
        if (closeByTimestamp_ < block.timestamp + MIN_CLOSE_DELAY_SECONDS) revert P42_BAD_CLOSE_BY();
        if (closeByTimestamp_ < earliestCloseTimestamp_) revert P42_BAD_CLOSE_BY();
        pool = pool_;
        owner = owner_;
        treasury = treasury_;
        feeBps = feeBps_;
        earliestCloseTimestamp = earliestCloseTimestamp_;
        closeByTimestamp = closeByTimestamp_;
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

    /// @notice One-time deployment ceremony step. Exact runtime-code pinning
    /// prevents an EOA or a marker-spoofing arbitrary receiver from becoming a
    /// future-prize rollover endpoint.
    function setRolloverDestination(address destination) external onlyOwner {
        if (rolloverDestination != address(0)) revert P42_ROLLOVER_ALREADY_SET();
        if (destination == treasury) revert P42_ROLLOVER_DESTINATION_NOT_SEPARATE();
        if (destination.codehash != keccak256(type(P42RolloverVault).runtimeCode)) {
            revert P42_ROLLOVER_DESTINATION_INVALID();
        }
        rolloverDestination = destination;
        emit RolloverDestinationSet(destination);
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
        uint256 total = totalCreditAtoms;
        uint256 solverCredit = creditAtomsOf[solver];
        if (atoms > MAX_TOTAL_CREDIT_ATOMS - total) {
            revert P42_CREDIT_BOUND_EXCEEDED(atoms, MAX_TOTAL_CREDIT_ATOMS - total);
        }
        if (atoms > MAX_TOTAL_CREDIT_ATOMS - solverCredit) {
            revert P42_CREDIT_BOUND_EXCEEDED(atoms, MAX_TOTAL_CREDIT_ATOMS - solverCredit);
        }
        totalCreditAtoms = total + atoms;
        creditAtomsOf[solver] = solverCredit + atoms;
        emit CreditRecorded(solver, atoms, total + atoms);
    }

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
        uint256 total = totalCreditAtoms;
        uint256 solverCredit = creditAtomsOf[solver];
        if (additionalAtoms > MAX_TOTAL_CREDIT_ATOMS - total) {
            revert P42_CREDIT_BOUND_EXCEEDED(additionalAtoms, MAX_TOTAL_CREDIT_ATOMS - total);
        }
        if (additionalAtoms > MAX_TOTAL_CREDIT_ATOMS - solverCredit) {
            revert P42_CREDIT_BOUND_EXCEEDED(additionalAtoms, MAX_TOTAL_CREDIT_ATOMS - solverCredit);
        }
        uint256 denominator = total + additionalAtoms;
        if (denominator == 0) return 0;
        return P42Math.mulDiv(IP42EscrowPool(pool).funded(), solverCredit + additionalAtoms, denominator);
    }

    /// @notice Permissionless and immutable: close is available only at the
    /// configured close-by timestamp. The owner has no early-close privilege.
    function close() external {
        if (closed) revert P42_CLOSED();
        if (block.timestamp < closeByTimestamp) {
            revert P42_CLOSE_BY_NOT_REACHED(closeByTimestamp, uint64(block.timestamp));
        }
        if (rolloverDestination == address(0)) revert P42_ROLLOVER_DESTINATION_NOT_SET();
        if (creditRecorder != address(0)) {
            uint256 openCount = IP42CreditCloseGuard(creditRecorder).openSubmissionCount();
            if (openCount != 0) revert P42_OPEN_SUBMISSIONS(openCount);
        }
        closed = true;
        closedAt = uint64(block.timestamp);
        closedPoolBalance = IP42EscrowPool(pool).funded();
        // Fees exist only as successful solver claims, never as a close-time reserve.
        feeReserve = 0;
        emit Closed(closedPoolBalance, 0, closedAt, claimDeadline());
    }

    function fundingDeadline() public view returns (uint64) {
        return closeByTimestamp - MIN_COMPETITION_SECONDS;
    }

    /// @dev This retains the public scheduling view for funding UX, but it no
    /// longer grants any actor authority to close before closeByTimestamp.
    function effectiveEarliestCloseTimestamp() public view returns (uint64) {
        uint64 firstFundedAt = IP42EscrowPool(pool).firstFundedAt();
        if (firstFundedAt == 0) return earliestCloseTimestamp;
        uint64 fundedEarliest = firstFundedAt + MIN_COMPETITION_SECONDS;
        return fundedEarliest > earliestCloseTimestamp ? fundedEarliest : earliestCloseTimestamp;
    }

    function positiveCreditClose() public view returns (bool) {
        return closed && totalCreditAtoms != 0;
    }

    function sponsorRefundsEnabled() external view returns (bool) {
        return closed && totalCreditAtoms == 0;
    }

    function claimDeadline() public view returns (uint64) {
        if (!positiveCreditClose()) return 0;
        return closedAt + CLAIM_DEADLINE_SECONDS;
    }

    /// @notice Solver entitlements are gross. Claim-time fees are subtracted
    /// only when the individual solver actually settles a successful claim.
    function distributablePool() public view returns (uint256) {
        if (!positiveCreditClose()) return 0;
        return closedPoolBalance;
    }

    function finalEntitlement(address solver) public view returns (uint256) {
        if (!positiveCreditClose()) return 0;
        return P42Math.mulDiv(closedPoolBalance, creditAtomsOf[solver], totalCreditAtoms);
    }

    function claimable(address solver) public view returns (uint256) {
        if (!positiveCreditClose() || block.timestamp > claimDeadline()) return 0;
        uint256 entitlement = finalEntitlement(solver);
        uint256 claimed = claimedWeiOf[solver];
        if (entitlement <= claimed) return 0;
        return entitlement - claimed;
    }

    function consumeClaim(address solver) external onlyPool returns (uint256 grossAmount, uint256 feeAmount) {
        if (!closed) revert P42_NOT_CLOSED();
        if (!positiveCreditClose()) return (0, 0);
        uint64 deadline = claimDeadline();
        if (block.timestamp > deadline) revert P42_CLAIMS_EXPIRED(deadline, uint64(block.timestamp));
        grossAmount = claimable(solver);
        claimedWeiOf[solver] += grossAmount;
        feeAmount = P42Math.mulDiv(grossAmount, feeBps, 10_000);
        totalGrossClaimed += grossAmount;
        totalFeeAccrued += feeAmount;
        emit ClaimConsumed(solver, grossAmount, feeAmount);
    }

    /// @notice Removed economics: a fee cannot be extracted before a solver has
    /// actually received a corresponding successful settlement.
    function sweepFee() external pure {
        revert P42_FEE_CLAIM_ONLY();
    }

    function sweepRollover() external {
        _sweepRollover();
    }

    /// @notice Legacy entry point now follows the rollover-only policy; it can
    /// never transfer a positive-credit residual to the fee treasury.
    function sweepResidual() external {
        _sweepRollover();
    }

    function _sweepRollover() private {
        if (!closed) revert P42_NOT_CLOSED();
        if (!positiveCreditClose()) revert P42_ROLLOVER_NOT_AVAILABLE();
        uint64 deadline = claimDeadline();
        if (block.timestamp <= deadline) revert P42_CLAIMS_NOT_EXPIRED(deadline, uint64(block.timestamp));
        if (rolloverSwept) revert P42_ROLLOVER_ALREADY_SWEPT();
        rolloverSwept = true;
        residualSwept = true;
        // `funded()` is accounted principal only; raw balance is deliberately
        // never read here, so forced ETH cannot be swept as prize residual.
        uint256 amount = IP42EscrowPool(pool).funded();
        if (amount != 0) IP42EscrowPool(pool).payRollover(rolloverDestination, amount);
        emit RolloverSwept(rolloverDestination, amount);
    }
}
