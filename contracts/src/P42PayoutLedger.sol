// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42EscrowPool {
    function funded() external view returns (uint256);
}

/// @notice Final-denominator improvement accounting for one problem pool.
/// Credits accrue while the pool is open, but no solver can claim until close.
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

    uint16 public constant MAX_FEE_BPS = 500;

    address public immutable owner;
    address public immutable pool;
    address public immutable treasury;
    uint16 public immutable feeBps;

    bool public closed;
    bool public pausedNewActions;
    address public creditRecorder;
    uint256 public closedPoolBalance;
    uint256 public feeReserve;
    uint256 public totalCreditAtoms;

    mapping(address => uint256) public creditAtomsOf;
    mapping(address => uint256) public claimedWeiOf;

    event NewActionsPaused(bool paused);
    event CreditRecorderSet(address indexed recorder);
    event CreditRecorded(address indexed solver, uint256 atoms, uint256 totalCreditAtoms);
    event Closed(uint256 poolBalance, uint256 feeReserve);
    event ClaimConsumed(address indexed solver, uint256 amount);

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
        closed = true;
        closedPoolBalance = IP42EscrowPool(pool).funded();
        feeReserve = closedPoolBalance * feeBps / 10_000;
        emit Closed(closedPoolBalance, feeReserve);
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
        uint256 amount = claimable(solver);
        claimedWeiOf[solver] += amount;
        emit ClaimConsumed(solver, amount);
        return amount;
    }
}
