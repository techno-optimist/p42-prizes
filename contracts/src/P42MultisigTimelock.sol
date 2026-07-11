// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Rotatable multisig/timelock governance for P42 protocol contracts.
/// Standard operations are delayed and may be cancelled once per calldata
/// family by the guardian. Recovery-class operations require a higher signer
/// threshold and a longer delay, and cannot be guardian-vetoed. Governance
/// signer replacement can use the base threshold only with an independent
/// guardian approval, so the configured signer-loss tolerance remains
/// executable without letting a base signer quorum seize the override quorum.
/// Every operation expires. A configured pauser may only send a literal `true` pause call.
contract P42MultisigTimelock {
    error NotSigner();
    error NotGuardian();
    error NotPauser();
    error NotSelfOverride();
    error BadThreshold();
    error BadSigner();
    error BadGuardian();
    error BadDelay();
    error OpExists();
    error UnknownOp();
    error NotPending();
    error AlreadyConfirmed();
    error AlreadyCancelConfirmed();
    error AlreadyRecoveryApproved();
    error NotSignerRecovery();
    error NotReady(uint64 eta);
    error OpExpired(uint64 expiresAt);
    error NotEnoughConfirmations(uint256 have, uint256 need);
    error GuardianCannotCancelOverride();
    error GuardianFamilyCancellationUsed(bytes32 family);
    error PauseTargetNotAllowed(address target);
    error InvalidPauseSelector(bytes4 selector);
    error CallFailed();

    enum State {
        None,
        Pending,
        Executed,
        Cancelled,
        Expired
    }

    struct Op {
        uint64 eta;
        uint64 expiresAt;
        uint32 confirmations;
        uint32 cancelConfirmations;
        State state;
        bool overrideClass;
        bytes32 family;
    }

    bytes4 public constant SET_PAUSED_NEW_ACTIONS_SELECTOR = bytes4(keccak256("setPausedNewActions(bool)"));
    bytes4 public constant SET_PAUSED_ALL_SELECTOR = bytes4(keccak256("setPausedAll(bool)"));
    bytes4 public constant ADD_SIGNER_SELECTOR = bytes4(keccak256("addSigner(address)"));
    bytes4 public constant REMOVE_SIGNER_SELECTOR = bytes4(keccak256("removeSigner(address)"));
    bytes4 public constant SWAP_SIGNER_SELECTOR = bytes4(keccak256("swapSigner(address,address)"));
    bytes4 public constant SET_THRESHOLD_SELECTOR = bytes4(keccak256("setThreshold(uint256)"));
    bytes4 public constant SET_GUARDIAN_SELECTOR = bytes4(keccak256("setGuardian(address)"));

    address[] public signers;
    mapping(address => bool) public isSigner;
    uint256 public threshold;
    uint256 public immutable delay;
    uint256 public immutable overrideDelay;
    uint256 public immutable operationGracePeriod;
    address public guardian;
    uint256 public governanceEpoch;

    mapping(bytes32 => Op) public ops;
    mapping(bytes32 => mapping(address => bool)) public confirmedBy;
    mapping(bytes32 => mapping(address => bool)) public cancelConfirmedBy;
    mapping(bytes32 => bool) public guardianCancelledFamily;
    mapping(bytes32 => uint256) public guardianApprovedRecoveryEpoch;
    mapping(address => bool) public isPauser;
    mapping(address => bool) public pauseTargetAllowed;

    bool private _executingOverride;

    event Scheduled(
        bytes32 indexed id,
        address indexed target,
        uint256 value,
        bytes data,
        bytes32 salt,
        uint64 eta
    );
    event OverrideScheduled(bytes32 indexed id, bytes32 indexed family, uint64 eta, uint64 expiresAt);
    event Confirmed(bytes32 indexed id, address indexed signer, uint32 confirmations);
    event CancelConfirmed(bytes32 indexed id, address indexed signer, uint32 confirmations);
    event SignerRecoveryApproved(bytes32 indexed id, address indexed guardian, uint256 governanceEpoch);
    event Executed(bytes32 indexed id, address indexed target, uint256 value);
    event Cancelled(bytes32 indexed id, address indexed by);
    event Expired(bytes32 indexed id);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event SignerSwapped(address indexed oldSigner, address indexed newSigner);
    event ThresholdSet(uint256 threshold, uint256 overrideThreshold);
    event GuardianSet(address indexed guardian);
    event PauserSet(address indexed pauser, bool allowed);
    event PauseTargetSet(address indexed target, bool allowed);
    event EmergencyPaused(address indexed by, address indexed target, bytes4 indexed selector);

    modifier onlySigner() {
        if (!isSigner[msg.sender]) revert NotSigner();
        _;
    }

    modifier onlySelfOverride() {
        if (msg.sender != address(this) || !_executingOverride) revert NotSelfOverride();
        _;
    }

    constructor(address[] memory signers_, uint256 threshold_, uint256 delaySeconds_, address guardian_) {
        if (delaySeconds_ == 0 || delaySeconds_ > type(uint64).max / 2) revert BadDelay();
        if (guardian_ == address(0)) revert BadGuardian();
        for (uint256 i; i < signers_.length; i++) {
            address signer = signers_[i];
            if (signer == address(0) || isSigner[signer]) revert BadSigner();
            isSigner[signer] = true;
            signers.push(signer);
        }
        _requireValidThreshold(threshold_, signers_.length);
        threshold = threshold_;
        delay = delaySeconds_;
        overrideDelay = delaySeconds_ * 2;
        operationGracePeriod = 7 days;
        guardian = guardian_;
    }

    receive() external payable {}

    function signerCount() external view returns (uint256) {
        return signers.length;
    }

    function overrideThreshold() public view returns (uint256) {
        return _overrideThreshold(threshold, signers.length);
    }

    /// @notice Number of unavailable signers the configured base threshold can
    /// tolerate while governance recovery remains executable.
    function toleratedSignerLoss() public view returns (uint256) {
        return signers.length - threshold;
    }

    function opId(address target, uint256 value, bytes calldata data, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(target, value, data, salt));
    }

    function opFamily(address target, bytes calldata data) public pure returns (bytes32) {
        return keccak256(abi.encode(target, keccak256(data)));
    }

    function stateOf(bytes32 id) public view returns (State) {
        Op storage op = ops[id];
        if (op.state == State.Pending && block.timestamp > op.expiresAt) return State.Expired;
        return op.state;
    }

    function currentConfirmations(bytes32 id) public view returns (uint256 count) {
        for (uint256 i; i < signers.length; i++) {
            if (confirmedBy[id][signers[i]]) count += 1;
        }
    }

    function currentCancelConfirmations(bytes32 id) public view returns (uint256 count) {
        for (uint256 i; i < signers.length; i++) {
            if (cancelConfirmedBy[id][signers[i]]) count += 1;
        }
    }

    function schedule(address target, uint256 value, bytes calldata data, bytes32 salt)
        external
        onlySigner
        returns (bytes32 id)
    {
        return _schedule(target, value, data, salt, false);
    }

    function scheduleOverride(address target, uint256 value, bytes calldata data, bytes32 salt)
        external
        onlySigner
        returns (bytes32 id)
    {
        return _schedule(target, value, data, salt, true);
    }

    function confirm(bytes32 id) external onlySigner {
        Op storage op = _pending(id);
        if (confirmedBy[id][msg.sender]) revert AlreadyConfirmed();
        confirmedBy[id][msg.sender] = true;
        op.confirmations += 1;
        emit Confirmed(id, msg.sender, op.confirmations);
    }

    /// @notice Independently authorizes a base-quorum replacement of one lost
    /// signer. Other governance mutations always require the full override
    /// signer threshold.
    function approveSignerRecovery(address target, bytes calldata data, bytes32 salt) external {
        if (msg.sender != guardian) revert NotGuardian();
        bytes32 id = opId(target, 0, data, salt);
        Op storage op = _pending(id);
        if (!op.overrideClass || !_isSignerRecovery(target, data)) revert NotSignerRecovery();
        uint256 approvalEpoch = governanceEpoch + 1;
        if (guardianApprovedRecoveryEpoch[id] == approvalEpoch) revert AlreadyRecoveryApproved();
        guardianApprovedRecoveryEpoch[id] = approvalEpoch;
        emit SignerRecoveryApproved(id, msg.sender, governanceEpoch);
    }

    /// @notice Guardian cancellation is deliberately unavailable for recovery
    /// operations and is one-shot per target+calldata family for standard ops.
    function cancel(bytes32 id) external {
        if (msg.sender != guardian) revert NotGuardian();
        Op storage op = _pending(id);
        if (op.overrideClass) revert GuardianCannotCancelOverride();
        if (guardianCancelledFamily[op.family]) revert GuardianFamilyCancellationUsed(op.family);
        guardianCancelledFamily[op.family] = true;
        op.state = State.Cancelled;
        emit Cancelled(id, msg.sender);
    }

    /// @notice A normal signer majority can cancel any pending operation,
    /// including a recovery-class operation, without guardian participation.
    function confirmCancel(bytes32 id) external onlySigner {
        Op storage op = _pending(id);
        if (cancelConfirmedBy[id][msg.sender]) revert AlreadyCancelConfirmed();
        cancelConfirmedBy[id][msg.sender] = true;
        op.cancelConfirmations += 1;
        emit CancelConfirmed(id, msg.sender, op.cancelConfirmations);
        if (currentCancelConfirmations(id) >= threshold) {
            op.state = State.Cancelled;
            emit Cancelled(id, msg.sender);
        }
    }

    function expire(bytes32 id) external {
        Op storage op = ops[id];
        if (op.state == State.None) revert UnknownOp();
        if (op.state != State.Pending) revert NotPending();
        if (block.timestamp <= op.expiresAt) revert NotReady(op.expiresAt + 1);
        op.state = State.Expired;
        emit Expired(id);
    }

    /// @notice Permissionless once the required current signers have confirmed
    /// and the appropriate delay has elapsed.
    function execute(address target, uint256 value, bytes calldata data, bytes32 salt)
        external
        returns (bytes memory)
    {
        bytes32 id = opId(target, value, data, salt);
        Op storage op = ops[id];
        if (op.state != State.Pending) revert UnknownOp();
        if (block.timestamp > op.expiresAt) revert OpExpired(op.expiresAt);
        if (block.timestamp < op.eta) revert NotReady(op.eta);
        uint256 have = currentConfirmations(id);
        uint256 need = op.overrideClass ? _overrideExecutionThreshold(id, target, data) : threshold;
        if (have < need) revert NotEnoughConfirmations(have, need);

        op.state = State.Executed;
        bool previousOverride = _executingOverride;
        _executingOverride = op.overrideClass;
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        _executingOverride = previousOverride;
        if (!ok) revert CallFailed();
        emit Executed(id, target, value);
        return ret;
    }

    function addSigner(address signer) external onlySelfOverride {
        if (signer == address(0) || isSigner[signer]) revert BadSigner();
        uint256 newCount = signers.length + 1;
        uint256 newThreshold = threshold;
        uint256 minimumMajority = newCount / 2 + 1;
        if (newThreshold < minimumMajority) newThreshold = minimumMajority;
        _requireValidThreshold(newThreshold, newCount);
        isSigner[signer] = true;
        signers.push(signer);
        governanceEpoch += 1;
        if (newThreshold != threshold) {
            threshold = newThreshold;
            emit ThresholdSet(newThreshold, _overrideThreshold(newThreshold, newCount));
        }
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlySelfOverride {
        if (!isSigner[signer]) revert BadSigner();
        uint256 newCount = signers.length - 1;
        uint256 newThreshold = threshold < newCount ? threshold : newCount - 1;
        uint256 minimumMajority = newCount / 2 + 1;
        if (newThreshold < minimumMajority) newThreshold = minimumMajority;
        _requireValidThreshold(newThreshold, newCount);
        _removeSignerAt(_signerIndex(signer));
        governanceEpoch += 1;
        if (newThreshold != threshold) {
            threshold = newThreshold;
            emit ThresholdSet(newThreshold, _overrideThreshold(newThreshold, newCount));
        }
        emit SignerRemoved(signer);
    }

    function swapSigner(address oldSigner, address newSigner) external onlySelfOverride {
        if (!isSigner[oldSigner] || newSigner == address(0) || isSigner[newSigner]) revert BadSigner();
        uint256 index = _signerIndex(oldSigner);
        isSigner[oldSigner] = false;
        isSigner[newSigner] = true;
        signers[index] = newSigner;
        governanceEpoch += 1;
        emit SignerSwapped(oldSigner, newSigner);
    }

    function setThreshold(uint256 threshold_) external onlySelfOverride {
        _requireValidThreshold(threshold_, signers.length);
        threshold = threshold_;
        governanceEpoch += 1;
        emit ThresholdSet(threshold_, _overrideThreshold(threshold_, signers.length));
    }

    function setGuardian(address guardian_) external onlySelfOverride {
        if (guardian_ == address(0)) revert BadGuardian();
        guardian = guardian_;
        governanceEpoch += 1;
        emit GuardianSet(guardian_);
    }

    function setPauser(address pauser, bool allowed) external onlySelfOverride {
        if (pauser == address(0)) revert BadSigner();
        isPauser[pauser] = allowed;
        emit PauserSet(pauser, allowed);
    }

    function setPauseTarget(address target, bool allowed) external onlySelfOverride {
        if (target == address(0)) revert PauseTargetNotAllowed(target);
        pauseTargetAllowed[target] = allowed;
        emit PauseTargetSet(target, allowed);
    }

    /// @notice Sends only a literal pause=true call. Unpause must use the normal
    /// timelock path, so a compromised hot pauser cannot resume unsafe actions.
    function emergencyPause(address target, bytes4 selector) external {
        if (!isSigner[msg.sender] && !isPauser[msg.sender]) revert NotPauser();
        if (!pauseTargetAllowed[target]) revert PauseTargetNotAllowed(target);
        if (selector != SET_PAUSED_NEW_ACTIONS_SELECTOR && selector != SET_PAUSED_ALL_SELECTOR) {
            revert InvalidPauseSelector(selector);
        }
        (bool ok,) = target.call(abi.encodeWithSelector(selector, true));
        if (!ok) revert CallFailed();
        emit EmergencyPaused(msg.sender, target, selector);
    }

    function _schedule(address target, uint256 value, bytes calldata data, bytes32 salt, bool overrideClass)
        private
        returns (bytes32 id)
    {
        require(target != address(0), "P42_TARGET_ZERO");
        id = opId(target, value, data, salt);
        Op storage op = ops[id];
        if (op.state != State.None) revert OpExists();
        uint256 selectedDelay = overrideClass ? overrideDelay : delay;
        uint64 eta = uint64(block.timestamp + selectedDelay);
        uint64 expiresAt = uint64(uint256(eta) + operationGracePeriod);
        bytes32 family = opFamily(target, data);
        ops[id] = Op({
            eta: eta,
            expiresAt: expiresAt,
            confirmations: 1,
            cancelConfirmations: 0,
            state: State.Pending,
            overrideClass: overrideClass,
            family: family
        });
        confirmedBy[id][msg.sender] = true;
        emit Scheduled(id, target, value, data, salt, eta);
        if (overrideClass) emit OverrideScheduled(id, family, eta, expiresAt);
        emit Confirmed(id, msg.sender, 1);
    }

    function _pending(bytes32 id) private view returns (Op storage op) {
        op = ops[id];
        if (op.state == State.None) revert UnknownOp();
        if (op.state != State.Pending) revert NotPending();
        if (block.timestamp > op.expiresAt) revert OpExpired(op.expiresAt);
    }

    function _signerIndex(address signer) private view returns (uint256) {
        for (uint256 i; i < signers.length; i++) {
            if (signers[i] == signer) return i;
        }
        revert BadSigner();
    }

    function _removeSignerAt(uint256 index) private {
        address removed = signers[index];
        uint256 last = signers.length - 1;
        if (index != last) signers[index] = signers[last];
        signers.pop();
        isSigner[removed] = false;
    }

    function _requireValidThreshold(uint256 threshold_, uint256 count) private pure {
        if (
            count < 3 || threshold_ == 0 || threshold_ > count || threshold_ * 2 <= count
                || _overrideThreshold(threshold_, count) > count
        ) revert BadThreshold();
    }

    function _overrideThreshold(uint256 threshold_, uint256 count) private pure returns (uint256) {
        uint256 twoThirds = (2 * count + 2) / 3;
        uint256 thresholdPlusOne = threshold_ + 1;
        return thresholdPlusOne > twoThirds ? thresholdPlusOne : twoThirds;
    }

    function _overrideExecutionThreshold(bytes32 id, address target, bytes calldata data)
        private
        view
        returns (uint256)
    {
        if (
            _isSignerRecovery(target, data)
                && guardianApprovedRecoveryEpoch[id] == governanceEpoch + 1
        ) return threshold;
        return overrideThreshold();
    }

    function _isSignerRecovery(address target, bytes calldata data) private view returns (bool) {
        return target == address(this) && data.length >= 4 && bytes4(data[:4]) == SWAP_SIGNER_SELECTOR;
    }
}
