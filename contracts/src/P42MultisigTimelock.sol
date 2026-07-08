// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Governance root-of-trust for P42: an M-of-N multisig with a timelock
/// delay and an emergency guardian veto. Deployed as the `owner` of the P42
/// contracts so NO single key can pause, close, sweep fees, slash, or re-wire
/// the protocol — every privileged action must be scheduled by a signer,
/// confirmed by a threshold of signers, and can only execute after `delay`
/// (a window in which anyone can observe the pending action, and the guardian
/// can cancel it). The guardian can ONLY cancel (never propose or execute), so
/// it is a brake, not a lever — worst case it delays governance, never steals.
///
/// Fixes the deep-audit / autonomy-debate finding that the live deployment's
/// single immutable EOA owner is an unbounded-blast-radius single point of
/// compromise. Signers are immutable in v1 (rotation = redeploy or a governance-
/// controlled successor); execution after approval is permissionless.
contract P42MultisigTimelock {
    error NotSigner();
    error NotGuardian();
    error BadThreshold();
    error BadSigner();
    error OpExists();
    error UnknownOp();
    error NotPending();
    error AlreadyConfirmed();
    error NotReady(uint64 eta);
    error NotEnoughConfirmations(uint256 have, uint256 need);
    error CallFailed();

    enum State { None, Pending, Executed, Cancelled }

    struct Op {
        uint64 eta;
        uint32 confirmations;
        State state;
    }

    address[] public signers;
    mapping(address => bool) public isSigner;
    uint256 public immutable threshold;
    uint256 public immutable delay;
    address public immutable guardian;

    mapping(bytes32 => Op) public ops;
    mapping(bytes32 => mapping(address => bool)) public confirmedBy;

    event Scheduled(bytes32 indexed id, address indexed target, uint256 value, bytes data, bytes32 salt, uint64 eta);
    event Confirmed(bytes32 indexed id, address indexed signer, uint32 confirmations);
    event Executed(bytes32 indexed id, address indexed target, uint256 value);
    event Cancelled(bytes32 indexed id, address indexed by);

    modifier onlySigner() {
        if (!isSigner[msg.sender]) revert NotSigner();
        _;
    }

    constructor(address[] memory signers_, uint256 threshold_, uint256 delaySeconds_, address guardian_) {
        if (threshold_ == 0 || threshold_ > signers_.length) revert BadThreshold();
        for (uint256 i; i < signers_.length; i++) {
            address s = signers_[i];
            if (s == address(0) || isSigner[s]) revert BadSigner();
            isSigner[s] = true;
            signers.push(s);
        }
        threshold = threshold_;
        delay = delaySeconds_;
        guardian = guardian_;
    }

    receive() external payable {}

    function signerCount() external view returns (uint256) {
        return signers.length;
    }

    function opId(address target, uint256 value, bytes calldata data, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(target, value, data, salt));
    }

    /// @notice A signer schedules a privileged call; the timelock starts and the
    /// proposer's confirmation counts as the first.
    function schedule(address target, uint256 value, bytes calldata data, bytes32 salt)
        external
        onlySigner
        returns (bytes32 id)
    {
        id = opId(target, value, data, salt);
        Op storage op = ops[id];
        if (op.state != State.None) revert OpExists();
        uint64 eta = uint64(block.timestamp + delay);
        op.eta = eta;
        op.confirmations = 1;
        op.state = State.Pending;
        confirmedBy[id][msg.sender] = true;
        emit Scheduled(id, target, value, data, salt, eta);
        emit Confirmed(id, msg.sender, 1);
    }

    function confirm(bytes32 id) external onlySigner {
        Op storage op = ops[id];
        if (op.state != State.Pending) revert NotPending();
        if (confirmedBy[id][msg.sender]) revert AlreadyConfirmed();
        confirmedBy[id][msg.sender] = true;
        op.confirmations += 1;
        emit Confirmed(id, msg.sender, op.confirmations);
    }

    /// @notice The guardian vetoes a pending op (emergency brake; delay-only power).
    function cancel(bytes32 id) external {
        if (msg.sender != guardian) revert NotGuardian();
        Op storage op = ops[id];
        if (op.state != State.Pending) revert NotPending();
        op.state = State.Cancelled;
        emit Cancelled(id, msg.sender);
    }

    /// @notice Permissionless once approved + past the timelock: forwards the call.
    function execute(address target, uint256 value, bytes calldata data, bytes32 salt)
        external
        returns (bytes memory)
    {
        bytes32 id = opId(target, value, data, salt);
        Op storage op = ops[id];
        if (op.state != State.Pending) revert UnknownOp();
        if (block.timestamp < op.eta) revert NotReady(op.eta);
        if (op.confirmations < threshold) revert NotEnoughConfirmations(op.confirmations, threshold);
        op.state = State.Executed;
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed();
        emit Executed(id, target, value);
        return ret;
    }
}
