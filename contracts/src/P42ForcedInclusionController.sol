// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42OptimismPortal {
    function depositTransaction(address to, uint256 value, uint64 gasLimit, bool isCreation, bytes calldata data)
        external
        payable;
}

interface IP42ForcedInclusionWallet {
    function setForcedCallPolicy(
        address target,
        bytes4 selector,
        bool ok,
        uint256 chainId,
        uint64 expiresAt,
        uint32 maxCalls,
        bytes32 calldataHash,
        bytes32 scopeHash
    ) external;

    function executeForcedPolicy(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory);
}

/// @notice L1 controller for a bounded OP Stack forced-deposit challenge path.
/// Its L2 alias occupies P42AgentWallet's one-time forced-inclusion role. The
/// controller cannot forward arbitrary governance calls or target anything but the
/// immutable challenge manager with the immutable challenge selector.
contract P42ForcedInclusionController {
    error NotOperator();
    error NotGuardian();
    error ZeroAddress();
    error BadChallengeCalldata();
    error BadPolicy();
    error ValueMismatch(uint256 expected, uint256 received);

    IP42OptimismPortal public immutable portal;
    address public immutable l2Wallet;
    address public immutable challengeManager;
    bytes4 public immutable challengeSelector;
    address public immutable guardian;
    address public operator;

    event OperatorSet(address indexed operator);
    event ChallengePolicyDeposited(bytes32 indexed calldataHash, bytes32 indexed scopeHash, uint64 expiresAt);
    event ChallengeDeposited(bytes32 indexed calldataHash, uint256 bondWei);

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    constructor(
        address portal_,
        address l2Wallet_,
        address challengeManager_,
        bytes4 challengeSelector_,
        address operator_,
        address guardian_
    ) {
        if (
            portal_ == address(0) || l2Wallet_ == address(0) || challengeManager_ == address(0)
                || challengeSelector_ == bytes4(0) || operator_ == address(0) || guardian_ == address(0)
        ) revert ZeroAddress();
        portal = IP42OptimismPortal(portal_);
        l2Wallet = l2Wallet_;
        challengeManager = challengeManager_;
        challengeSelector = challengeSelector_;
        operator = operator_;
        guardian = guardian_;
        emit OperatorSet(operator_);
    }

    function setOperator(address nextOperator) external {
        if (msg.sender != guardian) revert NotGuardian();
        if (nextOperator == address(0)) revert ZeroAddress();
        operator = nextOperator;
        emit OperatorSet(nextOperator);
    }

    function depositChallengePolicy(
        bytes calldata challengeCalldata,
        uint256 l2ChainId,
        uint64 expiresAt,
        bytes32 scopeHash,
        uint64 l2GasLimit
    ) external onlyOperator {
        _validateChallengeCalldata(challengeCalldata);
        if (l2ChainId == 0 || expiresAt == 0 || scopeHash == bytes32(0) || l2GasLimit == 0) {
            revert BadPolicy();
        }
        bytes32 calldataHash = keccak256(challengeCalldata);
        bytes memory walletCalldata = abi.encodeCall(
            IP42ForcedInclusionWallet.setForcedCallPolicy,
            (
                challengeManager,
                challengeSelector,
                true,
                l2ChainId,
                expiresAt,
                1,
                calldataHash,
                scopeHash
            )
        );
        portal.depositTransaction(l2Wallet, 0, l2GasLimit, false, walletCalldata);
        emit ChallengePolicyDeposited(calldataHash, scopeHash, expiresAt);
    }

    function depositChallenge(bytes calldata challengeCalldata, uint256 bondWei, uint64 l2GasLimit)
        external
        payable
        onlyOperator
    {
        _validateChallengeCalldata(challengeCalldata);
        if (msg.value != bondWei) revert ValueMismatch(bondWei, msg.value);
        if (l2GasLimit == 0) revert BadPolicy();
        bytes memory walletCalldata = abi.encodeCall(
            IP42ForcedInclusionWallet.executeForcedPolicy,
            (challengeManager, bondWei, challengeCalldata)
        );
        portal.depositTransaction{value: bondWei}(l2Wallet, bondWei, l2GasLimit, false, walletCalldata);
        emit ChallengeDeposited(keccak256(challengeCalldata), bondWei);
    }

    function _validateChallengeCalldata(bytes calldata challengeCalldata) private view {
        if (challengeCalldata.length < 4 || bytes4(challengeCalldata[:4]) != challengeSelector) {
            revert BadChallengeCalldata();
        }
    }
}
