// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Bounded session-key wallet for autonomous P42 operations.
/// Every session is chain-bound, expiring and revocable. Calls with arguments
/// require an exact calldata policy, which binds problem/submission/commitment
/// scope without teaching this wallet every downstream ABI.
contract P42AgentWallet {
    error NotOwner();
    error NotSession();
    error KeyRevoked();
    error SessionExpired(uint64 expiresAt, uint64 nowAt);
    error WrongChain(uint256 expected, uint256 actual);
    error CallNotAllowed(address target, bytes4 selector);
    error ExactCalldataPolicyRequired(address target, bytes4 selector);
    error CallPolicyExpired(uint64 expiresAt, uint64 nowAt);
    error CallPolicyExhausted(uint32 maxCalls);
    error CalldataHashMismatch(bytes32 expected, bytes32 actual);
    error BadSessionPolicy();
    error BadCallPolicy();
    error ValueCapExceeded(uint256 value, uint256 cap);
    error SpendCapExceeded(uint256 wouldSpend, uint256 cap);
    error CallFailed();
    error Reentrancy();

    uint64 public constant MAX_SESSION_LIFETIME = 30 days;

    struct CallPolicy {
        bool configured;
        uint64 expiresAt;
        uint32 maxCalls;
        uint32 calls;
        uint256 chainId;
        bytes32 calldataHash;
        bytes32 scopeHash;
    }

    address public immutable owner;
    address public sessionKey;
    uint256 public sessionChainId;
    uint64 public sessionExpiresAt;
    bool public revoked;
    uint256 public perCallValueCapWei;
    uint256 public totalSpendCapWei;
    uint256 public spentWei;
    bool private _entered;

    mapping(address => mapping(bytes4 => bool)) public allowed;
    mapping(address => mapping(bytes4 => CallPolicy)) public callPolicies;

    event SessionKeySet(address indexed sessionKey);
    event SessionPolicySet(address indexed sessionKey, uint256 indexed chainId, uint64 expiresAt);
    event SessionRevoked();
    event AllowedSet(address indexed target, bytes4 indexed selector, bool ok);
    event CallPolicySet(
        address indexed target,
        bytes4 indexed selector,
        bool allowed,
        uint256 chainId,
        uint64 expiresAt,
        uint32 maxCalls,
        bytes32 calldataHash,
        bytes32 scopeHash
    );
    event CapsSet(uint256 perCallValueCapWei, uint256 totalSpendCapWei);
    event Executed(address indexed target, uint256 value, bytes4 indexed selector, bytes32 calldataHash);
    event Funded(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (_entered) revert Reentrancy();
        _entered = true;
        _;
        _entered = false;
    }

    constructor(
        address owner_,
        address sessionKey_,
        uint256 perCallValueCapWei_,
        uint256 totalSpendCapWei_
    ) payable {
        require(owner_ != address(0), "P42_OWNER_ZERO");
        require(sessionKey_ != address(0), "P42_SESSION_ZERO");
        owner = owner_;
        sessionKey = sessionKey_;
        sessionChainId = block.chainid;
        sessionExpiresAt = uint64(block.timestamp) + MAX_SESSION_LIFETIME;
        perCallValueCapWei = perCallValueCapWei_;
        totalSpendCapWei = totalSpendCapWei_;
        emit SessionKeySet(sessionKey_);
        emit SessionPolicySet(sessionKey_, block.chainid, sessionExpiresAt);
        emit CapsSet(perCallValueCapWei_, totalSpendCapWei_);
        if (msg.value > 0) emit Funded(msg.sender, msg.value);
    }

    receive() external payable {
        emit Funded(msg.sender, msg.value);
    }

    function setSessionKey(address key) external onlyOwner {
        _setSessionPolicy(key, block.chainid, uint64(block.timestamp) + MAX_SESSION_LIFETIME);
    }

    function setSessionPolicy(address key, uint256 chainId, uint64 expiresAt) external onlyOwner {
        _setSessionPolicy(key, chainId, expiresAt);
    }

    function revoke() external onlyOwner {
        revoked = true;
        emit SessionRevoked();
    }

    function setCaps(uint256 perCall, uint256 total) external onlyOwner {
        perCallValueCapWei = perCall;
        totalSpendCapWei = total;
        emit CapsSet(perCall, total);
    }

    /// @notice Compatibility helper for selector-only no-argument calls. A
    /// selector-zero allowance can authorize a bare empty-calldata transfer,
    /// but never fallback calldata. A nonzero selector-only call remains
    /// compatible; calls carrying arguments require `setCallPolicy` with an
    /// exact calldata hash before the session key can execute them.
    function setAllowed(address target, bytes4 selector, bool ok) external onlyOwner {
        require(target != address(0), "P42_TARGET_ZERO");
        allowed[target][selector] = ok;
        delete callPolicies[target][selector];
        emit AllowedSet(target, selector, ok);
    }

    function setCallPolicy(
        address target,
        bytes4 selector,
        bool ok,
        uint256 chainId,
        uint64 expiresAt,
        uint32 maxCalls,
        bytes32 calldataHash,
        bytes32 scopeHash
    ) external onlyOwner {
        if (
            target == address(0) || selector == bytes4(0) || chainId != block.chainid
                || expiresAt <= block.timestamp || maxCalls == 0 || calldataHash == bytes32(0)
                || scopeHash == bytes32(0)
        ) revert BadCallPolicy();
        allowed[target][selector] = ok;
        callPolicies[target][selector] = CallPolicy({
            configured: true,
            expiresAt: expiresAt,
            maxCalls: maxCalls,
            calls: 0,
            chainId: chainId,
            calldataHash: calldataHash,
            scopeHash: scopeHash
        });
        emit AllowedSet(target, selector, ok);
        emit CallPolicySet(target, selector, ok, chainId, expiresAt, maxCalls, calldataHash, scopeHash);
    }

    function withdraw(address payable to, uint256 amount) external onlyOwner nonReentrant {
        require(to != address(0), "P42_WITHDRAW_ZERO");
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert CallFailed();
        emit Withdrawn(to, amount);
    }

    function execute(address target, uint256 value, bytes calldata data)
        external
        nonReentrant
        returns (bytes memory)
    {
        if (msg.sender != sessionKey) revert NotSession();
        if (revoked) revert KeyRevoked();
        if (block.chainid != sessionChainId) revert WrongChain(sessionChainId, block.chainid);
        if (block.timestamp > sessionExpiresAt) {
            revert SessionExpired(sessionExpiresAt, uint64(block.timestamp));
        }

        bytes4 selector = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        if (!allowed[target][selector]) revert CallNotAllowed(target, selector);
        bytes32 dataHash = keccak256(data);
        CallPolicy storage policy = callPolicies[target][selector];
        if (policy.configured) {
            if (policy.chainId != block.chainid) revert WrongChain(policy.chainId, block.chainid);
            if (block.timestamp > policy.expiresAt) {
                revert CallPolicyExpired(policy.expiresAt, uint64(block.timestamp));
            }
            if (policy.calls >= policy.maxCalls) revert CallPolicyExhausted(policy.maxCalls);
            if (dataHash != policy.calldataHash) revert CalldataHashMismatch(policy.calldataHash, dataHash);
            policy.calls += 1;
        } else if (selector == bytes4(0) ? data.length != 0 : data.length != 4) {
            revert ExactCalldataPolicyRequired(target, selector);
        }

        if (value > perCallValueCapWei) revert ValueCapExceeded(value, perCallValueCapWei);
        uint256 wouldSpend = spentWei + value;
        if (wouldSpend > totalSpendCapWei) revert SpendCapExceeded(wouldSpend, totalSpendCapWei);
        spentWei = wouldSpend;
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed();
        emit Executed(target, value, selector, dataHash);
        return ret;
    }

    function _setSessionPolicy(address key, uint256 chainId, uint64 expiresAt) private {
        uint256 maxExpiresAt = block.timestamp + MAX_SESSION_LIFETIME;
        if (
            key == address(0) || chainId != block.chainid || expiresAt <= block.timestamp
                || expiresAt > maxExpiresAt
        ) {
            revert BadSessionPolicy();
        }
        sessionKey = key;
        sessionChainId = chainId;
        sessionExpiresAt = expiresAt;
        revoked = false;
        spentWei = 0;
        emit SessionKeySet(key);
        emit SessionPolicySet(key, chainId, expiresAt);
    }
}
