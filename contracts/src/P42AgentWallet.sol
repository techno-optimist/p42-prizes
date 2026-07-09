// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice A scoped session-key wallet for an autonomous P42 agent — the on-chain
/// enforcement of `docs/CHALLENGE_KEY_POLICY.md` / `docs/WALLET_SESSION_POLICY.md`.
///
/// The agent's operating budget lives in this wallet (the balance is the hard
/// max-loss backstop). A governance `owner` (a human/multisig, held cold) can
/// revoke the session key and withdraw at any time. The `sessionKey` (the agent's
/// hot operating key) can ONLY forward calls to an allowlist of (target, selector)
/// pairs — the P42 lifecycle functions — bounded by a per-call ETH value cap and a
/// cumulative spend cap. So a leaked or buggy session key cannot drain the wallet,
/// send funds to an arbitrary address, or call anything outside the P42 flow;
/// worst case it burns up to the caps on the P42 contracts, and the owner revokes.
///
/// This is NOT ERC-4337 (no EntryPoint / bundler / gas abstraction) — it is the
/// minimal contract that delivers the bounded-blast-radius safety property.
/// Migrating to a 4337 smart account + session-key module is a Phase-2 refinement.
contract P42AgentWallet {
    error NotOwner();
    error NotSession();
    error KeyRevoked();
    error CallNotAllowed(address target, bytes4 selector);
    error ValueCapExceeded(uint256 value, uint256 cap);
    error SpendCapExceeded(uint256 wouldSpend, uint256 cap);
    error CallFailed();
    error Reentrancy();

    address public immutable owner;     // governance / revoker (cold)
    address public sessionKey;          // agent operating key (hot, scoped)
    bool public revoked;
    uint256 public perCallValueCapWei;  // max ETH value per forwarded call
    uint256 public totalSpendCapWei;    // cumulative ETH the session key may spend
    uint256 public spentWei;
    bool private _entered;

    // allowlist: sessionKey may call allowed[target][selector]
    mapping(address => mapping(bytes4 => bool)) public allowed;

    event SessionKeySet(address indexed sessionKey);
    event SessionRevoked();
    event AllowedSet(address indexed target, bytes4 indexed selector, bool ok);
    event CapsSet(uint256 perCallValueCapWei, uint256 totalSpendCapWei);
    event Executed(address indexed target, uint256 value, bytes4 indexed selector);
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
        owner = owner_;
        sessionKey = sessionKey_;
        perCallValueCapWei = perCallValueCapWei_;
        totalSpendCapWei = totalSpendCapWei_;
        emit SessionKeySet(sessionKey_);
        emit CapsSet(perCallValueCapWei_, totalSpendCapWei_);
        if (msg.value > 0) emit Funded(msg.sender, msg.value);
    }

    receive() external payable {
        emit Funded(msg.sender, msg.value);
    }

    // --- owner (governance) controls ---

    function setSessionKey(address key) external onlyOwner {
        sessionKey = key;
        revoked = false;
        // totalSpendCapWei is a PER-SESSION budget: rotating to a fresh key
        // starts a fresh meter, so the new key is immediately usable up to the
        // cap without a separate setCaps() call (F18). The owner still bounds
        // total exposure via the wallet balance and can revoke at any time.
        spentWei = 0;
        emit SessionKeySet(key);
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

    function setAllowed(address target, bytes4 selector, bool ok) external onlyOwner {
        allowed[target][selector] = ok;
        emit AllowedSet(target, selector, ok);
    }

    function withdraw(address payable to, uint256 amount) external onlyOwner nonReentrant {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert CallFailed();
        emit Withdrawn(to, amount);
    }

    // --- scoped session-key execution ---

    /// @notice The session key forwards a call to an allowlisted P42 function.
    /// Reverts unless (target, selector) is allowlisted and the value is within
    /// both the per-call and cumulative caps.
    function execute(address target, uint256 value, bytes calldata data)
        external
        nonReentrant
        returns (bytes memory)
    {
        if (msg.sender != sessionKey) revert NotSession();
        if (revoked) revert KeyRevoked();
        bytes4 selector = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        if (!allowed[target][selector]) revert CallNotAllowed(target, selector);
        if (value > perCallValueCapWei) revert ValueCapExceeded(value, perCallValueCapWei);
        uint256 wouldSpend = spentWei + value;
        if (wouldSpend > totalSpendCapWei) revert SpendCapExceeded(wouldSpend, totalSpendCapWei);
        spentWei = wouldSpend;
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed();
        emit Executed(target, value, selector);
        return ret;
    }
}
