// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Red-team harness (risk 12: reentrancy). A malicious ETH recipient that,
/// on receiving value from any P42 ETH-outflow path, re-enters a preconfigured
/// target/selector. It is deliberately generic:
///   * `exec` lets the test drive arbitrary calls *as this contract* (so the mock
///     can be the solver/challenger/claimant of record for commit/reveal/finalize/
///     challenge/claimBond, satisfying msg.sender==attacker gates), and
///   * `receive` fires a single re-entrant call while the outer transfer is still
///     in flight, recording whether it succeeded rather than bubbling the revert,
///     so the *outer* honest payout is allowed to complete. This isolates the
///     question "could the attacker double-withdraw?" from "did the payout revert?".
/// The mock never itself reverts inside `receive`, so a contract that (a) relies
/// only on a nonReentrant guard or (b) relies only on CEI both surface as
/// `reentrySucceeded == false` with no extra ETH extracted.
contract ReentrantClaimer {
    address public reenterTarget;
    bytes public reenterData;
    bool public armed;

    // Observations recorded across the attack.
    uint256 public reentryCallCount;
    bool public reentrySucceeded;
    bytes public lastReentryReturn;
    uint256 public totalReceivedWei;

    event Reentered(address target, bool success, uint256 returnLen);

    /// @notice Arm a one-shot re-entrant call to `target` with calldata `data`.
    function arm(address target, bytes calldata data) external {
        reenterTarget = target;
        reenterData = data;
        armed = true;
    }

    function disarm() external {
        armed = false;
    }

    /// @notice Forward an arbitrary call originating from this contract, so the
    /// test can make the mock the msg.sender of commit/reveal/finalize/challenge.
    /// Reverts (bubbling the reason) if the forwarded call fails.
    function exec(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return ret;
    }

    receive() external payable {
        totalReceivedWei += msg.value;
        if (!armed) return;
        armed = false; // one-shot: never loop indefinitely
        reentryCallCount += 1;
        (bool ok, bytes memory ret) = reenterTarget.call(reenterData);
        reentrySucceeded = ok;
        lastReentryReturn = ret;
        emit Reentered(reenterTarget, ok, ret.length);
    }
}
