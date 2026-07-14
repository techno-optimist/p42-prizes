// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockOptimismPortal {
    address public lastTo;
    uint256 public lastValue;
    uint64 public lastGasLimit;
    bool public lastIsCreation;
    bytes public lastData;
    uint256 public lastMsgValue;
    address public lastSender;

    function depositTransaction(address to, uint256 value, uint64 gasLimit, bool isCreation, bytes calldata data)
        external
        payable
    {
        lastTo = to;
        lastValue = value;
        lastGasLimit = gasLimit;
        lastIsCreation = isCreation;
        lastData = data;
        lastMsgValue = msg.value;
        lastSender = msg.sender;
    }
}
