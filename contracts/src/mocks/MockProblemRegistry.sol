// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockProblemRegistry {
    mapping(uint256 => bool) public explicitlyFrozen;
    mapping(uint256 => address) public problemPool;

    function setProblem(uint256 problemId, address pool, bool frozen) external {
        problemPool[problemId] = pool;
        explicitlyFrozen[problemId] = frozen;
    }
}
