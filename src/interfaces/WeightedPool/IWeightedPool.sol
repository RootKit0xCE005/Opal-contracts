// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IWeightedPool {
    function getPoolId() external view returns (bytes32);

    function balanceOf(address token) external view returns (uint256);
}
