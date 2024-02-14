// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockedLiquidityGauge {
    function userCheckpoint(address) external pure returns (bool) {
        return true;
    }

    function initialize(address) external pure {}
}
