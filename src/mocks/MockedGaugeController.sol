// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockedGaugeController {
    function getGaugeType(address) external pure returns (uint256) {
        return 1;
    }
}
