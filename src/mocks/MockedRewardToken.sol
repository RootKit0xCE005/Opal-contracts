// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockedERC20} from "./MockedERC20.sol";

contract MockedRewardToken {
    MockedBaseToken public baseToken;

    constructor(address addr) {
        baseToken = new MockedBaseToken(addr);
    }

    function rewardToken() external view returns (address) {
        return address(baseToken);
    }

    function getERC20() external view returns (address) {
        return MockedBaseToken(baseToken).baseToken();
    }
}

contract MockedBaseToken {
    constructor(address addr) {
        baseTokenAddr = addr;
    }

    address public baseTokenAddr;

    function baseToken() external view returns (address) {
        return baseTokenAddr;
    }
}
