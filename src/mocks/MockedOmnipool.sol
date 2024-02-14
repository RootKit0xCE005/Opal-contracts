// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockedERC20} from "./MockedERC20.sol";

contract MockedOmnipool {
    struct UnderlyingPool {
        address addr;
    }

    UnderlyingPool[] public underlyingPools;
    uint256 public totalUnderlyingPools;
    MockedERC20 public gem;

    constructor(address _gem) {
        gem = MockedERC20(_gem);
    }

    function addUnderlyingPool(address addr) public {
        underlyingPools.push(UnderlyingPool(addr));
        totalUnderlyingPools++;
    }

    function getUnderlyingPoolsLength() public view returns (uint8) {
        return uint8(underlyingPools.length);
    }

    function getUnderlyingPool(uint8 index) public view returns (address) {
        return underlyingPools[index].addr;
    }

    function approveForRewardManager(address token, uint256 amount) public {
        // Transfer the rewards to the user
        MockedERC20 erc20 = MockedERC20(token);
        erc20.approve(msg.sender, amount);
    }

    function swapForGem(address _token, uint256 _amountIn) external returns (bool) {
        // Burn the extra reward tokens
        MockedERC20 erc20Token = MockedERC20(_token);
        erc20Token.burn(address(this), _amountIn);
        // Mint the GEM token
        gem.mint(address(this), _amountIn);
        return true;
    }
}
