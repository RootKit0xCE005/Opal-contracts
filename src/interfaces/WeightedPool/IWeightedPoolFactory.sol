// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IWeightedPoolFactory {
    function create(
        string memory name,
        string memory symbol,
        IERC20[] memory tokens,
        uint256[] memory normalizedWeights,
        IRateProvider[] memory rateProviders,
        uint256 swapFeePercentage,
        address owner,
        bytes32 salt
    ) external returns (address);
}

interface IRateProvider {}
