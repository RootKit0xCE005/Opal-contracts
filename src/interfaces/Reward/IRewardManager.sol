// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRewardManager {
    function getRewardToken(uint256 index) external view returns (address);

    function getExtraRewardToken(uint256 index) external view returns (address);

    function setExtraRewardTokens() external returns (uint256);
}
