// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILiquidityGauge {
    function initialize(address _lpToken) external;
    function integrateFraction(address account) external view returns (uint256);
    function integrateFractionBoosted(address account) external view returns (uint256);
    function userCheckpoint(address account) external returns (bool);
}
