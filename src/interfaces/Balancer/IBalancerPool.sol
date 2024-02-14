// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

interface IBalancerPool {
    function decimals() external view returns (uint256);
    function getPoolId() external view returns (bytes32);

    function getInvariant() external view returns (uint256 invariant_);

    function getNormalizedWeights() external view returns (uint256[] memory);

    function getSwapEnabled() external view returns (bool);

    function getOwner() external view returns (address);

    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function getBptIndex() external view returns (uint256);

    function withdrawAndUnwrap(uint256 amount, bool claim) external returns (bool);
}
