// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "src/interfaces/Omnipool/IOmnipool.sol";

interface IOmnipoolController {
    struct WeightUpdate {
        address poolAddress;
        uint256 newWeight;
    }

    function handleRebalancingRewards(
        address account,
        uint256 deviationBefore,
        uint256 deviationAfter
    ) external;

    function computePoolWeights()
        external
        view
        returns (address[] memory pools, uint256[] memory poolWeights, uint256 totalUSDValue);

    function computePoolWeight(address pool)
        external
        view
        returns (uint256 poolWeight, uint256 totalUSDValue);

    function getLastWeightUpdate(address pool) external view returns (uint256);

    function isPool(address poolAddress) external view returns (bool);
}
