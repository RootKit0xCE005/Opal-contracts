// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.20;

import "src/interfaces/Omnipool/IOmnipool.sol";
import "src/interfaces/Omnipool/IOmnipoolController.sol";
import "src/interfaces/Tokenomics/IRebalancingRewardsHandler.sol";

interface IGemMintingRebalancingRewardsHandler is IRebalancingRewardsHandler {
    event SetGemRebalancingRewardPerDollarPerSecond(uint256 gemRebalancingRewardPerDollarPerSecond);
    event SetMaxRebalancingRewardDollarMultiplier(uint256 maxRebalancingRewardDollarMultiplier);
    event SetMinRebalancingRewardDollarMultiplier(uint256 minRebalancingRewardDollarMultiplier);

    function controller() external view returns (IOmnipoolController);

    function totalGemMinted() external view returns (uint256);

    function gemRebalancingRewardPerDollarPerSecond() external view returns (uint256);

    function maxRebalancingRewardDollarMultiplier() external view returns (uint256);

    function minRebalancingRewardDollarMultiplier() external view returns (uint256);

    function setGemRebalancingRewardPerDollarPerSecond(
        uint256 _gemRebalancingRewardPerDollarPerSecond
    ) external;

    function setMaxRebalancingRewardDollarMultiplier(uint256 _maxRebalancingRewardDollarMultiplier)
        external;

    function setMinRebalancingRewardDollarMultiplier(uint256 _minRebalancingRewardDollarMultiplier)
        external;

    function poolGemRebalancingRewardPerSecond(address pool) external view returns (uint256);

    function computeRebalancingRewards(
        address conicPool,
        uint256 deviationBefore,
        uint256 deviationAfter
    ) external view returns (uint256);
}
