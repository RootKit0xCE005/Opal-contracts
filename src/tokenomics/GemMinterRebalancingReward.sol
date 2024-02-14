// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "src/interfaces/Tokenomics/IGemMinterRebalancingReward.sol";
import "src/interfaces/Omnipool/IOmnipool.sol";
import "src/interfaces/Omnipool/IOmnipoolController.sol";
import "src/interfaces/Registry/IRegistryAccess.sol";
import "src/interfaces/Registry/IRegistryContract.sol";
import "src/utils/ScaledMath.sol";
import "src/utils/RegistryContract.sol";
import "src/utils/RegistryAccess.sol";

import {
    ROLE_OPAL_TEAM,
    ROLE_OMNIPOOL_CONTROLLER,
    CONTRACT_REGISTRY_ACCESS,
    CONTRACT_OMNIPOOL_CONTROLLER,
    CONTRACT_GEM_TOKEN,
    CONTRACT_INCENTIVES_MS
} from "src/utils/constants.sol";

contract GemMinterRebalancingReward is IGemMintingRebalancingRewardsHandler {
    using SafeERC20 for IERC20;
    using ScaledMath for uint256;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev the maximum amount of gem that can be minted for rebalancing rewards
    uint256 internal constant _MAX_REBALANCING_REWARDS = 1_900_000e18; // 19% of total supply

    /// @dev gives out 1 dollar per 1 hour (assuming 1 gem = 10 USD) for every 10,000 USD of TVL
    uint256 internal constant _INITIAL_REBALANCING_REWARD_PER_DOLLAR_PER_SECOND =
        1e18 / uint256(3600 * 1 * 10_000 * 10);

    /// @dev to avoid gem rewards being too low, the TVL is assumed to be at least 10k
    /// when computing the rebalancing rewards
    uint256 internal constant _INITIAL_MIN_REBALANCING_REWARD_DOLLAR_MULTIPLIER = 10_000e18;

    /// @dev to avoid gem rewards being too high, the TVL is assumed to be at most 10m
    /// when computing the rebalancing rewards
    uint256 internal constant _INITIAL_MAX_REBALANCING_REWARD_DOLLAR_MULTIPLIER = 10_000_000e18;

    IRegistryContract public registryContract;
    IRegistryAccess public registryAccess;
    IOmnipoolController public immutable controller;
    IERC20 public immutable gem;

    address public immutable incentivesMs;

    uint256 public override totalGemMinted;
    uint256 public override gemRebalancingRewardPerDollarPerSecond;
    uint256 public override maxRebalancingRewardDollarMultiplier;
    uint256 public override minRebalancingRewardDollarMultiplier;

    error NotAuthorized();

    modifier onlyOmnipoolController() {
        if (!registryAccess.checkRole(ROLE_OMNIPOOL_CONTROLLER, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) revert NotAuthorized();
        _;
    }

    constructor(address registryContract_) {
        registryContract = IRegistryContract(registryContract_);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));
        incentivesMs = registryContract.getContract(CONTRACT_INCENTIVES_MS);
        gemRebalancingRewardPerDollarPerSecond = _INITIAL_REBALANCING_REWARD_PER_DOLLAR_PER_SECOND;
        minRebalancingRewardDollarMultiplier = _INITIAL_MIN_REBALANCING_REWARD_DOLLAR_MULTIPLIER;
        maxRebalancingRewardDollarMultiplier = _INITIAL_MAX_REBALANCING_REWARD_DOLLAR_MULTIPLIER;
        controller = IOmnipoolController(registryContract.getContract(CONTRACT_OMNIPOOL_CONTROLLER));
        gem = IERC20(registryContract.getContract(CONTRACT_GEM_TOKEN));
    }

    function setGemRebalancingRewardPerDollarPerSecond(
        uint256 _gemRebalancingRewardPerDollarPerSecond
    ) external override onlyOpalTeam {
        gemRebalancingRewardPerDollarPerSecond = _gemRebalancingRewardPerDollarPerSecond;
        emit SetGemRebalancingRewardPerDollarPerSecond(_gemRebalancingRewardPerDollarPerSecond);
    }

    function setMaxRebalancingRewardDollarMultiplier(uint256 _maxRebalancingRewardDollarMultiplier)
        external
        override
        onlyOpalTeam
    {
        maxRebalancingRewardDollarMultiplier = _maxRebalancingRewardDollarMultiplier;
        emit SetMaxRebalancingRewardDollarMultiplier(_maxRebalancingRewardDollarMultiplier);
    }

    function setMinRebalancingRewardDollarMultiplier(uint256 _minRebalancingRewardDollarMultiplier)
        external
        override
        onlyOpalTeam
    {
        minRebalancingRewardDollarMultiplier = _minRebalancingRewardDollarMultiplier;
        emit SetMinRebalancingRewardDollarMultiplier(_minRebalancingRewardDollarMultiplier);
    }

    function _distributeRebalancingRewards(address pool, address account, uint256 amount)
        internal
        returns (uint256)
    {
        if (totalGemMinted + amount > _MAX_REBALANCING_REWARDS) {
            amount = _MAX_REBALANCING_REWARDS - totalGemMinted;
        }
        if (amount == 0) return 0;
        IERC20(gem).safeTransferFrom(incentivesMs, account, amount);
        totalGemMinted += amount;
        emit RebalancingRewardDistributed(pool, account, address(gem), amount);
        return amount;
    }

    function poolGemRebalancingRewardPerSecond(address pool)
        public
        view
        override
        returns (uint256)
    {
        (uint256 poolWeight, uint256 totalUSDValue) = controller.computePoolWeight(pool);
        uint256 tvlMultiplier = totalUSDValue;
        if (tvlMultiplier < minRebalancingRewardDollarMultiplier) {
            tvlMultiplier = minRebalancingRewardDollarMultiplier;
        }
        if (tvlMultiplier > maxRebalancingRewardDollarMultiplier) {
            tvlMultiplier = maxRebalancingRewardDollarMultiplier;
        }
        return gemRebalancingRewardPerDollarPerSecond.mulDown(poolWeight).mulDown(tvlMultiplier);
    }

    function handleRebalancingRewards(
        IOmnipool omnipool,
        address account,
        uint256 deviationBefore,
        uint256 deviationAfter
    ) external onlyOmnipoolController returns (uint256) {
        uint256 gemRewardAmount =
            computeRebalancingRewards(address(omnipool), deviationBefore, deviationAfter);
        return _distributeRebalancingRewards(address(omnipool), account, gemRewardAmount);
    }

    /**
     * @notice Computes the amount of gem a user should get when depositing.
     * @param omnipool address of the pool.
     * @param deviationBefore The deviation difference caused by this deposit.
     * @param deviationAfter The deviation after updating weights.
     * @dev Formula: amount gem = t * gem/s * (1 - (Δdeviation / initialDeviation))
     * where
     * - gem/s: the amount of gem per second to be distributed for rebalancing
     * - t: the time elapsed since the weight update
     * - Δdeviation: the deviation difference caused by this deposit
     * - initialDeviation: the deviation after updating weights
     * @return rewardAmount The amount of gem to give to the user as a reward.
     */
    function computeRebalancingRewards(
        address omnipool,
        uint256 deviationBefore,
        uint256 deviationAfter
    ) public view override returns (uint256) {
        if (deviationBefore < deviationAfter) return 0;
        uint256 gemPerSecond = poolGemRebalancingRewardPerSecond(omnipool);
        uint256 deviationDelta = deviationBefore - deviationAfter;
        uint256 deviationImprovementRatio =
            deviationDelta.divDown(IOmnipool(omnipool).getTotalDeviationAfterUpdate());
        uint256 lastWeightUpdate = controller.getLastWeightUpdate(omnipool);
        uint256 elapsedSinceUpdate = uint256(block.timestamp) - lastWeightUpdate;
        return (elapsedSinceUpdate * gemPerSecond).mulDown(deviationImprovementRatio);
    }
}
