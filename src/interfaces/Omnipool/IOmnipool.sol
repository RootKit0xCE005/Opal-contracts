// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "src/interfaces/Balancer/IBalancerPool.sol";
import "src/interfaces/Omnipool/IOmnipoolController.sol";
import "src/interfaces/Balancer/IBalancerVault.sol";
import {PoolType} from "src/pools/BPTOracle.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

interface IOmnipool {
    // --------------------------- STRUCTS ---------------------------
    struct UnderlyingPool {
        address poolAddress; // aura pool address
        bytes32 poolId; // balancer pool id
        IAsset[] assets; // list of input tokens of the pool
        uint256 targetWeight; // target pool weight
        PoolType poolType;
        uint8 assetIndex;
        uint8 bptIndex;
    }

    function changeUnderlyingPool(
        uint8 id,
        address _poolAddress,
        bytes32 _poolId,
        uint8 _assetIndex,
        uint8 _bptIndex,
        uint256 _weight,
        PoolType _poolType
    ) external;

    struct PoolWithAmount {
        address poolAddress;
        uint256 amount;
    }

    struct PoolWeight {
        address poolAddress;
        uint256 weight;
    }

    //TODO: calculate boosted APR depending of rebalancing
    function deposit(uint256 _amountIn, uint256 _minLpReceived) external;

    function withdraw(uint256 _amountOut, uint256 _minUnderlyingReceived) external;

    function desactivate() external;

    function updateWeights(IOmnipoolController.WeightUpdate[] calldata poolWeights) external;

    function updateWeight(address poolAddress, uint256 newWeight) external;

    /* PUBLIC VIEW */

    function getTotalDeposited() external view returns (uint256);

    function getUserTotalDeposit(address user) external view returns (uint256);

    function getUnderlyingBalance(uint8 poolId, uint256 _amount, uint256 _underlyingPrice)
        external
        view
        returns (uint256);

    function approveForRewardManager(address token, uint256 amount) external;

    function swapForGem(address _token, uint256 _amountIn) external returns (bool);

    function getUnderlyingPool(uint8 index) external view returns (address);

    function setGemPoolId(bytes32 _poolId) external;

    function setExtraRewardPool(address _token, bytes32 _poolId) external;

    function getPoolByAddress(address pool) external view returns (UnderlyingPool memory);

    function getUnderlyingToken() external view returns (IERC20Metadata);

    function getTotalUnderlying() external view returns (uint256);

    function getTotalDeviationAfterUpdate() external view returns (uint256);

    function getUnderlyingPoolsLength() external view returns (uint8);

    function getLpToken() external view returns (IERC20Metadata);

    function totalUnderlying() external view returns (uint256);
}
