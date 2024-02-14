// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/interfaces/IERC20Metadata.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IBaseRewardPool} from "src/interfaces/Reward/IBaseRewardPool.sol";
import {IOmnipoolController} from "src/interfaces/Omnipool/IOmnipoolController.sol";
import {IOmnipool} from "src/interfaces/Omnipool/IOmnipool.sol";
import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";
import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";
import {IPriceFeed} from "src/interfaces/IPriceFeed.sol";
import {IRebalancingRewardsHandler} from "src/interfaces/Tokenomics/IRebalancingRewardsHandler.sol";

import {ScaledMath} from "src/utils/ScaledMath.sol";

import {
    CONTRACT_GEM_TOKEN,
    CONTRACT_REGISTRY_ACCESS,
    CONTRACT_PRICE_FEED_ORACLE,
    ROLE_OPAL_TEAM
} from "src/utils/constants.sol";

contract OmnipoolController is IOmnipoolController {
    using EnumerableSet for EnumerableSet.AddressSet;
    using ScaledMath for uint256;

    uint256 internal constant _MAX_WEIGHT_UPDATE_MIN_DELAY = 32 days;
    uint256 internal constant _MIN_WEIGHT_UPDATE_MIN_DELAY = 1 days;

    EnumerableSet.AddressSet internal _pools;
    EnumerableSet.AddressSet internal _activePools;

    address public immutable gemToken;

    IRegistryContract public registryContract;
    IRegistryAccess public registryAccess;
    IPriceFeed public oracle;

    uint256 public weightUpdateMinDelay;

    mapping(address => uint256) public lastWeightUpdate;
    mapping(address => address) public balancerPoolToOmnipool;
    mapping(address => address) public omnipoolToBalancerPool;

    /// @dev mapping from conic pool to their rebalancing reward handlers
    mapping(address => EnumerableSet.AddressSet) internal _rebalancingRewardHandlers;

    IOmnipool public omnipool;

    event OmniPoolAdded(address indexed pool);
    event OmniPoolRemoved(address indexed pool);
    event OmniPoolShutdown(address indexed pool);
    event HandlerAdded(address indexed pool, address handler);
    event HandlerRemoved(address indexed pool, address handler);
    event OracleSet(address priceOracle);
    event WeightUpdateMinDelaySet(uint256 weightUpdateMinDelay);

    error FailedToAddPool();
    error FailedToRemove();
    error AlreadyExist();
    error DelayNotElapsed();
    error DelayTooShort();
    error DelayTooLong();
    error InvalidPool();
    error NotAuthorized();

    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    constructor(address _omnipool, address _registryContract) {
        omnipool = IOmnipool(_omnipool);
        registryContract = IRegistryContract(_registryContract);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));
        gemToken = registryContract.getContract(CONTRACT_GEM_TOKEN);
        oracle = IPriceFeed(registryContract.getContract(CONTRACT_PRICE_FEED_ORACLE));
    }

    /**
     * @notice  Get the list of pools.
     * @return  address[]  .
     */
    function listPools() public view returns (address[] memory) {
        return _pools.values();
    }

    /**
     * @notice  Get the list of active pools.
     * @return  address[]  .
     */
    function listActivePools() public view returns (address[] memory) {
        return _activePools.values();
    }

    /**
     * @notice  Add a pool
     * @param   poolAddress  The address of the pool
     */
    function addOmnipool(address poolAddress) external onlyOpalTeam {
        if (!_pools.add(poolAddress)) {
            revert FailedToAddPool();
        }
        if (!_activePools.add(poolAddress)) {
            revert FailedToAddPool();
        }

        emit OmniPoolAdded(poolAddress);
    }

    /**
     * @notice  Remove a pool
     * @param   poolAddress  The address of the pool.
     */
    function removePool(address poolAddress) external onlyOpalTeam {
        if (!_pools.remove(poolAddress)) {
            revert FailedToRemove();
        }
        if (_activePools.contains(poolAddress)) {
            // shutdown the pool before removing it
            revert FailedToRemove();
        }

        emit OmniPoolRemoved(poolAddress);
    }

    function addRebalancingRewardHandler(address pool, address handler) external onlyOpalTeam {
        if (!_rebalancingRewardHandlers[pool].add(handler)) {
            revert AlreadyExist();
        }

        emit HandlerAdded(pool, handler);
    }

    function removeBalanceHandler(address pool, address handler) external onlyOpalTeam {
        if (!_rebalancingRewardHandlers[pool].remove(handler)) {
            revert FailedToRemove();
        }

        emit HandlerRemoved(pool, handler);
    }

    /**
     * @notice  Add mapping value
     * @param   omnipool_  address of the omnipool.
     * @param   balancerPool  address of the balancer pool.
     */
    function addPoolToOmnipool(address balancerPool, address omnipool_) external onlyOpalTeam {
        if (balancerPoolToOmnipool[omnipool_] != address(0)) {
            revert AlreadyExist();
        }
        balancerPoolToOmnipool[balancerPool] = omnipool_;
        omnipoolToBalancerPool[omnipool_] = balancerPool;
    }

    /**
     * @notice  Desactivate a pool
     * @dev     .
     * @param   poolAddress  The address of the pool.
     */
    function desactivatePool(address poolAddress) external onlyOpalTeam {
        if (!_activePools.remove(poolAddress)) {
            revert FailedToRemove();
        }
        IOmnipool(poolAddress).desactivate();
    }

    /**
     * @notice  Check if a pool is registered.
     * @param   poolAddress  The address of the pool.
     * @return  bool  True if the pool is registered, false otherwise.
     */
    function isPool(address poolAddress) public view returns (bool) {
        return _pools.contains(poolAddress);
    }

    /**
     * @notice  Check if a pool is active.
     * @param   poolAddress  The address of the pool.
     * @return  bool  True if the pool is active, false otherwise.
     */
    function isActivePool(address poolAddress) public view returns (bool) {
        return _activePools.contains(poolAddress);
    }

    /**
     * @notice  Update the weights of a pool.
     * @dev     The delay between two weight updates must be at least `weightUpdateMinDelay`.
     * @param   omniPool The address of the pool.
     * @param   weights The new weight.
     */
    function updateWeights(address omniPool, IOmnipoolController.WeightUpdate[] memory weights)
        public
        onlyOpalTeam
    {
        uint256 length = weights.length;
        for (uint256 i; i < length;) {
            IOmnipool(omniPool).updateWeights(weights);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice  Update the weights of a list of pools.
     * @param   weights  The list of weights.
     */
    function updateAllWeights(IOmnipoolController.WeightUpdate[] calldata weights)
        external
        onlyOpalTeam
    {
        uint256 length = weights.length;
        for (uint256 i; i < length;) {
            updateWeights(address(omnipool), weights);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice  Set the minimum delay between two weight updates.
     * @dev     The delay must be between 1 day and 32 days.
     * @param   delay  The new minimum delay.
     */
    function setWeightUpdateMinDelay(uint256 delay) external onlyOpalTeam {
        if (delay > _MAX_WEIGHT_UPDATE_MIN_DELAY) {
            revert DelayTooLong();
        }

        if (delay < _MIN_WEIGHT_UPDATE_MIN_DELAY) {
            revert DelayTooShort();
        }
        weightUpdateMinDelay = delay;
        emit WeightUpdateMinDelaySet(delay);
    }

    function handleRebalancingRewards(
        address account,
        uint256 deviationBefore,
        uint256 deviationAfter
    ) external {
        if (!isPool(msg.sender)) {
            revert NotAuthorized();
        }
        uint256 length = _rebalancingRewardHandlers[msg.sender].length();
        for (uint256 i; i < length;) {
            address handler = _rebalancingRewardHandlers[msg.sender].at(i);
            IRebalancingRewardsHandler(handler).handleRebalancingRewards(
                IOmnipool(msg.sender), account, deviationBefore, deviationAfter
            );
            unchecked {
                ++i;
            }
        }
    }

    /// @notice returns the weights of the Opal pools to know how much inflation
    /// each of them will receive. totalUSDValue only accounts for funds in active pools
    function computePoolWeights()
        public
        view
        returns (address[] memory pools, uint256[] memory poolWeights, uint256 totalUSDValue)
    {
        pools = listPools();
        uint256[] memory poolUSDValues = new uint256[](pools.length);
        for (uint256 i; i < pools.length; i++) {
            if (isActivePool(pools[i])) {
                IOmnipool pool = IOmnipool(pools[i]);
                IERC20Metadata underlying = pool.getUnderlyingToken();
                uint256 price = oracle.getUSDPrice(address(underlying));
                uint256 poolUSDValue =
                    pool.getTotalUnderlying().convertScale(underlying.decimals(), 18).mulDown(price);
                poolUSDValues[i] = poolUSDValue;
                totalUSDValue += poolUSDValue;
            }
        }

        poolWeights = new uint256[](pools.length);

        if (totalUSDValue == 0) {
            for (uint256 i; i < pools.length; i++) {
                poolWeights[i] = ScaledMath.ONE / pools.length;
            }
        } else {
            for (uint256 i; i < pools.length; i++) {
                poolWeights[i] = poolUSDValues[i].divDown(totalUSDValue);
            }
        }
    }

    /// @notice Same as `computePoolWeights` but only returns the value for a single pool
    /// totalUSDValue only accounts for funds in active pools
    function computePoolWeight(address pool)
        public
        view
        returns (uint256 poolWeight, uint256 totalUSDValue)
    {
        if (!isPool(pool)) {
            revert InvalidPool();
        }
        address[] memory pools = listPools();
        uint256 poolUSDValue;
        for (uint256 i; i < pools.length; i++) {
            if (isActivePool(pools[i])) {
                IOmnipool currentPool = IOmnipool(pools[i]);
                IERC20Metadata underlying = currentPool.getUnderlyingToken();
                uint256 price = oracle.getUSDPrice(address(underlying));
                uint256 usdValue = currentPool.getTotalUnderlying().convertScale(
                    underlying.decimals(), 18
                ).mulDown(price);
                totalUSDValue += usdValue;
                if (address(currentPool) == pool) poolUSDValue = usdValue;
            }
        }

        if (!isActivePool(pool)) {
            return (0, totalUSDValue);
        }
        poolWeight =
            totalUSDValue == 0 ? ScaledMath.ONE / pools.length : poolUSDValue.divDown(totalUSDValue);
    }

    function getLastWeightUpdate(address pool) external view returns (uint256) {
        return lastWeightUpdate[pool];
    }
}
