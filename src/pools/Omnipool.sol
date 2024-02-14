// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

import "src/interfaces/Balancer/IBalancerVault.sol";
import {OpalLpToken} from "src/pools/OpalLpToken.sol";
import {IRewardPoolDepositWrapper} from "src/interfaces/Reward/IRewardPoolDepositWrapper.sol";
import {IBalancerPool} from "src/interfaces/Balancer/IBalancerPool.sol";
import {BPTOracle} from "src/pools/BPTOracle.sol";

import {ScaledMath} from "src/utils/ScaledMath.sol";
import {ArrayExtensions} from "src/utils/ArrayExtensions.sol";

import {IOmnipoolController} from "src/interfaces/Omnipool/IOmnipoolController.sol";

import {IPriceFeed} from "src/interfaces/IPriceFeed.sol";

import {RewardManager} from "src/RewardManager.sol";

import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";

import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";

import {IOpalLpToken} from "src/interfaces/Token/IOpalLpToken.sol";

import {IOmnipool} from "src/interfaces/Omnipool/IOmnipool.sol";

import {
    CONTRACT_BPT_ORACLE,
    CONTRACT_GEM_TOKEN,
    CONTRACT_REGISTRY_ACCESS,
    CONTRACT_OMNIPOOL_CONTROLLER,
    CONTRACT_PRICE_FEED_ORACLE,
    ROLE_OPAL_TEAM,
    ROLE_REWARD_MANAGER,
    ROLE_OMNIPOOL_CONTROLLER,
    PoolType,
    CONTRACT_OPAL_TREASURY,
    CONTRACT_WETH,
    SCALED_ONE,
    WITHDRAW_FEES
} from "src/utils/constants.sol";

contract Omnipool is IOmnipool {
    using ArrayExtensions for uint256[];
    using ScaledMath for uint256;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using SafeERC20 for IERC20;
    using SafeERC20 for IERC20Metadata;

    BPTOracle public bptOracle;
    IRewardPoolDepositWrapper public rewardPoolDepositWrapper;
    IPriceFeed public oracle;

    address public immutable GEM;
    address public immutable WETH;
    bytes32 public wethToGemPoolId;
    address public immutable opalTreasury;

    address public rewardManager;

    /// @notice Emitted when the Gem pool id is updated
    event GemPoolIdUpdated(bytes32 poolId);
    /// @notice Emitted when a new extra reward pool id is set
    event ExtraRewardPoolIdUpdated(address token, bytes32 poolId);

    /// @notice Map an X ERC20 token to a pool id that swap X for WETH
    mapping(address => bytes32) public extraRewardPools;
    IRewardPoolDepositWrapper public auraRewardPoolDepositWrapper;

    using ScaledMath for uint256;

    // --------------------------- VARIABLES ---------------------------
    IERC20Metadata public immutable underlyingToken;
    UnderlyingPool[] public underlyingPools; // slice of all balancer underlying pools
    IRegistryContract public registryContract;
    IRegistryAccess public registryAccess;

    uint256 public totalDeposited; // total amount of deposit tokens deposited
    uint256 public totalUnderlyingPools; // total number of underlying balancer pools
    uint256 internal _cacheUpdatedTimestamp;
    uint256 internal _cachedTotalUnderlying;
    uint256 public maxDeviation;
    uint256 public totalDeviationAfterWeightUpdate;
    bool public isShutdown;
    bool public desactivated;
    bool public rebalancingRewardActive;

    uint256 public _MIN_DEPEG_THRESHOLD;
    uint256 public _MAX_DEPEG_THRESHOLD;

    uint256 internal constant _MAX_USD_LP_VALUE_FOR_REMOVING_CURVE_POOL = 100e18;

    // --------------------------- IMMUTABLES --------------------------
    IBalancerVault public balancerVault;
    IOpalLpToken public immutable lpToken;
    mapping(address => address) public lpTokenPerPool;
    mapping(address => uint256) public lastTransactionBlock;
    mapping(address => uint256) public lastPriceLookup;

    uint8 public immutable decimals;

    error PoolNotFound();
    error NotAuthorized();
    error NotEnoughBalance();
    error InvalidThreshold();
    error InvalidWeight();
    error TooMuchSlippage();
    error PoolAlreadyShutdown();
    error NotSumToOne();
    error CantDepositAndWithdrawSameBlock();
    error CannotSetRewardManagerTwice();
    error NullAddress();

    event Desactivate(address omnipool);
    event DepegThresholdUpdated(uint256 newDepegThreshold_);
    event Shutdown();
    event HandledDepeggedPool(address pool_);
    event NewWeight(address pool_, uint256 weight_);

    // Modifier
    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    modifier onlyRewardManager() {
        if (!registryAccess.checkRole(ROLE_REWARD_MANAGER, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    modifier onlyController() {
        if (!registryAccess.checkRole(ROLE_OMNIPOOL_CONTROLLER, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    // --------------------------- CONSTRUCTOR ---------------------------
    constructor(
        address _underlyingToken,
        address _balancerVault,
        address _registryContract,
        address _depositWrapper,
        string memory _name,
        string memory _symbol
    ) payable {
        underlyingToken = IERC20Metadata(_underlyingToken);
        balancerVault = IBalancerVault(_balancerVault);
        decimals = underlyingToken.decimals();
        registryContract = IRegistryContract(_registryContract);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));
        bptOracle = BPTOracle(registryContract.getContract(CONTRACT_BPT_ORACLE));
        oracle = IPriceFeed(registryContract.getContract(CONTRACT_PRICE_FEED_ORACLE));
        auraRewardPoolDepositWrapper = IRewardPoolDepositWrapper(_depositWrapper);
        lpToken =
            new OpalLpToken(address(registryContract), underlyingToken.decimals(), _name, _symbol);
        WETH = registryContract.getContract(CONTRACT_WETH);
        GEM = registryContract.getContract(CONTRACT_GEM_TOKEN);
        opalTreasury = registryContract.getContract(CONTRACT_OPAL_TREASURY);

        rewardPoolDepositWrapper = IRewardPoolDepositWrapper(_depositWrapper);
    }

    // --------------------------- PUBLIC FUNCTIONS ---------------------------

    /**
     * @notice Get the Total Value Locked (TVL) of a specific pool
     * @param poolId The ID of the pool
     * @return The TVL of the pool in USD
     */
    function getPoolTvl(uint256 poolId) public view returns (uint256) {
        UnderlyingPool memory pool = underlyingPools[poolId];
        uint256 bptPrice = computeBptValution(poolId);
        uint256 bptBalance = IBalancerPool(pool.poolAddress).balanceOf(address(this));
        uint256 bptValue = bptPrice * bptBalance / 1e18;
        return bptValue;
    }

    /**
     * @notice Get the Total Value Locked (TVL) across all pools
     * @return The total TVL in USD
     */
    function getTotalTvl() public view returns (uint256) {
        uint256 totalTvl;
        uint8 len = uint8(underlyingPools.length);
        for (uint8 i = 0; i < len;) {
            totalTvl += getPoolTvl(i);
            unchecked {
                ++i;
            }
        }
        return totalTvl;
    }

    /**
     * @notice Set the address of the reward manager
     * @param _rewardManager The address of the reward manager
     */
    function setRewardManager(address _rewardManager) external onlyOpalTeam {
        if (_rewardManager == address(0)) {
            revert NullAddress();
        }
        if (rewardManager != address(0)) {
            revert CannotSetRewardManagerTwice();
        }
        rewardManager = _rewardManager;
    }

    /**
     * @notice Compute the valuation of a pool's Balancer Pool Tokens (BPT) in USD
     * @param poolId The ID of the pool
     * @return The valuation of the pool's BPT in USD
     */
    function computeBptValution(uint256 poolId) public view returns (uint256) {
        UnderlyingPool memory pool = underlyingPools[poolId];
        return bptOracle.getPoolValuation(pool.poolId, pool.poolType);
    }

    /**
     * @notice Deposit underlying tokens for a specified user
     * @param _amountIn The amount of underlying tokens to deposit
     * @param _depositFor The address of the user for whom to deposit
     * @param _minLpReceived The minimum amount of LP tokens to receive
     */
    function depositFor(uint256 _amountIn, address _depositFor, uint256 _minLpReceived) public {
        if (lastTransactionBlock[_depositFor] == block.number) {
            revert CantDepositAndWithdrawSameBlock();
        }

        if (lastTransactionBlock[_depositFor] == block.number) {
            revert CantDepositAndWithdrawSameBlock();
        }

        uint256 underlyingPrice = bptOracle.getUSDPrice(address(underlyingToken));

        underlyingToken.forceApprove(address(auraRewardPoolDepositWrapper), _amountIn);

        (
            uint256 beforeTotalUnderlying,
            uint256 beforeAllocatedBalance,
            uint256[] memory beforeAllocatedPerPool
        ) = _getTotalAndPerPoolUnderlying(underlyingPrice);

        uint256 exchangeRate = _exchangeRate(beforeTotalUnderlying);

        // Transfer underlying token to this contract
        underlyingToken.safeTransferFrom(msg.sender, address(this), _amountIn);

        _depositToAura(beforeAllocatedBalance, beforeAllocatedPerPool, _amountIn);

        (uint256 afterTotalUnderlying,, uint256[] memory afterAllocatedPerPool) =
            _getTotalAndPerPoolUnderlying(underlyingPrice);

        uint256 underlyingBalanceIncrease = afterTotalUnderlying - beforeTotalUnderlying;
        uint256 mintableUnderlyingAmount = _min(_amountIn, underlyingBalanceIncrease);
        uint256 lpReceived = mintableUnderlyingAmount.divDown(exchangeRate);
        require(lpReceived >= _minLpReceived, "too much slippage");

        lpToken.mint(_depositFor, lpReceived);

        totalDeposited += _amountIn;

        _handleRebalancingRewards(
            msg.sender,
            beforeTotalUnderlying,
            afterTotalUnderlying,
            beforeAllocatedPerPool,
            afterAllocatedPerPool
        );
        lastTransactionBlock[_depositFor] = block.number;
    }

    // --------------------------- EXTERNAL FUNCTIONS ---------------------------

    /**
     * @notice Change the underlying pool configuration
     * @param id The ID of the pool to change or create
     * @param _poolAddress The address of the Balancer Pool
     * @param _poolId The ID of the Balancer Pool
     * @param _assetIndex The index of the underlying asset
     * @param _bptIndex The index of the BPT in the pool
     * @param _weight The target weight of the pool
     * @param _poolType The type of the pool
     */
    function changeUnderlyingPool(
        uint8 id,
        address _poolAddress,
        bytes32 _poolId,
        uint8 _assetIndex,
        uint8 _bptIndex,
        uint256 _weight,
        PoolType _poolType
    ) external onlyOpalTeam {
        // create assets slice
        (address[] memory _assets,,) = balancerVault.getPoolTokens(_poolId);
        uint256 length = _assets.length;
        IAsset[] memory assets = new IAsset[](length);
        for (uint256 i = 0; i < length;) {
            assets[i] = IAsset(address(_assets[i]));
            unchecked {
                ++i;
            }
        }
        // create UnderlyingPool entity
        UnderlyingPool memory newPool = UnderlyingPool({
            poolAddress: _poolAddress,
            poolId: _poolId,
            assets: assets,
            assetIndex: _assetIndex,
            targetWeight: _weight,
            poolType: _poolType,
            bptIndex: _bptIndex
        });
        // push or insert depending on id
        if (id >= underlyingPools.length) {
            underlyingPools.push(newPool);
            ++totalUnderlyingPools;
        } else {
            underlyingPools[id] = newPool;
        }
    }

    /**
     * @notice Get the total balance of Balancer Pool Tokens for a specified pool
     * @param poolId The ID of the pool
     * @return The total balance of BPT in the pool
     */
    function getTotalBptBalance(uint8 poolId) public view returns (uint256) {
        UnderlyingPool memory pool = underlyingPools[poolId];
        return IERC20(pool.poolAddress).balanceOf(address(this));
    }

    /**
     * @notice Deposit underlying tokens for the caller
     * @param _amountIn The amount of underlying tokens to deposit
     */
    function deposit(uint256 _amountIn, uint256 _minLpReceived) external {
        depositFor(_amountIn, msg.sender, _minLpReceived);
    }

    /**
     * @notice Withdraw underlying tokens from the protocol
     * @param _amountOut The amount of LP tokens to withdraw
     * @param _minUnderlyingReceived The minimum amount of underlying tokens to receive
     */
    function withdraw(uint256 _amountOut, uint256 _minUnderlyingReceived) external override {
        if (lastTransactionBlock[msg.sender] == block.number) {
            revert CantDepositAndWithdrawSameBlock();
        }
        if (_amountOut > lpToken.balanceOf(msg.sender)) {
            revert NotEnoughBalance();
        }

        uint256 underlyingPrice = bptOracle.getUSDPrice(address(underlyingToken));
        uint256 underlyingBalanceBefore_ = underlyingToken.balanceOf(address(this));

        (uint256 totalUnderlying_, uint256 allocatedUnderlying_, uint256[] memory allocatedPerPool)
        = _getTotalAndPerPoolUnderlying(underlyingPrice);

        uint256 underlyingToReceive_ = _amountOut.mulDown(_exchangeRate(totalUnderlying_));

        if (underlyingBalanceBefore_ < underlyingToReceive_) {
            uint256 underlyingToWithdraw_ = underlyingToReceive_ - underlyingBalanceBefore_;
            _withdrawFromAura(allocatedUnderlying_, allocatedPerPool, underlyingToWithdraw_);
        }
        uint256 underlyingBalanceAfter_ = underlyingToken.balanceOf(address(this));

        uint256 underlyingWithdrawn_ = _min(underlyingBalanceAfter_, underlyingToReceive_);
        uint256 underlyingFees = underlyingWithdrawn_ * WITHDRAW_FEES / SCALED_ONE;
        underlyingWithdrawn_ -= underlyingFees;

        if (underlyingWithdrawn_ < _minUnderlyingReceived) {
            revert TooMuchSlippage();
        }
        lastTransactionBlock[msg.sender] = block.number;
        lpToken.burn(msg.sender, _amountOut);
        totalDeposited -= underlyingWithdrawn_;

        underlyingToken.safeTransfer(opalTreasury, underlyingFees);
        underlyingToken.safeTransfer(msg.sender, underlyingWithdrawn_);
    }

    /**
     * @notice Get the underlying balance for a specified pool and amount
     * @param poolId The ID of the pool
     * @param _amount The amount of tokens
     * @param _underlyingPrice The price of the underlying token
     * @return The underlying balance in the specified pool for the given amount
     */
    function getUnderlyingBalance(uint8 poolId, uint256 _amount, uint256 _underlyingPrice)
        public
        view
        override
        returns (uint256)
    {
        uint256 valuation = computeBptValution(poolId);
        return _amount.mulDown(valuation).divDown(_underlyingPrice).convertScale(
            18, underlyingToken.decimals()
        );
    }

    /**
     * @notice Get the user's deposit in a specified pool
     * @param user The address of the user
     * @param poolId The ID of the pool
     * @return The user's deposit in the specified pool
     */
    function getUserDeposit(address user, uint256 poolId) public view returns (uint256) {
        UnderlyingPool memory pool = underlyingPools[poolId];
        uint256 bptBalance = IBalancerPool(pool.poolAddress).balanceOf(user);
        uint256 valuation = computeBptValution(poolId);
        return valuation * bptBalance;
    }

    // --------------------------- INTERNAL FUNCTIONS ---------------------------

    /**
     * @notice Deposit underlying tokens into Aura Reward Pool
     * @param _pool The underlying pool information
     * @param _underlyingAmountIn The amount of underlying tokens to deposit
     */
    function _depositToAuraPool(UnderlyingPool memory _pool, uint256 _underlyingAmountIn)
        internal
    {
        uint256[] memory amountsIn = new uint256[](_pool.assets.length);

        // create join request
        uint256[] memory userDataAmountsIn = amountsIn;
        amountsIn[_pool.assetIndex] = _underlyingAmountIn;

        // if the assets include bpt, we must remove it from the amountsIn in the userData
        if (_pool.bptIndex > 0) {
            userDataAmountsIn = new uint256[](_pool.assets.length - 1);
            userDataAmountsIn[_pool.assetIndex - 1] = _underlyingAmountIn;
        }

        bytes memory userData =
            abi.encode(IBalancerVault.JoinKind.EXACT_TOKENS_IN_FOR_BPT_OUT, userDataAmountsIn, 2);

        // join balancer pool
        IRewardPoolDepositWrapper.JoinPoolRequest memory joinRequest = IRewardPoolDepositWrapper
            .JoinPoolRequest({
            assets: _pool.assets,
            maxAmountsIn: amountsIn,
            userData: userData,
            fromInternalBalance: false
        });

        // deposit into aura
        auraRewardPoolDepositWrapper.depositSingle(
            address(_pool.poolAddress),
            underlyingToken,
            _underlyingAmountIn,
            _pool.poolId,
            joinRequest
        );
    }

    /**
     * @notice Deposit underlying tokens into Aura, looping among pools
     * @param totalUnderlying_ The total value of underlying tokens
     * @param allocatedPerPool_ The array of per-pool allocated tokens
     * @param _underlyingAmountIn The amount of underlying tokens to deposit
     */
    function _depositToAura(
        uint256 totalUnderlying_,
        uint256[] memory allocatedPerPool_,
        uint256 _underlyingAmountIn
    ) internal {
        uint256 depositsRemaining = _underlyingAmountIn;
        uint256 totalAfterDeposit = totalUnderlying_ + _underlyingAmountIn;
        uint256[] memory allocatedPerPoolCopy = allocatedPerPool_.copy();

        while (depositsRemaining > 0) {
            (uint256 poolIndex, uint256 maxDeposit) =
                _getDepositPool(totalAfterDeposit, allocatedPerPoolCopy);
            // account for rounding errors
            if (depositsRemaining < maxDeposit + 1e2) {
                maxDeposit = depositsRemaining;
            }

            UnderlyingPool memory auraPool = underlyingPools[poolIndex];

            // Depositing into least balanced pool
            uint256 toDeposit = _min(depositsRemaining, maxDeposit);
            _depositToAuraPool(auraPool, toDeposit);
            depositsRemaining -= toDeposit;
            allocatedPerPoolCopy[poolIndex] += toDeposit;
        }
    }

    /**
     * @notice Get the maximum deviation allowed for pool weights
     * @param totalUnderlying_ The total value of underlying tokens
     * @param allocatedPerPool The array of per-pool allocated tokens
     */
    function _getDepositPool(uint256 totalUnderlying_, uint256[] memory allocatedPerPool)
        internal
        view
        returns (uint256 poolIndex, uint256 maxDepositAmount)
    {
        int256 depositPoolIndex = -1;
        for (uint256 i; i < allocatedPerPool.length; i++) {
            UnderlyingPool memory pool = underlyingPools[i];
            uint256 currentAlloc = allocatedPerPool[i];
            // TODO: Check if the following convert scale always works
            uint256 targetWeight = (pool.targetWeight);
            uint256 targetAllocation_ = totalUnderlying_.mulDown(targetWeight);
            if (currentAlloc >= targetAllocation_) continue;
            uint256 maxBalance_ = targetAllocation_ + targetAllocation_.mulDown(_getMaxDeviation());
            uint256 maxDepositAmount_ = maxBalance_ - currentAlloc;
            if (maxDepositAmount_ <= maxDepositAmount) continue;
            maxDepositAmount = maxDepositAmount_;
            depositPoolIndex = int256(i);
        }
        require(depositPoolIndex > -1, "error retrieving deposit pool");
        poolIndex = uint256(depositPoolIndex);
    }

    /**
     * @notice Withdraw Balancer Pool Tokens (BPT) from a given pool
     * @param _pool The underlying pool information
     * @param _underlyingAmount The amount of2 BPT to withdraw
     */
    function _withdrawFromAuraPool(UnderlyingPool memory _pool, uint256 _underlyingAmount)
        internal
    {
        IBalancerPool auraPool = IBalancerPool(_pool.poolAddress);

        // Compute how much BPT we need to withdraw
        uint256 _bptPrice = bptOracle.getPoolValuation(_pool.poolId, _pool.poolType);
        uint256 _bptAmountOut = _underlyingAmount.mulDown(
            bptOracle.getUSDPrice(address(underlyingToken))
        ).divDown(_bptPrice).convertScale(underlyingToken.decimals(), 18);

        // Make sure we have enough BPT to withdraw
        uint256 balance = auraPool.balanceOf(address(this));
        require(balance >= _bptAmountOut, "not enough balance");
        auraPool.withdrawAndUnwrap(_bptAmountOut, true);

        uint256 assetIndex = _pool.assetIndex;

        // BPT not being in the assets array, we need to adjust the index
        if (_pool.bptIndex > 0 && _pool.bptIndex < assetIndex) {
            assetIndex = assetIndex - 1;
        }
        bytes memory userData = abi.encode(
            IBalancerVault.ExitKind.EXACT_BPT_IN_FOR_ONE_TOKEN_OUT, _bptAmountOut, assetIndex
        );
        IBalancerVault.ExitPoolRequest memory exitRequest = IBalancerVault.ExitPoolRequest({
            assets: _pool.assets,
            minAmountsOut: new uint256[](_pool.assets.length),
            userData: userData,
            toInternalBalance: false
        });
        balancerVault.exitPool(_pool.poolId, address(this), payable(address(this)), exitRequest);
    }

    function _withdrawFromAura(
        uint256 totalUnderlying_,
        uint256[] memory allocatedPerPool_,
        uint256 underlyingToWithdraw_
    ) internal {
        uint256 withdrawalsRemaining = underlyingToWithdraw_;
        uint256 totalAfterWithdrawal = totalUnderlying_ - underlyingToWithdraw_;
        uint256[] memory allocatedPerPoolCopy = allocatedPerPool_.copy();

        while (withdrawalsRemaining > 0) {
            (uint256 poolIndex, uint256 maxWithdrawal) =
                _getWithdrawPool(totalAfterWithdrawal, allocatedPerPoolCopy);
            // account for rounding errors
            if (withdrawalsRemaining < maxWithdrawal + 1e2) {
                maxWithdrawal = withdrawalsRemaining;
            }

            UnderlyingPool memory auraPool = underlyingPools[poolIndex];

            uint256 underlyingToWithdraw = _min(withdrawalsRemaining, maxWithdrawal);
            _withdrawFromAuraPool(auraPool, underlyingToWithdraw);
            withdrawalsRemaining -= underlyingToWithdraw;
            allocatedPerPoolCopy[poolIndex] -= underlyingToWithdraw;
        }
    }

    function _getWithdrawPool(uint256 totalUnderlying_, uint256[] memory allocatedPerPool)
        internal
        view
        returns (uint256 poolIndex, uint256 maxWithdrawAmount)
    {
        int256 withdrawPoolIndex = -1;
        for (uint256 i; i < allocatedPerPool.length; i++) {
            UnderlyingPool memory pool = underlyingPools[i];
            uint256 currentAlloc = allocatedPerPool[i];

            uint256 targetWeight = pool.targetWeight;
            // If a balancer pool has a weight of 0,
            // withdraw from it if it has more than the max lp value
            if (targetWeight == 0) {
                uint256 price_ = bptOracle.getUSDPrice(address(underlyingToken));
                uint256 allocatedUsd = (price_ * currentAlloc) / 10 ** underlyingToken.decimals();
                if (allocatedUsd >= _MAX_USD_LP_VALUE_FOR_REMOVING_CURVE_POOL / 2) {
                    return (uint256(i), currentAlloc);
                }
            }

            uint256 targetAllocation_ = totalUnderlying_.mulDown(targetWeight);
            if (currentAlloc <= targetAllocation_) continue;
            uint256 minBalance_ = targetAllocation_ - targetAllocation_.mulDown(_getMaxDeviation());
            uint256 maxWithdrawAmount_ = currentAlloc - minBalance_;
            if (maxWithdrawAmount_ <= maxWithdrawAmount) continue;
            maxWithdrawAmount = maxWithdrawAmount_;
            withdrawPoolIndex = int256(i);
        }
        require(withdrawPoolIndex > -1, "error retrieving withdraw pool");
        poolIndex = uint256(withdrawPoolIndex);
    }

    /**
     * @notice Set the maximum deviation for pool weights
     * @param _maxDeviation The maximum allowed deviation in pool weights
     */
    function setMaxDeviation(uint256 _maxDeviation) external onlyOpalTeam {
        maxDeviation = _maxDeviation;
    }

    // ------------- PURE FUNCTIONS -------------

    /**
     * @notice Get the minimum of two values
     * @param a The first value
     * @param b The second value
     * @return The minimum of the two values
     */
    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /* PUBLIC VIEW */

    /**
     * @notice Get the total deposit of a user across all pools
     * @param user The address of the user
     * @return The total deposit of the user in USD
     */
    function getUserTotalDeposit(address user) public view returns (uint256) {
        uint256 total;
        uint8 length = uint8(underlyingPools.length);
        for (uint8 i = 0; i < length;) {
            total += getUserDeposit(user, i);
            unchecked {
                ++i;
            }
        }
        return total;
    }

    function totalUnderlying() public view virtual returns (uint256) {
        (uint256 totalUnderlying_,,) = getTotalAndPerPoolUnderlying();

        return totalUnderlying_;
    }

    // ------------- VIEW FUNCTIONS -------------

    /**
     * @notice Get the exchange rate of LP tokens to underlying tokens
     * @param totalUnderlying_ The total value of underlying tokens
     * @return The exchange rate
     */
    function _exchangeRate(uint256 totalUnderlying_) internal view returns (uint256) {
        uint256 lpSupply = lpToken.totalSupply();
        if (lpSupply == 0 || totalUnderlying_ == 0) return 10 ** 18;

        return totalUnderlying_.divDown(lpSupply);
    }

    /**
     * @notice Get the total and per-pool underlying balances
     * @param  id The id of the pool
     * @return The current underlying weight of the pool
     */
    function _getUnderlyingCurrentWeight(uint256 id) internal view returns (uint256) {
        uint256 totalTvl = getTotalTvl();
        uint256 poolTvl = getPoolTvl(id);
        return poolTvl == 0 || totalTvl == 0 ? 0 : (poolTvl * 100 / totalTvl);
    }

    /**
     * @notice Get the total and per-pool underlying balances
     * @param underlyingPrice The price of the underlying token
     * @return totalUnderlying_ The total value of underlying tokens
     * @return totalAllocated The total value of allocated tokens
     * @return perPoolUnderlying The array of per-pool underlying balances
     */
    function _getTotalAndPerPoolUnderlying(uint256 underlyingPrice)
        internal
        view
        returns (uint256 totalUnderlying_, uint256 totalAllocated, uint256[] memory)
    {
        uint256[] memory perPoolUnderlying = new uint256[](underlyingPools.length);
        uint8 length = uint8(underlyingPools.length);
        for (uint8 i = 0; i < length;) {
            uint256 totalBalance = getTotalBptBalance(i);
            uint256 poolUnderlying = getUnderlyingBalance(i, totalBalance, underlyingPrice);
            perPoolUnderlying[i] = poolUnderlying;
            totalUnderlying_ += poolUnderlying;
            unchecked {
                ++i;
            }
        }
        totalAllocated = totalUnderlying_ + underlyingToken.balanceOf(address(this));
        return (totalUnderlying_, totalAllocated, perPoolUnderlying);
    }

    /**
     * @notice Get the index of the least balanced underlying pool
     * @return The index of the least balanced pool
     */
    function getLeastBalancedUnderlying() public view returns (uint8) {
        uint8 min = 0;
        int256 largestDiff = 0;
        uint8 length = uint8(underlyingPools.length);
        for (uint8 i = 0; i < length;) {
            uint256 currentPoolWeight = _getUnderlyingCurrentWeight(i);
            int256 diff = int256(underlyingPools[i].targetWeight) - int256(currentPoolWeight);
            if (diff > largestDiff) {
                min = i;
                largestDiff = diff;
            }
            unchecked {
                ++i;
            }
        }
        return min;
    }

    /**
     * @notice Approve spending of a certain amount of tokens
     * @param token The address of the token to approve
     * @param amount The amount to approve
     */
    function approveForRewardManager(address token, uint256 amount) external onlyRewardManager {
        // Transfer the rewards to the user
        IERC20 erc20 = IERC20(token);
        erc20.forceApprove(rewardManager, amount);
    }

    /**
     * @notice Set the pool id of an extra reward token
     */
    function setExtraRewardPool(address _token, bytes32 _poolId) external onlyOpalTeam {
        if (_poolId != bytes32(0)) {
            IERC20(_token).forceApprove(address(balancerVault), 0);
            IERC20(_token).forceApprove(address(balancerVault), type(uint256).max);
        }
        extraRewardPools[_token] = _poolId;
        emit ExtraRewardPoolIdUpdated(_token, _poolId);
    }

    /**
     * @notice Update GEM pool id
     */
    function setGemPoolId(bytes32 _poolId) external onlyOpalTeam {
        wethToGemPoolId = _poolId;
        emit GemPoolIdUpdated(_poolId);
    }

    /**
     * @notice Swap an ERC20 into GEM
     * @dev It has to be in the omnipool contract because Balancer does not allow the reward manager to perform a swap (ERR 401) https://docs.balancer.fi/concepts/advanced/relayers.html
     */
    function swapForGem(address _token, uint256 _amountIn)
        external
        onlyRewardManager
        returns (bool)
    {
        bytes32 poolId = extraRewardPools[_token];
        if (poolId == bytes32(0) || wethToGemPoolId == bytes32(0)) {
            return false;
        }

        IERC20 erc20Token = IERC20(_token);
        erc20Token.forceApprove(address(balancerVault), _amountIn);

        // First step erc20Token -> WETH
        IBalancerVault.BatchSwapStep memory stepOne = IBalancerVault.BatchSwapStep({
            poolId: poolId,
            assetInIndex: 0,
            assetOutIndex: 1,
            amount: _amountIn,
            userData: bytes("")
        });
        // Second step WETH -> GEM
        IBalancerVault.BatchSwapStep memory stepTwo = IBalancerVault.BatchSwapStep({
            poolId: wethToGemPoolId,
            assetInIndex: 1,
            assetOutIndex: 2,
            amount: 0,
            userData: bytes("")
        });

        IBalancerVault.FundManagement memory fundManagement = IBalancerVault.FundManagement({
            sender: address(this),
            fromInternalBalance: false,
            recipient: payable(address(this)),
            toInternalBalance: false
        });

        IAsset[] memory assets = new IAsset[](3);
        assets[0] = IAsset(_token);
        assets[1] = IAsset(WETH);
        assets[2] = IAsset(GEM);

        IBalancerVault.BatchSwapStep[] memory batchSwapSteps = new IBalancerVault.BatchSwapStep[](2);
        batchSwapSteps[0] = stepOne;
        batchSwapSteps[1] = stepTwo;

        int256[] memory limits = new int256[](3);
        limits[0] = type(int256).max;
        limits[1] = type(int256).max;
        limits[2] = type(int256).max;

        uint256 deadline = block.timestamp + 60_000;

        balancerVault.batchSwap(
            IBalancerVault.SwapKind.GIVEN_IN,
            batchSwapSteps,
            assets,
            fundManagement,
            limits,
            deadline
        );

        return true;
    }

    /**
     * @notice  Get Underlying Pools Length
     * @return  uint8  length
     */
    function getUnderlyingPoolsLength() external view returns (uint8) {
        return uint8(underlyingPools.length);
    }

    /**
     * @notice  Get Underlying Pool
     * @param   index  index of the underlying pools
     * @return  address  address of the pool
     */
    function getUnderlyingPool(uint8 index) external view returns (address) {
        return underlyingPools[index].poolAddress;
    }

    /**
     * @notice  Get total Deposited
     * @return  uint256  total deposited
     */
    function getTotalDeposited() external view returns (uint256) {
        return totalDeposited;
    }

    /**
     * @notice  desactiate the pool
     * @dev     Only callable by the controller
     */
    function desactivate() external onlyController {
        if (isShutdown) {
            revert PoolAlreadyShutdown();
        }
        isShutdown = true;
        emit Shutdown();
    }

    /**
     * @notice  Validate Pool
     * @param   poolAddress  address of the pool
     * @return  bool  return true if the pool is valid
     */
    function _validatePool(address poolAddress) internal view returns (bool) {
        uint256 length = underlyingPools.length;
        for (uint8 i = 0; i < length;) {
            if (underlyingPools[i].poolAddress == poolAddress) {
                return true;
            }
            unchecked {
                ++i;
            }
        }
        return false;
    }

    function _setWeightToZero(address pool_) internal {
        UnderlyingPool memory pool = getPoolByAddress(pool_);
        uint256 weight_ = pool.targetWeight;
        if (weight_ == 0) revert("pool already set to 0 weight");
        if (weight_ != ScaledMath.ONE) {
            revert("can't remove last pool");
        }

        int256 scaleUp_ = int256(ScaledMath.ONE.divDown(ScaledMath.ONE - pool.targetWeight));
        uint8 underlyingPoolLength = uint8(underlyingPools.length);
        for (uint8 i; i < underlyingPoolLength;) {
            address poolAddress_ = underlyingPools[i].poolAddress;
            uint256 newWeight_ =
                poolAddress_ == pool_ ? 0 : (pool.targetWeight).mulDown(uint256(scaleUp_));
            pool.targetWeight = newWeight_;
            emit NewWeight(poolAddress_, newWeight_);

            unchecked {
                ++i;
            }
        }

        // Updating total deviation
        (uint256 totalUnderlying_,, uint256[] memory allocatedPerPool) =
            getTotalAndPerPoolUnderlying();
        uint256 totalDeviation = _computeTotalDeviation(totalUnderlying_, allocatedPerPool);
        totalDeviationAfterWeightUpdate = totalDeviation;
    }

    function computeTotalDeviation() public view returns (uint256) {
        (uint256 totalUnderlying_,, uint256[] memory perPoolAllocations_) =
            getTotalAndPerPoolUnderlying();
        return _computeTotalDeviation(totalUnderlying_, perPoolAllocations_);
    }

    /**
     * @notice  Calculates the deviation of the Omnipool from the target allocation.
     * @dev     The deviation is calculated as the absolute difference between the target weight and the current weight.
     * @param   allocatedUnderlying_  The total amount of underlying assets allocated to the Balancer pools.
     * @param   perPoolAllocations_  The amount of underlying assets allocated to each Balancer pool.
     * @return  uint256  .
     */
    function _computeTotalDeviation(
        uint256 allocatedUnderlying_,
        uint256[] memory perPoolAllocations_
    ) internal view returns (uint256) {
        uint256 totalDeviation;
        uint256 length = perPoolAllocations_.length;
        for (uint256 i; i < length;) {
            uint256 weight = underlyingPools[i].targetWeight;
            uint256 targetAmount = allocatedUnderlying_.mulDown(weight);
            totalDeviation += targetAmount.absSub(perPoolAllocations_[i]);
            unchecked {
                ++i;
            }
        }
        return totalDeviation;
    }

    function getTotalAndPerPoolUnderlying()
        public
        view
        returns (
            uint256 totalUnderlying_,
            uint256 totalAllocated_,
            uint256[] memory perPoolUnderlying_
        )
    {
        uint256 underlyingPrice_ = bptOracle.getUSDPrice(address(underlyingToken));
        return _getTotalAndPerPoolUnderlying(underlyingPrice_);
    }

    /**
     * @notice  Updates the weights of the Balancer pools.
     * @dev
     * @param   poolWeights  The new weights of the Balancer pools.
     */
    function updateWeights(IOmnipoolController.WeightUpdate[] calldata poolWeights)
        external
        override
        onlyController
    {
        uint256 weightLength = poolWeights.length;
        uint256 total;
        for (uint8 i; i < weightLength;) {
            address pool = poolWeights[i].poolAddress;
            if (!isBalancerPool(pool)) {
                revert PoolNotFound();
            }
            uint256 newWeight = poolWeights[i].newWeight;
            underlyingPools[i].targetWeight = newWeight;

            total += newWeight;
            unchecked {
                ++i;
            }

            emit NewWeight(pool, newWeight);
        }

        if (total != ScaledMath.ONE) {
            revert NotSumToOne();
        }

        (uint256 totalUnderlying_, uint256 totalAllocated, uint256[] memory allocatedPerPool) =
            getTotalAndPerPoolUnderlying();

        uint256 totalDeviation = _computeTotalDeviation(totalUnderlying_, allocatedPerPool);
        totalDeviationAfterWeightUpdate = totalDeviation;
        rebalancingRewardActive = !_isBalanced(allocatedPerPool, totalAllocated);
    }

    /**
     * @notice  Update a single balancer pool weight.
     * @dev     This function is used to update a single balancer pool weight.
     * @param   poolAddress  The address of the balancer pool.
     * @param   newWeight  The new weight of the balancer pool.
     */
    function updateWeight(address poolAddress, uint256 newWeight)
        external
        override
        onlyController
    {
        if (!isBalancerPool(poolAddress)) {
            revert PoolNotFound();
        }
        uint256 index = getPoolIndex(poolAddress);
        underlyingPools[index].targetWeight = newWeight;
        emit NewWeight(poolAddress, newWeight);

        (uint256 totalUnderlying_, uint256 totalAllocated, uint256[] memory allocatedPerPool) =
            getTotalAndPerPoolUnderlying();

        uint256 totalDeviation = _computeTotalDeviation(totalUnderlying_, allocatedPerPool);
        totalDeviationAfterWeightUpdate = totalDeviation;
        rebalancingRewardActive = !_isBalanced(allocatedPerPool, totalAllocated);
    }

    function _handleRebalancingRewards(
        address account,
        uint256 allocatedBalanceBefore_,
        uint256 allocatedBalanceAfter_,
        uint256[] memory allocatedPerPoolBefore,
        uint256[] memory allocatedPerPoolAfter
    ) internal {
        if (!rebalancingRewardActive) return;
        uint256 deviationBefore =
            _computeTotalDeviation(allocatedBalanceBefore_, allocatedPerPoolBefore);
        uint256 deviationAfter =
            _computeTotalDeviation(allocatedBalanceAfter_, allocatedPerPoolAfter);

        IOmnipoolController controller =
            IOmnipoolController(registryContract.getContract(CONTRACT_OMNIPOOL_CONTROLLER));
        controller.handleRebalancingRewards(account, deviationBefore, deviationAfter);

        if (_isBalanced(allocatedPerPoolAfter, allocatedBalanceAfter_)) {
            rebalancingRewardActive = false;
        }
    }

    /**
     * @notice  Checks if the Balancer pools are balanced.
     * @dev     The Balancer pools are considered balanced if the deviation of the Omnipool from the target allocation is less than the maximum deviation.
     * @param   allocatedPerPool_  The amount of underlying assets allocated to each Balancer pool.
     * @param   totalAllocated_  The total amount of underlying assets allocated to the Balancer pools.
     * @return  bool  .
     */
    function _isBalanced(uint256[] memory allocatedPerPool_, uint256 totalAllocated_)
        internal
        view
        returns (bool)
    {
        if (totalAllocated_ == 0) return true;
        uint256 length = allocatedPerPool_.length;
        for (uint256 i; i < length;) {
            uint256 weight_ = underlyingPools[i].targetWeight;
            uint256 currentAllocated_ = allocatedPerPool_[i];
            uint256 targetAmount = totalAllocated_.mulDown(weight_);
            uint256 deviation = targetAmount.absSub(currentAllocated_);
            uint256 deviationRatio = deviation.divDown(targetAmount);

            if (deviationRatio > maxDeviation) return false;

            unchecked {
                ++i;
            }
        }
        return true;
    }

    /**
     * @notice  Checks if a pool is a Balancer pool.
     * @dev     This function is used to check if a pool is a Balancer pool.
     * @param   pool  The address of the pool.
     * @return  bool  return true if the pool is a Balancer pool
     */
    function isBalancerPool(address pool) public view returns (bool) {
        uint256 len = uint8(underlyingPools.length);
        for (uint8 i = 0; i < len;) {
            if (underlyingPools[i].poolAddress == pool) {
                return true;
            }
            unchecked {
                ++i;
            }
        }
        return false;
    }

    function _getMaxDeviation() internal view returns (uint256) {
        return rebalancingRewardActive ? 0 : maxDeviation;
    }

    function getUnderlyingToken() external view returns (IERC20Metadata) {
        return IERC20Metadata(underlyingToken);
    }

    function getTotalUnderlying() external view returns (uint256) {
        return totalUnderlyingPools;
    }

    function getTotalDeviationAfterUpdate() external view returns (uint256) {
        // TO DO
        return totalDeviationAfterWeightUpdate;
    }

    function getLpToken() external view returns (IERC20Metadata) {
        return IERC20Metadata(address(lpToken));
    }

    function getPoolByAddress(address pool) public view returns (UnderlyingPool memory) {
        uint8 length = uint8(underlyingPools.length);
        for (uint8 i = 0; i < length;) {
            if (underlyingPools[i].poolAddress == pool) {
                return underlyingPools[i];
            }
            unchecked {
                ++i;
            }
        }
        revert();
    }

    function getPoolIndex(address pool) public view returns (uint256) {
        uint8 length = uint8(underlyingPools.length);
        for (uint8 i = 0; i < length;) {
            if (underlyingPools[i].poolAddress == pool) {
                return i;
            }
            unchecked {
                ++i;
            }
        }
        revert();
    }

    function getAllUnderlyingPoolWeight() public view returns (uint256[] memory) {
        uint256[] memory weights = new uint256[](underlyingPools.length);
        uint8 length = uint8(underlyingPools.length);
        for (uint8 i = 0; i < length;) {
            weights[i] = underlyingPools[i].targetWeight;
            unchecked {
                ++i;
            }
        }
        return weights;
    }

    function getPoolWeight(uint256 index) public view returns (uint256) {
        return underlyingPools[index].targetWeight;
    }
}
