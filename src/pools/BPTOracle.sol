// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/interfaces/IERC20Metadata.sol";
import {IRateProvider} from
    "balancer-v2-monorepo/pkg/interfaces/contracts/pool-utils/IRateProvider.sol";
import {IRateProviderPool} from
    "balancer-v2-monorepo/pkg/interfaces/contracts/pool-utils/IRateProviderPool.sol";
import {IManagedPool} from
    "balancer-v2-monorepo/pkg/interfaces/contracts/pool-utils/IManagedPool.sol";
import {IExternalWeightedMath} from
    "balancer-v2-monorepo/pkg/interfaces/contracts/pool-weighted/IExternalWeightedMath.sol";
import {IBalancerPool} from "src/interfaces/Balancer/IBalancerPool.sol";
import {IBalancerVault} from "src/interfaces/Balancer/IBalancerVault.sol";
import {IPriceFeed} from "src/interfaces/IPriceFeed.sol";
import {IOracle} from "src/interfaces/Oracle/IOracle.sol";
import {VaultReentrancyLib} from "src/utils/VaultReentrancyLib.sol";
import {PRBMathSD59x18} from "src/utils/PRBMathSD59x18.sol";
import {PRBMathUD60x18} from "src/utils/PRBMathUD60x18.sol";
import {PoolType} from "src/utils/constants.sol";

import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";
import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";
import {
    CONTRACT_PRICE_FEED_ORACLE,
    CONTRACT_REGISTRY_ACCESS,
    ROLE_OPAL_TEAM,
    CONTRACT_BALANCER_VAULT
} from "src/utils/constants.sol";

/**
 * @title BPTOracle
 * @author Opal Team
 * @dev A smart contract for providing price information for Balancer pools in various types.
 */
contract BPTOracle {
    using VaultReentrancyLib for IBalancerVault;

    using PRBMathUD60x18 for uint256;

    /**
     *  @custom:library PRBMathSD59x18 Smart contract library for advanced fixed-point math that works with int256
     */
    using PRBMathSD59x18 for int256;

    address public priceFeedAddress;

    IRegistryAccess public registryAccess;
    IRegistryContract public registryContract;
    IBalancerVault internal immutable balancerVault;

    mapping(address => uint256) public tokenHeartbeat;

    error NullAddress();
    error PriceFeedNotFound();
    error NotAuthorized();
    error HeartbeatNotSet();
    error StalePrice();

    event SetTokenHeartbeat(address token, uint256 heartbeat);

    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) revert NotAuthorized();
        _;
    }

    constructor(address registryContract_) {
        if (registryContract_ == address(0)) revert NullAddress();
        registryContract = IRegistryContract(registryContract_);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));
        priceFeedAddress = registryContract.getContract(CONTRACT_PRICE_FEED_ORACLE);
        balancerVault = IBalancerVault(registryContract.getContract(CONTRACT_BALANCER_VAULT));
    }

    /**
     * @notice  .
     * @dev     .
     * @param   token  address of the token.
     * @param   heartbeat  the heartbeat of the token
     */
    function setHeartbeat(address token, uint256 heartbeat) external onlyOpalTeam {
        tokenHeartbeat[token] = heartbeat;
        emit SetTokenHeartbeat(token, heartbeat);
    }

    /**
     * @dev Get the USD price for a stable pool identified by its poolId.
     * @param poolId The poolId of the stable pool.
     * @return The USD price for the stable pool.
     */
    function BptPriceStablePool(bytes32 poolId) public view returns (uint256) {
        (address[] memory tokens,,) = balancerVault.getPoolTokens(poolId);

        (address poolAddress,) = balancerVault.getPool(poolId);
        uint256 min = type(uint256).max;
        address token;
        uint256 length = tokens.length;
        for (uint256 i; i < length;) {
            token = address(tokens[i]);

            if (token == poolAddress) {
                unchecked {
                    ++i;
                }
                continue;
            }

            uint256 value = getUSDPrice(token);
            if (value < min) {
                min = value;
            }

            unchecked {
                ++i;
            }
        }
        return (min * IRateProvider(poolAddress).getRate()) / 1e18;
    }

    /**
     * @dev Get the USD price for a weighted pool identified by its poolId.
     * @dev https://hackmd.io/@re73/SJHmQaCFq
     * @param poolId The poolId of the weighted pool.
     * @return The USD price for the weighted pool.
     */
    function BptPriceWeightPool(bytes32 poolId) public view returns (uint256) {
        (address[] memory tokens,,) = balancerVault.getPoolTokens(poolId);

        (address poolAddress,) = balancerVault.getPool(poolId);

        // 1. weight = balance * price / invariant
        uint256[] memory weights = IManagedPool(poolAddress).getNormalizedWeights();

        uint256 length = tokens.length;

        int256 invariant = int256(IBalancerPool(poolAddress).getInvariant());

        int256 totalPi = PRBMathSD59x18.fromInt(1e18);

        for (uint256 i = 0; i < length;) {
            // Get token price
            uint256 assetPrice = getUSDPrice(address(tokens[i]));

            uint256 weight = weights[i];

            int256 actualPrice = int256(assetPrice.mul(1e18).div(weight));

            int256 uniquePi = actualPrice.pow(int256(weight));

            totalPi = totalPi.mul(uniquePi);

            unchecked {
                ++i;
            }
        }

        // Pool TVL in USD
        int256 numerator = totalPi.mul(invariant);

        // 4. Total Supply of BPT tokens for this pool
        int256 totalSupply = int256(IBalancerPool(poolAddress).totalSupply());

        // 5. BPT Price (USD) = TVL / totalSupply
        uint256 bptPrice = uint256((numerator.toInt().div(totalSupply)));
        return bptPrice;
    }

    /**
     * @dev Get the USD price for a composable pool identified by its poolId.
     * @param poolId The poolId of the composable pool.
     * @return The USD price for the composable pool.
     */
    function BptPriceComposablePool(bytes32 poolId) public view returns (uint256) {
        (address[] memory tokens,,) = balancerVault.getPoolTokens(poolId);

        (address pool,) = balancerVault.getPool(poolId);

        uint256 length = tokens.length;

        uint256 minPrice = type(uint256).max;
        uint256 poolRate;

        for (uint256 i; i < length;) {
            if (address(tokens[i]) == pool) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Get token price
            uint256 assetPrice = getUSDPrice(address(tokens[i]));

            // Get pool rate
            poolRate = IRateProvider(pool).getRate();

            uint256 actualPrice = assetPrice * poolRate / poolRate;

            minPrice = minPrice < actualPrice ? minPrice : actualPrice;

            unchecked {
                ++i;
            }
        }

        uint256 priceResult = minPrice * poolRate;

        return priceResult / 1e18;
    }

    /**
     * @dev Get the USD valuation for a Balancer pool based on its poolId and type.
     * @param poolId The poolId of the Balancer pool.
     * @param poolType The type of the Balancer pool.
     * @return The USD valuation for the Balancer pool.
     */
    function getPoolValuation(bytes32 poolId, PoolType poolType) public view returns (uint256) {
        if (poolType == PoolType.WEIGHTED) {
            return BptPriceWeightPool(poolId);
        } else if (poolType == PoolType.STABLE) {
            return BptPriceStablePool(poolId);
        } else if (poolType == PoolType.COMPOSABLE) {
            return BptPriceComposablePool(poolId);
        }
        return 0;
    }

    /**
     * @dev call the oracle to get the price in USD with 18 decimals
     * @param token the token address
     * @return priceInUSD the amount in USD with token decimals
     */
    function getUSDPrice(address token) public view returns (uint256 priceInUSD) {
        if (tokenHeartbeat[token] == 0) {
            revert HeartbeatNotSet();
        }

        IOracle priceFeed = IPriceFeed(priceFeedAddress).getPriceFeedFromAsset(token);
        if (address(priceFeed) == address(0)) revert PriceFeedNotFound();
        (, int256 priceInUSDInt,, uint256 updatedAt,) = priceFeed.latestRoundData();
        if (updatedAt + tokenHeartbeat[token] < block.timestamp) revert StalePrice();
        // Oracle answer are normalized to 8 decimals
        uint256 newPrice = _normalizeAmount(uint256(priceInUSDInt), 8);
        return newPrice;
    }

    function _normalizeAmount(uint256 _price, uint256 _answerDigits)
        public
        pure
        returns (uint256 price)
    {
        uint256 targetDigits = 18;
        if (_answerDigits >= targetDigits) {
            // Scale the returned price value down to target precision
            price = _price / (10 ** (_answerDigits - targetDigits));
        } else if (_answerDigits < targetDigits) {
            // Scale the returned price value up to target precision
            price = _price * (10 ** (targetDigits - _answerDigits));
        }
        return price;
    }

    /**
     * @dev call the oracle to get the price in USD of `amount` of token with 18 decimals
     * @param amount the amount of token to convert in USD with 18 decimals
     * @param token the token address
     * @return amountInUSD the amount in USD with 18 decimals
     */
    function _getQuote(uint256 amount, address token) internal view returns (uint256 amountInUSD) {
        return amount * getUSDPrice(token) / 1e18;
    }
}
