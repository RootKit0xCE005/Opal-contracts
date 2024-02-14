// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPriceFeed} from "src/interfaces/IPriceFeed.sol";
import {IOracle} from "src/interfaces/Oracle/IOracle.sol";

import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";
import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";

import {IERC20Metadata} from "@openzeppelin/contracts/interfaces/IERC20Metadata.sol";

import {CONTRACT_REGISTRY_ACCESS, ROLE_OPAL_TEAM} from "src/utils/constants.sol";

/**
 * Network: Mainnet
 *
 * stETH/USD Address: 0xcfe54b5cd566ab89272946f602d76ea879cab4a8
 * ETH/USD Address: 0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419
 * USDC/USD Address:0x48731cF7e84dc94C5f84577882c14Be11a5B7456
 */
contract PriceFeed is IPriceFeed {
    enum OracleStatus {
        oracleWorking,
        oracleUntrusted,
        oracleFrozen
    }

    IRegistryAccess public registryAccess;
    IRegistryContract public registryContract;

    mapping(address => IOracle) private _priceFeedMapping;
    mapping(IOracle => bool) private _isSupportedPriceFeed;
    mapping(address => OracleStatus) private _oracleStatus;

    error NotAuthorized();
    error PriceFeedNotFound();

    event AddNewPriceFeedAsset(address asset, address priceFeed);

    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) revert NotAuthorized();
        _;
    }

    constructor(address _registryContract) {
        registryContract = IRegistryContract(_registryContract);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));
    }
    /**
     * @notice Add a new price feed for a specific asset
     * @param asset The address of the asset
     * @param priceFeed The address of the price feed contract (IOracle)
     */

    function addPriceFeed(address asset, address priceFeed) public onlyOpalTeam {
        _priceFeedMapping[asset] = IOracle(priceFeed);
        _isSupportedPriceFeed[IOracle(priceFeed)] = true;
        emit AddNewPriceFeedAsset(asset, priceFeed);
    }

    function updatePricFeed(address asset, address priceFeed) public onlyOpalTeam {
        if (!_isSupportedPriceFeed[_priceFeedMapping[asset]]) revert PriceFeedNotFound();
        _priceFeedMapping[asset] = IOracle(priceFeed);
    }

    function removePriceFeed(address asset) public onlyOpalTeam {
        if (!_isSupportedPriceFeed[_priceFeedMapping[asset]]) revert PriceFeedNotFound();
        delete _priceFeedMapping[asset];
        _isSupportedPriceFeed[_priceFeedMapping[asset]] = false;
    }

    /**
     * @notice Get the latest round data for a specified asset price feed
     * @param asset The IOracle representing the asset's price feed
     * @return The round ID and the latest price
     */
    function LatestAssetPrice(IOracle asset) public view returns (uint80, int256) {
        if (!_isSupportedPriceFeed[asset]) revert PriceFeedNotFound();
        (uint80 roundID, int256 price,,,) = asset.latestRoundData();
        return (roundID, price);
    }

    /**
     * @notice Get the latest recorded price for a specified asset
     * @param asset The address of the asset
     * @return The latest recorded price, adjusted for decimals
     */
    function LastPrice(address asset) public view returns (int256) {
        IOracle priceFeed = _priceFeedMapping[asset];
        uint256 decimals = IERC20Metadata(asset).decimals();
        if (address(priceFeed) == address(0)) revert PriceFeedNotFound();
        (, int256 price,,,) = priceFeed.latestRoundData();
        return price / int256(10 ** decimals);
    }

    /**
     * @notice Get the latest recorded USD price for a specified token
     * @param token The address of the token
     * @return The latest recorded USD price, adjusted for token decimals
     */
    function getUSDPrice(address token) public view returns (uint256) {
        IOracle priceFeed = _priceFeedMapping[token];
        uint256 decimals = IERC20Metadata(token).decimals();
        if (address(priceFeed) == address(0)) revert PriceFeedNotFound();
        (, int256 price,,,) = priceFeed.latestRoundData();
        return uint256(price / int256(10 ** decimals));
    }

    /**
     * @notice Get the price feed contract for a specified asset
     * @param asset The address of the asset
     * @return The IOracle representing the asset's price feed
     */
    function getPriceFeedFromAsset(address asset) public view returns (IOracle) {
        return _priceFeedMapping[asset];
    }

    /**
     * @notice Get the quote for a specified asset and amount
     * @param asset The address of the asset
     * @param amount The amount for which the quote is requested
     * @return The calculated quote based on the latest recorded price and amount, adjusted for decimals
     */
    function getQuote(address asset, uint256 amount) public view returns (uint256) {
        IOracle priceFeed = _priceFeedMapping[asset];
        uint256 decimals = IERC20Metadata(asset).decimals();
        if (address(priceFeed) == address(0)) revert PriceFeedNotFound();
        (, int256 price,,,) = priceFeed.latestRoundData();
        return uint256(price) * amount / (uint256(10) ** decimals);
    }

    /**
     * @notice Get the status of the oracle for a specified token
     * @param token The address of the token
     * @return The status of the oracle for the specified token
     */
    function getStatus(address token) public view returns (uint256) {
        return uint256(_oracleStatus[token]);
    }
}
