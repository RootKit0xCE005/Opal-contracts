// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IOracle} from "src/interfaces/Oracle/IOracle.sol";

enum OracleStatus {
    oracleWorking,
    oracleUntrusted,
    oracleFrozen
}

interface IPriceFeed {
    function LatestAssetPrice(IOracle asset) external view returns (uint80, int256);

    function getPriceFeedFromAsset(address asset) external view returns (IOracle);

    function getStatus(address token) external view returns (uint256);

    function getUSDPrice(address token) external view returns (uint256);
}
