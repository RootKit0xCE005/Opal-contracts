// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface IGemToken {
    function mint(address to, uint256 amount) external returns (uint256);

    function burn(uint256 amount) external;
}
