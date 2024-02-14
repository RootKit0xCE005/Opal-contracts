// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";

import {GEM_TOTAL_SUPPLY} from "src/utils/constants.sol";

contract GEM is ERC20 {
    constructor() ERC20("Opal", "GEM") {
        _mint(msg.sender, GEM_TOTAL_SUPPLY);
    }
}
