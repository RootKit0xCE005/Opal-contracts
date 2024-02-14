// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IOpalLpToken} from "src/interfaces/Token/IOpalLpToken.sol";
import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";
import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";
import {
    CONTRACT_REGISTRY_ACCESS,
    ROLE_BURN_LP_TOKEN,
    ROLE_MINT_LP_TOKEN
} from "src/utils/constants.sol";

contract OpalLpToken is IOpalLpToken, ERC20 {
    IRegistryContract public registryContract;
    IRegistryAccess public registryAccess;

    error NotAuthorized();

    modifier onlyMinter() {
        if (!registryAccess.checkRole(ROLE_MINT_LP_TOKEN, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    modifier onlyBurner() {
        if (!registryAccess.checkRole(ROLE_BURN_LP_TOKEN, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    uint8 private __decimals;

    constructor(
        address _registryContract,
        uint8 _decimals,
        string memory name,
        string memory symbol
    ) ERC20(name, symbol) {
        registryContract = IRegistryContract(_registryContract);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));

        __decimals = _decimals;
    }

    /**
     * @notice  Mint new token
     * @param   to  address of the receiver
     * @param   amount  amount to mint
     * @return  uint256  .
     */
    function mint(address to, uint256 amount) public override onlyMinter returns (uint256) {
        _mint(to, amount);
        return amount;
    }

    /**
     * @notice  Burn token
     * @dev     .
     * @param   _owner  The address of the people who want to burn the token
     * @param   _amount  The amount of token to burn
     * @return  uint256  .
     */
    function burn(address _owner, uint256 _amount) external override onlyBurner returns (uint256) {
        _burn(_owner, _amount);
        return _amount;
    }

    function decimals() public view virtual override(ERC20, IERC20Metadata) returns (uint8) {
        return __decimals;
    }
}
