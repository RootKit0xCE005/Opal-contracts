// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @dev Mocked ERC20 token for testing
 */
contract MockedERC20 is ERC20 {
    constructor(string memory _tokenName, string memory _tokenSymbol)
        ERC20(_tokenName, _tokenSymbol)
    {}

    function mint(address _to, uint256 _amount) external {
        _mint(_to, _amount);
    }

    function burn(address _from, uint256 _amount) external {
        _burn(_from, _amount);
    }
}
