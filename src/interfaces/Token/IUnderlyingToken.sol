pragma solidity ^0.8.20;

import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface IUnderlyingToken is IERC1155 {
    function registerTokenId(uint256 id, string memory name) external;
    function mint(address account, uint256 id, uint256 amount) external;
    function idExists(uint256 id) external view returns (bool);
}
