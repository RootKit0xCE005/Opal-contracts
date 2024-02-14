pragma solidity ^0.8.20;

import {ERC1155Burnable} from "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Burnable.sol";

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";
import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";

import {ROLE_OMNIPOOL, ROLE_OPAL_TEAM, CONTRACT_REGISTRY_ACCESS} from "src/utils/constants.sol";

contract UnderlyingToken is ERC1155("OwO"), ERC1155Burnable {
    string[] public _tokenIds;
    uint256 public _totalIds = 0;

    mapping(address => bool) public omniPools;

    IRegistryAccess public registryAccess;
    IRegistryContract public registryContract;

    error NotAuthorized();

    modifier idExist(uint256 id) {
        require(idExists(id), "id does not exist");
        _;
    }

    modifier onlyAuthorized() {
        if (!omniPools[msg.sender] && !registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    constructor(address _registryContract) ERC1155Burnable() {
        registryContract = IRegistryContract(_registryContract);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));
    }

    /**
     * @notice  Register token id
     * @param   id  Id of the token
     * @param   name  Name of the token
     */
    function registerTokenId(uint256 id, string calldata name) external onlyAuthorized {
        if (id >= _totalIds) {
            _tokenIds.push(name);
            _totalIds++;
        } else {
            _tokenIds[id] = name;
        }
    }

    /* ONLY ADMIN */

    /**
     * @notice  Mint new token
     * @param   account  address of the account
     * @param   id id of the token
     * @param   amount  amount to mint
     */
    function mint(address account, uint256 id, uint256 amount) public idExist(id) onlyAuthorized {
        _mint(account, id, amount, "");
    }

    /**
     * @notice  Burn token
     * @param   account  address of the account
     * @param   id  id of the token
     * @param   amount  amount to burn
     */
    function burnFor(address account, uint256 id, uint256 amount) public onlyAuthorized {
        _burn(account, id, amount);
    }

    /**
     * @notice  Register Omnipool
     * @param   pool  address of the pool
     */
    function registerOmnipool(address pool) public onlyOpalTeam {
        omniPools[pool] = true;
    }

    /* PUBLIC VIEW */

    /**
     * @notice  Check if id exists
     * @param   id  id of the token
     * @return  bool  return true if id exists
     */
    function idExists(uint256 id) public view returns (bool) {
        return id < _totalIds;
    }

    /**
     * @notice  Get token name
     * @param   id  id of the token
     * @return  string  .
     */
    function getTokenName(uint256 id) public view idExist(id) returns (string memory) {
        return _tokenIds[id];
    }
}
