// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.19;

import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";
import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";

import {ROLE_OPAL_TEAM} from "src/utils/constants.sol";

contract RegistryContract is IRegistryContract {
    mapping(bytes32 => address) private _contracts;
    mapping(bytes32 => address) private _address;
    address private _registryAccess;

    /*//////////////////////////////////////////////////////////////
                                Event
    //////////////////////////////////////////////////////////////*/

    event SetContract(bytes32 name, address contractAddress);
    event SetAddress(bytes32 name, address importantAddress);

    /*//////////////////////////////////////////////////////////////
                                Error
    //////////////////////////////////////////////////////////////*/

    error NullAddress();
    error NotAuthorized();

    /*//////////////////////////////////////////////////////////////
                               Modifier
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice  Check if the caller is an admin
     */
    modifier onlyOpalTeam() {
        if (!IRegistryAccess(_registryAccess).checkRole(ROLE_OPAL_TEAM, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             Constructor
    //////////////////////////////////////////////////////////////*/

    constructor(address registryAccess_) {
        if (registryAccess_ == address(0)) {
            revert NullAddress();
        }
        _registryAccess = registryAccess_;
    }

    /*//////////////////////////////////////////////////////////////
                               External
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice  Set the address of the contract
     * @param   name  name of the contract
     * @param   contractAddress  address of the contract
     */
    function setContract(bytes32 name, address contractAddress) external onlyOpalTeam {
        if (contractAddress == address(0)) {
            revert NullAddress();
        }
        _contracts[name] = contractAddress;
        emit SetContract(name, contractAddress);
    }

    /**
     * @notice  Get the address of the contract
     * @param   name  name of the contract
     * @return  address  address of the contract
    */
    function getContract(bytes32 name) external view returns (address) {
        address _contract = _contracts[name];
        if (_contract == address(0))  revert NullAddress(); 
        return _contract;
    }
}
