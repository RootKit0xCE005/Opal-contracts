// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ROLE_ADMIN, ROLE_OPAL_TEAM} from "src/utils/constants.sol";

contract RegistryAccess is Ownable2Step, AccessControl {
    /*//////////////////////////////////////////////////////////////
                                Event
    //////////////////////////////////////////////////////////////*/

    event SetDaoCollateralContract(address foundationContract);

    /*//////////////////////////////////////////////////////////////
                                Error
    //////////////////////////////////////////////////////////////*/

    error NullAddress();
    error NotAuthorized();

    /*//////////////////////////////////////////////////////////////
                               Modifier
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice  This modifier is used to check if the caller has ROLE_ADMIN role
     */
    modifier onlyAdmin() {
        if (!hasRole(ROLE_ADMIN, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    /**
     * @notice  This modifier is used to check if the caller has Opal Tech Team role
     */
    modifier onlyOpalTeam() {
        if (!hasRole(ROLE_OPAL_TEAM, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             Constructor
    //////////////////////////////////////////////////////////////*/

    constructor() Ownable(msg.sender) {
        _grantRole(ROLE_ADMIN, msg.sender);
        _transferOwnership(msg.sender);
    }

    /*//////////////////////////////////////////p////////////////////
                               External
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice  transferAdminOwnership method
     * @param   newOwner address of the contract_ to grant role
     * @custom:audit This method is part of the two step ownership transfer
     */
    function transferAdminOwnership(address newOwner) public onlyAdmin {
        transferOwnership(newOwner);
    }

    /**
     * @notice  AcceptAdminOwnership method
     * @custom:audit This method is part of the two step ownership transfer
     */
    function acceptAdminOwnership() public {
        if (msg.sender != pendingOwner()) {
            revert NotAuthorized();
        }
        _revokeRole(ROLE_ADMIN, owner());
        _transferOwnership(msg.sender);
        _grantRole(ROLE_ADMIN, msg.sender);
    }

    /**
     * @notice  Add Opal Tech Team role
     * @dev     This role will give you the right to add/remove role
     * @param   user address of the contract_ to grant role
     */
    function addOpalRole(address user) public onlyAdmin {
        _grantRole(ROLE_OPAL_TEAM, user);
    }

    /**
     * @notice  Remove Opal Tech Team role
     * @dev     Don't forget to remove the role before removing the user
     * @param   user address of the contract_ to revoke role
     */
    function removeOpalTechRole(address user) public onlyAdmin {
        _revokeRole(ROLE_OPAL_TEAM, user);
    }

    /**
     * @notice  Add role
     * @dev     This role will give you the right to add/remove role
     * @param   user address of the contract_ to grant role
     */
    function addRole(bytes32 role, address user) public onlyOpalTeam {
        _grantRole(role, user);
    }

    /**
     * @notice  Remove role
     * @dev     Don't forget to remove the role before removing the user
     * @param   user address of the contract_ to revoke role
     */
    function removeRole(bytes32 role, address user) public onlyOpalTeam {
        _revokeRole(role, user);
    }

    /**
     * @notice  Get Owner
     * @return  address
     */
    function getOwner() public view returns (address) {
        return owner();
    }

    /**
     * @notice  Check Role
     * @param   role role to check
     * @param   user address of the contract_ to check
     * @return  bool
     */
    function checkRole(bytes32 role, address user) public view returns (bool) {
        return hasRole(role, user);
    }
}
