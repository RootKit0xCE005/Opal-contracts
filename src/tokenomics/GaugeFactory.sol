// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ILiquidityGauge} from "src/interfaces/Gauge/ILiquidityGauge.sol";
import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";
import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";
import {CONTRACT_REGISTRY_ACCESS, ROLE_OPAL_TEAM} from "src/utils/constants.sol";
import "../../lib/forge-std/src/console.sol"; 

contract GaugeFactory {
    // Storage
    IRegistryContract public registryContract;
    IRegistryAccess public registryAccess;

    address public implementation;

    mapping(address => bool) public isFactoryGauge;
    mapping(address => address) public gaugeToLpToken;
    mapping(address => address) public lpTokenToGauge;

    // Event
    event NewGauge(address indexed lpToken, address indexed gauge);
    event NewImplementation(address indexed implementation);

    // Errors
    error AddressZero();
    error NotAuthorized();

    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) revert NotAuthorized();
        _;
    }

    // Constructor
    constructor(address _implementation, address _registryContract) {
        implementation = _implementation;
        registryContract = IRegistryContract(_registryContract);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));

        emit NewImplementation(_implementation);
    }

    // State-changing functions

    /**
     * @notice  Deploy new liquidity gauge
     * @param   lpToken  address of the lpToken
     * @return  address  address of the new liquidity gauge
    */
    // @audit bad_bob could forn-run another user i.e:
    // bad_bob could make user deposit in wrong LiquidityGauge
    // since alice can calculate the next gauge address because clone uses create so it creates new contract based on nonce. 
    // bad_bob sees alice transaction in mempool so he send same transaction but with different lpToken address
    // now the same address with nonce 10 for example is created this is the same address alice calculated but with different lpToken
    // so now if alice wants to transfer or approve she endeed up approving or transfering another tokens.
    // because of this function can be called from another contract so the other contract can predict the gauge address
    // so alice will automate the deploy and approve or transfer process.
    function deployGauge(address lpToken) external returns(address) {
        if (lpToken == address(0)) revert AddressZero();

        address gauge = Clones.clone(implementation);
        ILiquidityGauge(gauge).initialize(lpToken);

        // @audit Storing these values in mapping has no Purpose 
        // not used in checking any where. the just consume gas. 
        isFactoryGauge[gauge] = true;
        gaugeToLpToken[gauge] = lpToken;
        lpTokenToGauge[lpToken] = gauge;

        emit NewGauge(lpToken, gauge);
        return gauge;
    }

    // Admin functions

    /**
     * @notice  Set new implementation
     * @param   _implementation  address of the new implementation
    */
    function setImplementation(address _implementation) external onlyOpalTeam {
        implementation = _implementation;
        emit NewImplementation(_implementation);
    }
}
