// SPDX-License-Identifier: MIT
pragma solidity >=0.8.16;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ILiquidityGauge} from "src/interfaces/Gauge/ILiquidityGauge.sol";
import {IGaugeController} from "src/interfaces/Gauge/IGaugeController.sol";
import {EscrowedToken} from "./EscrowedToken.sol";
import {
    MINTER_ESCROW_RATE,
    RATE_END_TIMESTAMP,
    INFLATION_DELAY,
    ROLE_OPAL_TEAM
} from "src/utils/constants.sol";
import {RegistryAccess} from "src/utils/RegistryAccess.sol";

contract MinterEscrow {
    using SafeERC20 for IERC20;

    // Storage

    uint256 public startDistribution;

    uint256 public mintedSupply;

    address public immutable token;
    address public immutable escrow;
    address public immutable controller;
    RegistryAccess public immutable registryAccess;

    // user -> gauge -> value
    mapping(address => mapping(address => uint256)) public minted;

    // minter -> user -> can mint for user
    mapping(address => mapping(address => bool)) public allowedMinterProxy;

    // Errors

    error ExceedsAllowedSupply();
    error CannotUpdate();
    error InvalidParameters();
    error TimestampTooFarInFuture();
    error GaugeNotAdded();
    error NotAuthorized();

    // Events
    event Minted(address indexed recipient, address indexed gauge, uint256 amount);

    // Modifiers
    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) revert NotAuthorized();
        _;
    }

    // Constructor
    constructor(address token_, address _escrow, address controller_, address _registryAccess) {
        token = token_;
        escrow = _escrow;
        controller = controller_;
        registryAccess = RegistryAccess(_registryAccess);

        IERC20(token).approve(escrow, type(uint256).max);

        startDistribution = block.timestamp + INFLATION_DELAY;
    }

    // View methods

    /**
     * @notice  Get available supply
     * @return  uint256  Available supply
     */
    function availableSupply() external view returns (uint256) {
        if (block.timestamp < startDistribution) return 0;
        return _availableSupply();
    }

    /**
     * @notice  Get the mintable amount in the timeframe
     * @param   start  Start time
     * @param   end  End time
     * @return  uint256  .
     */
    function mintableInTimeframe(uint256 start, uint256 end) external view returns (uint256) {
        return _mintableInTimeframe(start, end);
    }

    /**
     * @notice  Get rate
     * @return  uint256  .
     */
    function rate() external view returns (uint256) {
        if (block.timestamp >= startDistribution + RATE_END_TIMESTAMP) return 0;
        return MINTER_ESCROW_RATE;
    }

    /**
     * @notice  Get distribution end
     * @return  uint256  .
     */
    function distributionEnd() external view returns (uint256) {
        return startDistribution + RATE_END_TIMESTAMP;
    }

    // State-Changing Functions

    /**
     * @notice  Update approve
     * @param   _approve  New approve
     */
    function updateApprove(uint256 _approve) external onlyOpalTeam {
        IERC20(token).approve(escrow, _approve);
    }

    /**
     * @notice  Mint for gauge
     * @param   gauge Gauge to mint for
     */
    function mint(address gauge) external {
        _mintFor(gauge, msg.sender);
    }

    /**
     * @notice  Mint for multiple gauges
     * @param   gauges  Gauges to mint for
     */
    function mintMultiple(address[] calldata gauges) external {
        _mintMultipleFor(gauges, msg.sender);
    }

    /**
     * @notice  Mint for gauge
     * @param   gauge  The address of the gauge
     * @param   account  Account to mint for
     */
    function mintFor(address gauge, address account) external {
        if (allowedMinterProxy[msg.sender][account]) {
            _mintFor(gauge, account);
        }
    }

    /**
     * @notice  Mint for multiple gauges
     * @param   gauges  The addresses of the gauges
     * @param   account  Account to mint for
     */
    function mintMultipleFor(address[] calldata gauges, address account) external {
        if (allowedMinterProxy[msg.sender][account]) {
            _mintMultipleFor(gauges, account);
        }
    }

    // Internal Functions

    /**
     * @notice  Available supply
     * @return  uint256  .
     */
    function _availableSupply() internal view returns (uint256) {
        return (block.timestamp - startDistribution) * MINTER_ESCROW_RATE;
    }

    /**
     * @notice  Set minter proxy
     */
    function setMinterProxy(address minter, bool canMintFor) external {
        allowedMinterProxy[minter][msg.sender] = canMintFor;
    }

    /**
     * @notice  Mintable in timeframe
     * @param   start  beginning of timeframe.
     * @param   end  end of timeframe.
     * @return  uint256  .
     */
    function _mintableInTimeframe(uint256 start, uint256 end) internal view returns (uint256) {
        if (start > end) revert InvalidParameters();

        if (start < startDistribution) start = startDistribution;

        return (end - start) * MINTER_ESCROW_RATE;
    }

    /**
     * @notice  Mint for gauge
     * @param   gauge  The address of the gauge
     * @param   account  Account to mint for
     */
    function _mintFor(address gauge, address account) internal {
        uint256 toMintAmount = _prepareGaugeMint(gauge, account);

        if (toMintAmount > 0) {
            EscrowedToken(escrow).mint(toMintAmount, account, block.timestamp);
            emit Minted(account, gauge, toMintAmount);
        }
    }

    /**
     * @notice  Prepare gauge mint
     * @param   gauge  The address of the gauge
     * @param   account  Account to mint for
     */
    function _prepareGaugeMint(address gauge, address account) internal returns (uint256) {
        if (IGaugeController(controller).getGaugeType(gauge) == 0) revert GaugeNotAdded();

        ILiquidityGauge(gauge).userCheckpoint(account);
        uint256 totalMint = ILiquidityGauge(gauge).integrateFractionBoosted(account);
        uint256 toMintAmount = totalMint - minted[account][gauge];
        uint256 _newMintedSupply = mintedSupply + toMintAmount;
        if (_newMintedSupply > _availableSupply()) revert ExceedsAllowedSupply();
        if (toMintAmount > 0) {
            minted[account][gauge] = totalMint;
            mintedSupply = _newMintedSupply;
        }
        return toMintAmount;
    }

    /**
     * @notice  Mint for multiple gauges
     * @param   gauges  The addresses of the gauges
     * @param   account  Account to mint for
     */
    function _mintMultipleFor(address[] memory gauges, address account) internal {
        uint256 totalMintAmount;
        uint256 length = gauges.length;

        for (uint256 i; i < length;) {
            uint256 toMintAmount = _prepareGaugeMint(gauges[i], account);

            if (toMintAmount > 0) {
                totalMintAmount += toMintAmount;
                emit Minted(account, gauges[i], toMintAmount);
            }

            unchecked {
                ++i;
            }
        }

        EscrowedToken(escrow).mint(totalMintAmount, account, block.timestamp);
    }
}
