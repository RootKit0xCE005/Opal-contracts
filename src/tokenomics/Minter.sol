// SPDX-License-Identifier: MIT
pragma solidity >=0.8.16;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ILiquidityGauge} from "src/interfaces/Gauge/ILiquidityGauge.sol";
import {IGaugeController} from "src/interfaces/Gauge/IGaugeController.sol";

import {
    SCALED_ONE,
    INITIAL_MINTER_RATE,
    RATE_REDUCTION_COEFFICIENT,
    INFLATION_DELAY,
    RATE_REDUCTION_TIME
} from "src/utils/constants.sol";

contract Minter {
    using SafeERC20 for IERC20;

    // Storage

    int128 public miningEpoch;
    uint256 public startEpochTime;
    uint256 public startEpochSupply;
    uint256 public rate;

    uint256 public mintedSupply;

    address public immutable token;
    address public immutable controller;

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

    // Events

    event Minted(address indexed recipient, address indexed gauge, uint256 amount);

    event UpdateMiningParameters(uint256 time, uint256 rate, uint256 supply);

    // Constructor

    constructor(address token_, address controller_) {
        token = token_;
        controller = controller_;

        startEpochTime = block.timestamp + INFLATION_DELAY - RATE_REDUCTION_TIME;
        miningEpoch = -1;
        startEpochSupply = 0;
    }

    // View methods

    /**
     * @notice  Available supply
     * @return  uint256  .
     */
    function availableSupply() external view returns (uint256) {
        return _availableSupply();
    }

    /**
     * @notice  Mintable in timeframe
     * @param   start  beginning of timeframe.
     * @param   end  end of timeframe.
     * @return  uint256  .
     */
    function mintableInTimeframe(uint256 start, uint256 end) external view returns (uint256) {
        return _mintableInTimeframe(start, end);
    }

    // State-Changing Functions

    /**
     * @notice  Mint for gauge
     * @param   gauge  gauge to mint for.
     */
    function mint(address gauge) external {
        _mintFor(gauge, msg.sender);
    }

    /**
     * @notice  Mint for multiple gauges
     * @param   gauges  gauges to mint for.
     */
    function mintMultiple(address[] calldata gauges) external {
        uint256 length = gauges.length;
        for (uint256 i; i < length; i++) {
            if (gauges[i] == address(0)) continue;
            _mintFor(gauges[i], msg.sender);
        }
    }

    /**
     * @notice  Mint for gauge
     * @param   gauge  gauge to mint for.
     * @param   account  account to mint for.
     */
    function mintFor(address gauge, address account) external {
        if (allowedMinterProxy[msg.sender][account]) {
            _mintFor(gauge, account);
        }
    }

    /**
     * @notice  Mint for multiple gauges
     * @dev     This function is only callable by the minter proxy
     */
    function updateMiningParameters() external {
        if (block.timestamp < startEpochTime + RATE_REDUCTION_TIME) revert CannotUpdate();
        _updateMiningParameters();
    }

    /**
     * @notice  Start epoch time write
     * @return  uint256  .
     */
    function startEpochTimeWrite() public returns (uint256) {
        uint256 _startEpochTime = startEpochTime;
        if (block.timestamp >= startEpochTime + RATE_REDUCTION_TIME) {
            _updateMiningParameters();
        }
        return _startEpochTime;
    }

    /**
     * @notice  Future epoch time write
     * @return  uint256  .
     */
    function futureEpochTimeWrite() public returns (uint256) {
        uint256 _startEpochTime = startEpochTime;
        if (block.timestamp >= startEpochTime + RATE_REDUCTION_TIME) {
            _updateMiningParameters();
            return startEpochTime + RATE_REDUCTION_TIME;
        }
        return _startEpochTime + RATE_REDUCTION_TIME;
    }

    /**
     * @notice  Toggle approved mint
     * @param   minter  .
     */
    function toggleApprovedMint(address minter) external {
        allowedMinterProxy[minter][msg.sender] = !allowedMinterProxy[minter][msg.sender];
    }

    // Internal Functions

    /**
     * @notice  Available supply
     * @return  uint256  .
     */
    function _availableSupply() internal view returns (uint256) {
        return startEpochSupply + ((block.timestamp - startEpochTime) * rate);
    }

    /**
     * @notice  Update mining parameters
     * @dev     This function is only callable by the minter proxy
     */
    function _updateMiningParameters() internal {
        uint256 _rate = rate;
        uint256 _startEpochSupply = startEpochSupply;

        startEpochTime += RATE_REDUCTION_TIME;
        miningEpoch += 1;

        if (_rate == 0) {
            _rate = INITIAL_MINTER_RATE;
        } else {
            _startEpochSupply += _rate * RATE_REDUCTION_TIME;
            startEpochSupply = _startEpochSupply;
            _rate = _rate * RATE_REDUCTION_COEFFICIENT / SCALED_ONE;
        }

        rate = _rate;

        emit UpdateMiningParameters(startEpochTime, _rate, _startEpochSupply);
    }

    /**
     * @notice  Mintable in timeframe
     * @param   start  mintable timeframe start.
     * @param   end  mintable timeframe end.
     * @return  uint256  .
     */
    function _mintableInTimeframe(uint256 start, uint256 end) internal view returns (uint256) {
        if (start > end) revert InvalidParameters();

        uint256 toMint;
        uint256 currentEpochTime = startEpochTime;
        uint256 currentRate = rate;

        // If end is in the future epoch
        if (end > currentEpochTime + RATE_REDUCTION_TIME) {
            currentEpochTime += RATE_REDUCTION_TIME;
            currentRate = currentRate * RATE_REDUCTION_COEFFICIENT / SCALED_ONE;
        }

        if (end > currentEpochTime + RATE_REDUCTION_TIME) revert TimestampTooFarInFuture();

        for (uint256 i; i < 999;) {
            if (end >= currentEpochTime) {
                uint256 currentStart = start;
                uint256 currentEnd = end;
                if (currentEnd > currentEpochTime + RATE_REDUCTION_TIME) {
                    currentEnd = currentEpochTime + RATE_REDUCTION_TIME;
                }

                if (currentStart >= currentEpochTime + RATE_REDUCTION_TIME) {
                    // We should never get here but what if...
                    break;
                } else if (currentStart < currentEpochTime) {
                    currentStart = currentEpochTime;
                }

                toMint += currentRate * (currentEnd - currentStart);

                if (start >= currentEpochTime) break;
            }

            currentEpochTime = currentEpochTime - RATE_REDUCTION_TIME;
            currentRate = currentRate * RATE_REDUCTION_COEFFICIENT / SCALED_ONE;

            unchecked {
                ++i;
            }
        }

        return toMint;
    }

    /**
     * @notice  Mint for gauge and transfer to account
     * @param   gauge  address of the gauge
     * @param   account  address of the account
     */
    function _mintFor(address gauge, address account) internal {
        if (IGaugeController(controller).getGaugeType(gauge) == 0) revert GaugeNotAdded();

        if (block.timestamp >= startEpochTime + RATE_REDUCTION_TIME) {
            _updateMiningParameters();
        }

        ILiquidityGauge(gauge).userCheckpoint(account);
        uint256 totalMint = ILiquidityGauge(gauge).integrateFraction(account);
        uint256 toMintAmount = totalMint - minted[account][gauge];

        uint256 _newMintedSupply = mintedSupply + toMintAmount;
        if (_newMintedSupply > _availableSupply()) revert ExceedsAllowedSupply();

        if (toMintAmount > 0) {
            minted[account][gauge] = totalMint;
            mintedSupply = _newMintedSupply;

            IERC20(token).safeTransfer(account, toMintAmount);

            emit Minted(account, gauge, toMintAmount);
        }
    }
}
