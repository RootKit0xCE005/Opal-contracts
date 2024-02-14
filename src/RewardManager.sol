// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IAuraPool} from "src/interfaces/Aura/IAuraPool.sol";
import {IOmnipool} from "src/interfaces/Omnipool/IOmnipool.sol";
import {IRewardManager} from "src/interfaces/Reward/IRewardManager.sol";
import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";
import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";
import {
    REWARD_FEES,
    SCALED_ONE,
    ROLE_OPAL_TEAM,
    CONTRACT_BAL_TOKEN,
    CONTRACT_AURA_TOKEN,
    CONTRACT_GEM_TOKEN,
    CONTRACT_OPAL_TREASURY,
    CONTRACT_VOTE_LOCKER
} from "src/utils/constants.sol";

interface IRewardToken {
    function rewardToken() external view returns (address);
}

interface IBaseToken {
    function baseToken() external view returns (address);
}

/**
 * @title RewardManager
 */
contract RewardManager is IRewardManager {
    using SafeERC20 for IERC20;

    // --------------------------- STRUCTS ---------------------------
    struct RewardMeta {
        uint256 earnedIntegral;
        uint256 lastEarned;
        mapping(address => uint256) accountIntegral;
        mapping(address => uint256) accountShare;
    }

    // --------------------------- CONSTANTS ---------------------------
    uint256 public constant REWARD_TOKENS_LENGTH = 3;

    // --------------------------- IMMUTABLES --------------------------
    address public immutable BAL;
    address public immutable AURA;
    address public immutable GEM;

    IERC20 public immutable BALToken;
    IERC20 public immutable AURAToken;
    IERC20 public immutable GEMToken;

    IRegistryAccess public immutable registryAccess;
    IRegistryContract public immutable registryContract;

    // --------------------------- VARIABLES ---------------------------
    IOmnipool public omnipool;

    RewardMeta public BALMeta;
    RewardMeta public AURAMeta;
    RewardMeta public GEMMeta;

    uint256 public protocolFeesBALBalance = 0;
    uint256 public protocolFeesAURABalance = 0;

    uint256 private _extraRewardTokensLength;
    address[] private _extraRewardTokens;
    mapping(address => bool) private _extraRewardTokensMap;

    // --------------------------- ERROR ---------------------------
    error OutOfBounds();
    error NotAuthorized();

    // --------------------------- CONSTRUCTOR ---------------------------
    constructor(address _omnipool, address _registryAccess, address _registryContract) {
        omnipool = IOmnipool(_omnipool);
        registryContract = IRegistryContract(_registryContract);
        registryAccess = IRegistryAccess(_registryAccess);

        BAL = registryContract.getContract(CONTRACT_BAL_TOKEN);
        AURA = registryContract.getContract(CONTRACT_AURA_TOKEN);
        GEM = registryContract.getContract(CONTRACT_GEM_TOKEN);

        BALToken = IERC20(BAL);
        AURAToken = IERC20(AURA);
        GEMToken = IERC20(GEM);
    }

    // --------------------------- EVENTS ---------------------------
    /// @notice Emitted when the omnipool rewards are updated
    event RewardUpdated(uint256 bal, uint256 aura, uint256 gem);
    /// @notice Emitted when a user claim his rewards
    event RewardClaimed(address indexed user, uint256 bal, uint256 aura, uint256 gem);
    /// @notice Emitted when a token is swapped for another SCALED_ONE
    event RewardSwapped(
        address indexed tokenIn, uint256 amountIn, address indexed tokenOut, uint256 amountOut
    );
    /// @notice Emitted when underlying pool reward tokens are claimed
    event UnderlyingPoolRewardClaimed(
        address indexed underlyingPool, address indexed rewardToken, uint256 amount
    );

    // --------------------------- MODIFIERS ---------------------------
    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) {
            revert NotAuthorized();
        }
        _;
    }

    // --------------------------- PUBLIC FUNCTIONS ---------------------------

    // --------------------------- EXTERNAL FUNCTIONS ---------------------------
    // ------------- VIEW FUNCTIONS -------------
    /**
     * @notice Return an extra reward tokens by index
     * @return (address) : The address of the extra reward token
     */
    function getExtraRewardToken(uint256 index) external view returns (address) {
        if (index >= _extraRewardTokensLength) revert OutOfBounds();
        return _extraRewardTokens[index];
    }

    /**
     * @notice Return the reward token address by index
     * @return (address) : The address of the reward token
     */
    function getRewardToken(uint256 index) external view returns (address) {
        if (index == 0) return BAL;
        else if (index == 1) return AURA;
        else if (index == 2) return GEM;
        else revert OutOfBounds();
    }

    // ------------- FUNCTIONS -------------
    /**
     * @notice Claim the rewards of the user
     * @dev This function is called by the user to claim his rewards, it updates the state of the omnipool and claim the pending rewards of the underlying pools
     * @return bool : true if the claim is successful
     */
    function claimEarnings() external returns (bool) {
        // Update the state of the pool
        _updateUserState(msg.sender);

        // Get the share amounts
        uint256 balAmount = BALMeta.accountShare[msg.sender];
        uint256 auraAmount = AURAMeta.accountShare[msg.sender];
        uint256 gemAmount = GEMMeta.accountShare[msg.sender];

        // TODO: Particular case : amount is > at the balance of the pool, we could try to optimise gas cost by claiming only when the amount is > to the balance of the RM
        // But it would require to be aware of the exact amount of rewards earned by the omnipool (actually we just claim it each time)
        // But it could be very benefic for the users because we could imagine that we could automate the expensive part of the execution and pay from in another way
        // So the users wouldn't have to pay all this extra execution cost if they rewards are already available in the RM, we could also allow it to pay for this extra execution if it really wants to claim the rewards

        // Set the share balances to 0
        BALMeta.accountShare[msg.sender] = 0;
        AURAMeta.accountShare[msg.sender] = 0;
        GEMMeta.accountShare[msg.sender] = 0;

        // Allowance
        // Transfer the rewards to the user
        if (balAmount > 0) {
            omnipool.approveForRewardManager(BAL, balAmount);
            BALToken.safeTransferFrom(address(omnipool), msg.sender, balAmount);
        }
        if (auraAmount > 0) {
            omnipool.approveForRewardManager(AURA, auraAmount);
            AURAToken.safeTransferFrom(address(omnipool), msg.sender, auraAmount);
        }
        if (gemAmount > 0) {
            omnipool.approveForRewardManager(GEM, gemAmount);
            GEMToken.safeTransferFrom(address(omnipool), msg.sender, gemAmount);
        }

        // Emit the event
        emit RewardClaimed(msg.sender, balAmount, auraAmount, gemAmount);

        return true;
    }

    /**
     * @notice Extract the reward tokens informations from the underlying pools
     * @dev This function iterates over the underlying pools and extract the reward tokens informations, it also updates the rewardTokens array, we should call this function each time the omnipool is updated
     * @custom:conditions : /!\ For this method we suppose that BAL token is always the underlying pool reward token AND BAL token is not in the extra rewards tokens
     */
    function setExtraRewardTokens() external returns (uint256) {
        if (_extraRewardTokensLength > 0) {
            // Clean the mapping
            for (uint256 i = 0; i < _extraRewardTokensLength;) {
                _extraRewardTokensMap[_extraRewardTokens[i]] = false;
                unchecked {
                    ++i;
                }
            }
        }

        _extraRewardTokens = new address[](0);
        _extraRewardTokensLength = 0;

        uint8 underlyingPoolLength = omnipool.getUnderlyingPoolsLength();
        for (uint8 i = 0; i < underlyingPoolLength;) {
            address underlyingPool = omnipool.getUnderlyingPool(i);
            IAuraPool auraPool = IAuraPool(underlyingPool);
            // For each extra reward token, we add it to the rewardTokens array
            uint256 extraRewardsLength = auraPool.extraRewardsLength();
            for (uint256 j = 0; j < extraRewardsLength;) {
                address extraReward = auraPool.extraRewards(j);
                address extraRewardToken = _virtualBalanceRewardAddrToTokenAddr(extraReward);

                // Check if the token is SCALED_ONE of the reward tokens
                if (
                    extraRewardToken != BAL && extraRewardToken != AURA && extraRewardToken != GEM
                        && !_extraRewardTokensMap[extraRewardToken]
                ) {
                    // Add the reward token to the end of the list, it's a new SCALED_ONE
                    _extraRewardTokensMap[extraRewardToken] = true;
                    _extraRewardTokens.push(extraRewardToken);
                    unchecked {
                        ++_extraRewardTokensLength;
                    }
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        return _extraRewardTokensLength;
    }

    // --------------------------- INTERNAL FUNCTIONS ---------------------------
    // ------------- VIEW FUNCTIONS -------------
    /**
     * @notice Get the reward balances of the omnipool
     * @dev This function returns the balance of the reward tokens of the omnipool
     * @return (uint256, uint256, uint256) : the amount of BAL, AURA and GEM tokens in the omnipool
     */
    function _getRewardBalances() internal view returns (uint256, uint256, uint256) {
        uint256 balBalance = IERC20(BAL).balanceOf(address(omnipool));
        uint256 auraBalance = IERC20(AURA).balanceOf(address(omnipool));
        uint256 gemBalance = IERC20(GEM).balanceOf(address(omnipool));

        return (balBalance, auraBalance, gemBalance);
    }

    /**
     * @dev This function extract from an Aura.Finance contract the ERC20 token address
     * @param rewardAddr (address) : The address of the reward contract
     * @return (address) : An ERC20 token address
     */
    function _virtualBalanceRewardAddrToTokenAddr(address rewardAddr)
        internal
        view
        returns (address)
    {
        return IBaseToken(IRewardToken(rewardAddr).rewardToken()).baseToken();
    }

    // ------------- FUNCTIONS -------------
    /**
     * @notice Update the state of the pool and the rewards of the user
     */
    function _updateUserState(address _account) internal {
        // Get the user LP balance
        uint256 deposited = omnipool.getUserTotalDeposit(_account);

        // Update the pool state, claim the rewards and transfer them to the RewardManager
        _updateOmnipoolState();

        // Update the user's rewards
        _updateRewards(_account, deposited);
    }
    /**
     * @notice Update the rewards of the user
     * @dev This function updates the rewards of the user, it updates the earnedIntegral and lastEarned of the RewardMeta for each reward token
     */

    function _updateRewards(address account, uint256 balance) internal {
        uint256 BALIntegralDelta = BALMeta.earnedIntegral - BALMeta.accountIntegral[account];
        uint256 balShare = (balance * BALIntegralDelta) / SCALED_ONE;
        BALMeta.accountShare[account] += balShare;
        BALMeta.accountIntegral[account] = BALMeta.earnedIntegral;

        uint256 AURAIntegralDelta = AURAMeta.earnedIntegral - AURAMeta.accountIntegral[account];
        uint256 auraShare = (balance * AURAIntegralDelta) / SCALED_ONE;
        AURAMeta.accountShare[account] += auraShare;
        AURAMeta.accountIntegral[account] = AURAMeta.earnedIntegral;

        uint256 GEMIntegralDelta = GEMMeta.earnedIntegral - GEMMeta.accountIntegral[account];
        uint256 gemShare = (balance * GEMIntegralDelta) / SCALED_ONE;
        GEMMeta.accountShare[account] += gemShare;
        GEMMeta.accountIntegral[account] = GEMMeta.earnedIntegral;
    }

    /**
     * @notice Update the state of the omnipool
     * @dev This function updates the state of the omnipool, it claims the rewards and swap the other tokens for GEM tokens, it also updates the earnedIntegral and lastEarned of the RewardMeta
     */
    function _updateOmnipoolState() internal {
        (uint256 earnedBAL, uint256 earnedAURA, uint256 earnedGEM) = _claimOmnipoolRewards();

        // Apply fees
        uint256 protocolFeesBAL = earnedBAL * REWARD_FEES / SCALED_ONE;
        uint256 protocolFeesAURA = earnedAURA * REWARD_FEES / SCALED_ONE;

        protocolFeesBALBalance += protocolFeesBAL;
        protocolFeesAURABalance += protocolFeesAURA;

        earnedBAL -= protocolFeesBAL;
        earnedAURA -= protocolFeesAURA;

        uint256 totalDeposited = omnipool.getTotalDeposited();

        if (totalDeposited > 0) {
            BALMeta.earnedIntegral += (earnedBAL * SCALED_ONE) / totalDeposited;
            BALMeta.lastEarned += earnedBAL;

            AURAMeta.earnedIntegral += (earnedAURA * SCALED_ONE) / totalDeposited;
            AURAMeta.lastEarned += earnedAURA;

            GEMMeta.earnedIntegral += (earnedGEM * SCALED_ONE) / totalDeposited;
            GEMMeta.lastEarned += earnedGEM;
        }

        _claimProtocolFees();

        // Emit the event
        emit RewardUpdated(earnedBAL, earnedAURA, earnedGEM);
    }

    /**
     * @notice Claim the protocol fees
     */
    function _claimProtocolFees() internal {
        uint256 balToClaim = protocolFeesBALBalance;
        uint256 auraToClaim = protocolFeesAURABalance;

        protocolFeesBALBalance = 0;
        protocolFeesAURABalance = 0;

        address omnipoolAddr = address(omnipool);

        omnipool.approveForRewardManager(BAL, balToClaim);
        omnipool.approveForRewardManager(AURA, auraToClaim);

        uint256 balTreasuryPart = balToClaim / 2;
        uint256 auraTreasuryPart = auraToClaim / 2;

        address opalTreasury = registryContract.getContract(CONTRACT_OPAL_TREASURY);
        address voteLocker = registryContract.getContract(CONTRACT_VOTE_LOCKER);

        BALToken.safeTransferFrom(omnipoolAddr, opalTreasury, balTreasuryPart);
        AURAToken.safeTransferFrom(omnipoolAddr, opalTreasury, auraTreasuryPart);

        BALToken.safeTransferFrom(omnipoolAddr, voteLocker, balToClaim - balTreasuryPart);
        AURAToken.safeTransferFrom(omnipoolAddr, voteLocker, auraToClaim - auraTreasuryPart);
    }

    /**
     * @notice Claim the rewards of the omnipool
     * @dev This function iterates over the underlying pools and claim the rewards, it also swap the other tokens for GEM tokens
     * @return (uint256, uint256, uint256) : the amount of BAL, AURA and GEM tokens earned (initial balance - final balance)
     */
    function _claimOmnipoolRewards() internal returns (uint256, uint256, uint256) {
        uint8 underlyingPoolLength = omnipool.getUnderlyingPoolsLength();

        (uint256 initialBALBalance, uint256 initialAURABalance, uint256 initialGEMBalance) =
            _getRewardBalances();

        // Claim the rewards from the underlying pools and swap the other tokens for GEM tokens
        for (uint8 i = 0; i < underlyingPoolLength;) {
            _claimUnderlyingPoolRewards(i);
            unchecked {
                ++i;
            }
        }

        // Swap extra-rewards for GEMS
        _swapExtraReward();

        (uint256 BALBalance, uint256 AURABalance, uint256 GEMBalance) = _getRewardBalances();

        return (
            BALBalance - initialBALBalance,
            AURABalance - initialAURABalance,
            GEMBalance - initialGEMBalance
        );
    }

    function _claimUnderlyingPoolRewards(uint8 _poolIndex) internal {
        // Claim the rewards from the underlying pool
        bool success =
            IAuraPool(omnipool.getUnderlyingPool(_poolIndex)).getReward(address(omnipool), true);
        if (success) {
            emit UnderlyingPoolRewardClaimed(
                omnipool.getUnderlyingPool(_poolIndex),
                BAL,
                IERC20(BAL).balanceOf(address(omnipool))
            );
        }
    }

    /**
     * @notice Swap all extra rewards into GEM
     * @dev This function swap the extra rewards for GEM tokens, it calls the omnipool to perform the swap
     */
    function _swapExtraReward() internal {
        for (uint256 j = 0; j < _extraRewardTokensLength;) {
            address extraRewardToken = _extraRewardTokens[j];
            // ExtraRewardToken is not necessary up to date if the underlying pool reward token changed and the RM hasn't been updated with setExtraRewardTokens
            uint256 extraRewardBalance = IERC20(extraRewardToken).balanceOf(address(omnipool));
            if (extraRewardBalance > 0) {
                bool success = omnipool.swapForGem(extraRewardToken, extraRewardBalance);
                if (success) {
                    emit RewardSwapped(
                        extraRewardToken,
                        extraRewardBalance,
                        GEM,
                        IERC20(GEM).balanceOf(address(omnipool))
                    );
                }
            }
            unchecked {
                ++j;
            }
        }
    }
}
