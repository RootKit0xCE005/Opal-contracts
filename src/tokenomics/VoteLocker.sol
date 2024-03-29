// SPDX-License-Identifier: MIT
pragma solidity >=0.8.16;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IVoteLocker} from "src/interfaces/IVoteLocker.sol";

import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";
import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";
import {AuraMath, AuraMath32, AuraMath48, AuraMath208} from "src/utils/AuraMath.sol";

import {ROLE_OPAL_TEAM, CONTRACT_REGISTRY_ACCESS, WEEK} from "src/utils/constants.sol";

/**
 * @title   VoteLocker
 * @author  ConvexFinance & Aura Finance, modified by Paladin
 * @notice  Effectively allows for rolling 16 week lockups of a token, and provides balances available
 *          at each epoch (1 week). Also receives reward tokens and redistributes
 *          to depositors.
 * @dev     Individual and delegatee vote power lookups both use independent accounting mechanisms.
 *          Modified by Paladin to remove the direct staking of a specific reward token (see extension of
 *          this contract), and to replace revert strings by custom Errors.
 */
contract VoteLocker is ReentrancyGuard, IVoteLocker {
    using AuraMath for uint256;
    using AuraMath208 for uint208;
    using AuraMath48 for uint48;
    using AuraMath32 for uint32;
    using SafeERC20 for IERC20;

    /* ==========     STRUCTS     ========== */

    struct RewardData {
        /// Timestamp for current period finish
        uint32 periodFinish;
        /// Last time any user took action
        uint32 lastUpdateTime;
        /// RewardRate for the rest of the period
        uint96 rewardRate;
        /// Ever increasing rewardPerToken rate, based on % of total supply
        uint96 rewardPerTokenStored;
    }

    struct UserData {
        uint128 rewardPerTokenPaid;
        uint128 rewards;
    }

    struct EarnedData {
        address token;
        uint256 amount;
    }

    struct Balances {
        uint208 locked;
        uint48 nextUnlockIndex;
    }

    struct DelegateeCheckpoint {
        uint208 votes;
        uint48 epochStart;
    }

    /* ========== STATE VARIABLES ========== */

    IRegistryContract public registryContract;
    IRegistryAccess public registryAccess;

    // Rewards
    address[] public rewardTokens;
    mapping(address => uint256) public queuedRewards;
    uint256 public constant newRewardRatio = 830;
    // Core reward data
    mapping(address => RewardData) public rewardData;
    // Reward token -> distributor -> is approved to add rewards
    mapping(address => mapping(address => bool)) public rewardDistributors;
    // User -> reward token -> amount
    mapping(address => mapping(address => UserData)) public userData;
    // Duration that rewards are streamed over
    uint256 public constant rewardsDuration = 86_400 * 7;
    // Duration of lock/earned penalty period
    uint256 public constant lockDuration = rewardsDuration * 17;

    // Balances
    // Supplies and historic supply
    uint256 public lockedSupply;
    // Epochs contains only the tokens that were locked at that epoch, not a cumulative supply
    Epoch[] public _epochs;
    // Mappings for balance data
    mapping(address => Balances) public balances;
    mapping(address => LockedBalance[]) public userLocks;

    // Voting
    // Stored delegations
    mapping(address => address) private _delegates;
    // Checkpointed votes
    mapping(address => DelegateeCheckpoint[]) private _checkpointedVotes;
    // Delegatee balances (user -> unlock timestamp -> amount)
    mapping(address => mapping(uint256 => uint256)) public delegateeUnlocks;

    // Config
    // Blacklisted smart contract interactions
    mapping(address => bool) public blacklist;
    // Tokens
    IERC20 public immutable stakingToken;
    // Denom for calcs
    uint256 public constant denominator = 10_000;
    // Incentives
    uint256 public kickRewardPerEpoch = 100;
    uint256 public kickRewardEpochDelay = 3;
    // Shutdown
    bool public isShutdown = false;

    // Basic token data
    string private _name;
    string private _symbol;
    uint8 private immutable _decimals;

    /* ========== ERRORS ========== */

    error Blacklisted();
    error NotContract();
    error RewardAlreadyListed();
    error RewardNotListed();
    error InvalidRewardToken();
    error MaxRewardLength();
    error OverMaxRate();
    error MinDelay();
    error CannotWithdrawToken();
    error ContractShutdown();
    error NotShutdown();
    error ZeroAmount();
    error ArrayLengthMismatch();
    error NoBalanceLocked();
    error NoLocks();
    error NoExpiredLocks();
    error ZeroAddress();
    error SameAddress();
    error BlockNotMined();
    error FutureEpoch();
    error NotAuthorized();
    error RewardsTooBig();
    error RewardRateTooBig();
    error LockedSupplyTooLow();

    /* ========== EVENTS ========== */

    event DelegateChanged(
        address indexed delegator, address indexed fromDelegate, address indexed toDelegate
    );
    event DelegateCheckpointed(address indexed delegate);

    event Recovered(address _token, uint256 _amount);
    event RewardPaid(address indexed _user, address indexed _rewardsToken, uint256 _reward);
    event Staked(address indexed _user, uint256 _paidAmount, uint256 _lockedAmount);
    event Withdrawn(address indexed _user, uint256 _amount, bool _relocked);
    event KickReward(address indexed _user, address indexed _kicked, uint256 _reward);
    event RewardAdded(address indexed _token, uint256 _reward);

    event BlacklistModified(address account, bool blacklisted);
    event KickIncentiveSet(uint256 rate, uint256 delay);
    event Shutdown();

    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) revert NotAuthorized();
        _;
    }

    /**
     *
     *                 CONSTRUCTOR
     *
     */

    /**
     * @param _nameArg          Token name, simples
     * @param _symbolArg        Token symbol
     * @param _stakingToken     Token staked in this contract
     */
    constructor(
        string memory _nameArg,
        string memory _symbolArg,
        address _stakingToken,
        address _registryContract
    ) {
        _name = _nameArg;
        _symbol = _symbolArg;
        _decimals = 18;

        stakingToken = IERC20(_stakingToken);

        registryContract = IRegistryContract(_registryContract);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));

        uint256 currentEpoch = block.timestamp.div(rewardsDuration).mul(rewardsDuration);
        _epochs.push(Epoch({supply: 0, date: uint32(currentEpoch)}));
    }

    /**
     *
     *                 MODIFIER
     *
     */

    modifier updateReward(address _account) {
        {
            Balances storage userBalance = balances[_account];
            uint256 rewardTokensLength = rewardTokens.length;
            for (uint256 i = 0; i < rewardTokensLength;) {
                address token = rewardTokens[i];
                uint256 newRewardPerToken = _rewardPerToken(token);
                rewardData[token].rewardPerTokenStored = newRewardPerToken.to96();
                rewardData[token].lastUpdateTime =
                    _lastTimeRewardApplicable(rewardData[token].periodFinish).to32();
                if (_account != address(0)) {
                    userData[_account][token] = UserData({
                        rewardPerTokenPaid: newRewardPerToken.to128(),
                        rewards: _earned(_account, token, userBalance.locked).to128()
                    });
                }
                unchecked {
                    ++i;
                }
            }
        }
        _;
    }

    modifier notBlacklisted(address _sender, address _receiver) {
        if (blacklist[_sender]) revert Blacklisted();

        if (_sender != _receiver) {
            if (blacklist[_receiver]) revert Blacklisted();
        }

        _;
    }

    /**
     *
     *                 ADMIN
     *
     */

    /**
     * @notice  Modify blacklisted
     * @param   _account  account to modify
     * @param   _blacklisted  new blacklisted status
     */
    function modifyBlacklist(address _account, bool _blacklisted) external onlyOpalTeam {
        uint256 cs;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            cs := extcodesize(_account)
        }
        if (cs == 0) revert NotContract();

        blacklist[_account] = _blacklisted;
        emit BlacklistModified(_account, _blacklisted);
    }

    /**
     * @notice  Add reward to be distributed to stakers
     * @dev     Add a new reward token to be distributed to stakers
     * @param   _rewardsToken  address of the reward token
     * @param   _distributor  address of the distributor
     */
    function addReward(address _rewardsToken, address _distributor) external onlyOpalTeam {
        if (rewardData[_rewardsToken].lastUpdateTime != 0) revert RewardAlreadyListed();
        if (_rewardsToken == address(stakingToken)) revert InvalidRewardToken();
        if (rewardTokens.length >= 5) revert MaxRewardLength();

        rewardTokens.push(_rewardsToken);
        rewardData[_rewardsToken].lastUpdateTime = uint32(block.timestamp);
        rewardData[_rewardsToken].periodFinish = uint32(block.timestamp);
        rewardDistributors[_rewardsToken][_distributor] = true;
    }

    /**
     * @notice  Approve reward distributor
     * @dev     Modify approval for an address to call notifyRewardAmount
     * @param   _rewardsToken  address of the reward token
     * @param   _distributor  address of the distributor
     * @param   _approved  new approval status
     */
    function approveRewardDistributor(address _rewardsToken, address _distributor, bool _approved)
        external
        onlyOpalTeam
    {
        if (rewardData[_rewardsToken].lastUpdateTime == 0) revert RewardNotListed();
        rewardDistributors[_rewardsToken][_distributor] = _approved;
    }

    //set kick incentive
    /**
     * @notice  Set kick incentive
     * @dev     Set the kick incentive rate and delay
     * @param   _rate  The rate of the incentive
     * @param   _delay  The delay of the incentive
     */
    function setKickIncentive(uint256 _rate, uint256 _delay) external onlyOpalTeam {
        if (_rate > 500) revert OverMaxRate(); //max 5% per epoch
        if (_delay < 2) revert MinDelay(); //minimum 2 _epochs of grace
        kickRewardPerEpoch = _rate;
        kickRewardEpochDelay = _delay;

        emit KickIncentiveSet(_rate, _delay);
    }

    /**
     * @notice  Shutdown contract
     * @dev     Shutdown the contract. Unstake all tokens. Release all locks
     */
    function shutdown() external onlyOpalTeam {
        isShutdown = true;
        emit Shutdown();
    }

    /**
     * @notice  Recover ERC20
     * @dev     Added to support recovering LP Rewards from other systems such as BAL to be distributed to holders
     * @param   _tokenAddress  The address of the token contract
     * @param   _tokenAmount  The amount of token to transfer
     */
    function recoverERC20(address _tokenAddress, uint256 _tokenAmount, address _team)
        external
        onlyOpalTeam
    {
        if (_tokenAddress == address(stakingToken)) revert CannotWithdrawToken();
        if (rewardData[_tokenAddress].lastUpdateTime > 0) revert CannotWithdrawToken();

        IERC20(_tokenAddress).safeTransfer(_team, _tokenAmount);
        emit Recovered(_tokenAddress, _tokenAmount);
    }

    /**
     *
     *                 ACTIONS
     *
     */

    /**
     * @notice  Lock tokens
     * @dev     Locked tokens cannot be withdrawn for lockDuration and are eligible to receive stakingReward rewards
     * @param   _account  address of the account
     * @param   _amount  amount of tokens to lock
     */
    function lock(address _account, uint256 _amount) external nonReentrant updateReward(_account) {
        //pull tokens
        stakingToken.safeTransferFrom(msg.sender, address(this), _amount);

        //lock
        _lock(_account, _amount);
    }

    /**
     * @notice  Lock tokens
     * @param   _account  address of the account
     * @param   _amount  amount of tokens to lock
     */
    function _lock(address _account, uint256 _amount)
        internal
        notBlacklisted(msg.sender, _account)
    {
        if (_amount == 0) revert ZeroAmount();
        if (isShutdown) revert ContractShutdown();

        Balances storage bal = balances[_account];

        //must try check pointing epoch first
        _checkpointEpoch();

        //add user balances
        uint208 lockAmount = _amount.to208();
        bal.locked = bal.locked.add(lockAmount);

        //add to total supplies
        lockedSupply = lockedSupply.add(_amount);

        //add user lock records or add to current
        uint256 currentEpoch = block.timestamp.div(rewardsDuration).mul(rewardsDuration);
        uint256 unlockTime = currentEpoch.add(lockDuration);
        uint256 idx = userLocks[_account].length;
        if (idx == 0 || userLocks[_account][idx - 1].unlockTime < unlockTime) {
            userLocks[_account].push(
                LockedBalance({amount: lockAmount, unlockTime: uint32(unlockTime)})
            );
        } else {
            LockedBalance storage userL = userLocks[_account][idx - 1];
            userL.amount = userL.amount.add(lockAmount);
        }

        address delegatee = delegates(_account);
        if (delegatee != address(0)) {
            delegateeUnlocks[delegatee][unlockTime] += lockAmount;
            _checkpointDelegate(delegatee, lockAmount, 0);
        }

        //update epoch supply, epoch checkpointed above so safe to add to latest
        Epoch storage e = _epochs[_epochs.length - 1];
        e.supply = e.supply.add(lockAmount);

        emit Staked(_account, lockAmount, lockAmount);
    }

    // claim all pending rewards
    /**
     * @notice  Get all rewards
     * @dev     Claim all pending rewards
     * @param   _account  address of the account
     */
    function getReward(address _account) external {
        getReward(_account, false);
    }

    /**
     * @notice  Get all rewards
     * @dev     Claim all pending rewards
     * @param   _account  address of the account
     */
    function getReward(address _account, bool /*_stake*/ )
        public
        virtual
        nonReentrant
        updateReward(_account)
    {
        uint256 rewardTokensLength = rewardTokens.length;
        for (uint256 i; i < rewardTokensLength;) {
            address _rewardsToken = rewardTokens[i];
            uint256 reward = userData[_account][_rewardsToken].rewards;
            if (reward > 0) {
                userData[_account][_rewardsToken].rewards = 0;
                IERC20(_rewardsToken).safeTransfer(_account, reward);
                emit RewardPaid(_account, _rewardsToken, reward);
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice  Get all rewards
     * @param   _account  address of the account
     * @param   _skipIdx  array of id to skip reward tokens
     */
    function getReward(address _account, bool[] calldata _skipIdx)
        external
        nonReentrant
        updateReward(_account)
    {
        uint256 rewardTokensLength = rewardTokens.length;
        if (_skipIdx.length != rewardTokensLength) revert ArrayLengthMismatch();
        for (uint256 i; i < rewardTokensLength; i++) {
            if (_skipIdx[i]) continue;
            address _rewardsToken = rewardTokens[i];
            uint256 reward = userData[_account][_rewardsToken].rewards;
            if (reward > 0) {
                userData[_account][_rewardsToken].rewards = 0;
                IERC20(_rewardsToken).safeTransfer(_account, reward);
                emit RewardPaid(_account, _rewardsToken, reward);
            }
        }
    }

    /**
     * @notice  Checkpoint Epoch
     */
    function checkpointEpoch() external {
        _checkpointEpoch();
    }

    /**
     * @notice  Checkpoint Epoch
     * @dev     Insert a new epoch if needed. fill in any gaps
     */
    function _checkpointEpoch() internal {
        uint256 currentEpoch = block.timestamp.div(rewardsDuration).mul(rewardsDuration);

        //first epoch add in constructor, no need to check 0 length
        //check to add
        uint256 nextEpochDate = uint256(_epochs[_epochs.length - 1].date);
        if (nextEpochDate < currentEpoch) {
            while (nextEpochDate != currentEpoch) {
                nextEpochDate = nextEpochDate.add(rewardsDuration);
                _epochs.push(Epoch({supply: 0, date: uint48(nextEpochDate)}));
            }
        }
    }

    /**
     * @notice  Process expired locks
     * @dev     Withdraw/relock all currently locked tokens where the unlock time has passed
     * @param   _relock  relock or withdraw
     */
    function processExpiredLocks(bool _relock) external nonReentrant {
        _processExpiredLocks(msg.sender, _relock, msg.sender, 0);
    }

    /**
     * @notice  Process expired locks
     * @param   _account  address of the account
     */
    function kickExpiredLocks(address _account) external nonReentrant {
        //allow kick after grace period of 'kickRewardEpochDelay'
        _processExpiredLocks(_account, false, msg.sender, rewardsDuration.mul(kickRewardEpochDelay));
    }

    /**
     * @notice  Emergency withdraw
     * @dev     Withdraw without checkpointing or accruing any rewards, providing system is shutdown
     */
    function emergencyWithdraw() external nonReentrant {
        if (!isShutdown) revert NotShutdown();

        LockedBalance[] memory locks = userLocks[msg.sender];
        Balances storage userBalance = balances[msg.sender];

        uint256 amt = userBalance.locked;
        if (amt == 0) revert NoBalanceLocked();

        userBalance.locked = 0;
        userBalance.nextUnlockIndex = locks.length.to48();
        lockedSupply -= amt;

        emit Withdrawn(msg.sender, amt, false);

        stakingToken.safeTransfer(msg.sender, amt);
    }

    // Withdraw all currently locked tokens where the unlock time has passed
    /**
     * @notice  Process expired locks
     * @dev     Withdraw/relock all currently locked tokens where the unlock time has passed
     * @param   _account  address of the account
     * @param   _relock  relock or withdraw
     * @param   _rewardAddress  address of the reward token
     * @param   _checkDelay  delay to check for kick reward
     */
    function _processExpiredLocks(
        address _account,
        bool _relock,
        address _rewardAddress,
        uint256 _checkDelay
    ) internal updateReward(_account) {
        LockedBalance[] storage locks = userLocks[_account];
        Balances storage userBalance = balances[_account];
        uint208 locked;
        uint256 length = locks.length;
        uint256 reward = 0;
        uint256 expiryTime = _checkDelay == 0 && _relock
            ? block.timestamp.add(rewardsDuration)
            : block.timestamp.sub(_checkDelay);
        if (length == 0) revert NoLocks();
        // e.g. now = 16
        // if contract is shutdown OR latest lock unlock time (e.g. 17) <= now - (1)
        // e.g. 17 <= (16 + 1)
        if (isShutdown || locks[length - 1].unlockTime <= expiryTime) {
            //if time is beyond last lock, can just bundle everything together
            locked = userBalance.locked;

            //dont delete, just set next index
            userBalance.nextUnlockIndex = length.to48();

            //check for kick reward
            //this wont have the exact reward rate that you would get if looped through
            //but this section is supposed to be for quick and easy low gas processing of all locks
            //we'll assume that if the reward was good enough someone would have processed at an earlier epoch
            if (_checkDelay > 0) {
                uint256 currentEpoch =
                    block.timestamp.sub(_checkDelay).div(rewardsDuration).mul(rewardsDuration);
                uint256 epochsover =
                    currentEpoch.sub(uint256(locks[length - 1].unlockTime)).div(rewardsDuration);
                uint256 rRate = AuraMath.min(kickRewardPerEpoch.mul(epochsover + 1), denominator);
                reward = uint256(locked).mul(rRate).div(denominator);
            }
        } else {
            //use a processed index(nextUnlockIndex) to not loop as much
            //deleting does not change array length
            uint48 nextUnlockIndex = userBalance.nextUnlockIndex;
            for (uint256 i = nextUnlockIndex; i < length;) {
                //unlock time must be less or equal to time
                if (locks[i].unlockTime > expiryTime) break;

                //add to cumulative amounts
                locked = locked.add(locks[i].amount);

                //check for kick reward
                //each epoch over due increases reward
                if (_checkDelay > 0) {
                    uint256 currentEpoch =
                        block.timestamp.sub(_checkDelay).div(rewardsDuration).mul(rewardsDuration);
                    uint256 epochsover =
                        currentEpoch.sub(uint256(locks[i].unlockTime)).div(rewardsDuration);
                    uint256 rRate =
                        AuraMath.min(kickRewardPerEpoch.mul(epochsover + 1), denominator);
                    reward = reward.add(uint256(locks[i].amount).mul(rRate).div(denominator));
                }
                //set next unlock index
                nextUnlockIndex++;
                unchecked {
                    ++i;
                }
            }
            //update next unlock index
            userBalance.nextUnlockIndex = nextUnlockIndex;
        }
        if (locked == 0) revert NoExpiredLocks();

        //update user balances and total supplies
        userBalance.locked = userBalance.locked.sub(locked);
        lockedSupply = lockedSupply.sub(locked);

        //checkpoint the delegatee
        _checkpointDelegate(delegates(_account), 0, 0);

        emit Withdrawn(_account, locked, _relock);

        //send process incentive
        if (reward > 0) {
            //reduce return amount by the kick reward
            locked = locked.sub(reward.to208());

            //transfer reward
            stakingToken.safeTransfer(_rewardAddress, reward);
            emit KickReward(_rewardAddress, _account, reward);
        }

        //relock or return to user
        if (_relock) {
            _lock(_account, locked);
        } else {
            stakingToken.safeTransfer(_account, locked);
        }
    }

    /**
     *
     *         DELEGATION & VOTE BALANCE
     *
     */

    /**
     * @dev Delegate votes from the sender to `newDelegatee`.
     */
    function delegate(address newDelegatee) external virtual nonReentrant {
        // Step 1: Get lock data
        LockedBalance[] storage locks = userLocks[msg.sender];
        uint256 len = locks.length;
        if (len == 0) revert NoLocks();
        if (newDelegatee == address(0)) revert ZeroAddress();

        // Step 2: Update delegatee storage
        address oldDelegatee = delegates(msg.sender);
        if (newDelegatee == oldDelegatee) revert SameAddress();
        _delegates[msg.sender] = newDelegatee;

        emit DelegateChanged(msg.sender, oldDelegatee, newDelegatee);

        // Step 3: Move balances around
        //     Delegate for the upcoming epoch
        uint256 upcomingEpoch =
            block.timestamp.add(rewardsDuration).div(rewardsDuration).mul(rewardsDuration);
        uint256 i = len - 1;
        uint256 futureUnlocksSum = 0;
        LockedBalance memory currentLock = locks[i];
        // Step 3.1: Add future unlocks and sum balances
        while (currentLock.unlockTime > upcomingEpoch) {
            futureUnlocksSum += currentLock.amount;

            if (oldDelegatee != address(0)) {
                delegateeUnlocks[oldDelegatee][currentLock.unlockTime] -= currentLock.amount;
            }
            delegateeUnlocks[newDelegatee][currentLock.unlockTime] += currentLock.amount;

            if (i > 0) {
                i--;
                currentLock = locks[i];
            } else {
                break;
            }
        }

        // Step 3.2: Checkpoint old delegatee
        _checkpointDelegate(oldDelegatee, 0, futureUnlocksSum);

        // Step 3.3: Checkpoint new delegatee
        _checkpointDelegate(newDelegatee, futureUnlocksSum, 0);
    }

    function _checkpointDelegate(
        address _account,
        uint256 _upcomingAddition,
        uint256 _upcomingDeduction
    ) internal {
        // This would only skip on first checkpointing
        if (_account != address(0)) {
            uint256 upcomingEpoch =
                block.timestamp.add(rewardsDuration).div(rewardsDuration).mul(rewardsDuration);
            DelegateeCheckpoint[] storage ckpts = _checkpointedVotes[_account];
            if (ckpts.length > 0) {
                DelegateeCheckpoint memory prevCkpt = ckpts[ckpts.length - 1];
                // If there has already been a record for the upcoming epoch, no need to deduct the unlocks
                if (prevCkpt.epochStart == upcomingEpoch) {
                    ckpts[ckpts.length - 1] = DelegateeCheckpoint({
                        votes: (prevCkpt.votes + _upcomingAddition - _upcomingDeduction).to208(),
                        epochStart: upcomingEpoch.to48()
                    });
                }
                // else if it has been over 16 weeks since the previous checkpoint, all locks have since expired
                // e.g. week 1 + 17 <= 18
                else if (prevCkpt.epochStart + lockDuration <= upcomingEpoch) {
                    ckpts.push(
                        DelegateeCheckpoint({
                            votes: (_upcomingAddition - _upcomingDeduction).to208(),
                            epochStart: upcomingEpoch.to48()
                        })
                    );
                } else {
                    uint256 nextEpoch = upcomingEpoch;
                    uint256 unlocksSinceLatestCkpt = 0;
                    // Should be maximum 18 iterations
                    while (nextEpoch > prevCkpt.epochStart) {
                        unlocksSinceLatestCkpt += delegateeUnlocks[_account][nextEpoch];
                        nextEpoch -= rewardsDuration;
                    }
                    ckpts.push(
                        DelegateeCheckpoint({
                            votes: (
                                prevCkpt.votes - unlocksSinceLatestCkpt + _upcomingAddition
                                    - _upcomingDeduction
                                ).to208(),
                            epochStart: upcomingEpoch.to48()
                        })
                    );
                }
            } else {
                ckpts.push(
                    DelegateeCheckpoint({
                        votes: (_upcomingAddition - _upcomingDeduction).to208(),
                        epochStart: upcomingEpoch.to48()
                    })
                );
            }
            emit DelegateCheckpointed(_account);
        }
    }

    /**
     * @dev Get the address `account` is currently delegating to.
     */
    function delegates(address account) public view virtual returns (address) {
        return _delegates[account];
    }

    /**
     * @dev Gets the current votes balance for `account`
     */
    function getVotes(address account) external view returns (uint256) {
        return getPastVotes(account, block.timestamp);
    }

    /**
     * @dev Get the `pos`-th checkpoint for `account`.
     */
    function checkpoints(address account, uint32 pos)
        external
        view
        virtual
        returns (DelegateeCheckpoint memory)
    {
        return _checkpointedVotes[account][pos];
    }

    /**
     * @dev Get number of checkpoints for `account`.
     */
    function numCheckpoints(address account) external view virtual returns (uint48) {
        return _checkpointedVotes[account].length.to48();
    }

    /**
     * @dev Retrieve the number of votes for `account` at the end of `blockNumber`.
     */
    function getPastVotes(address account, uint256 timestamp) public view returns (uint256 votes) {
        if (timestamp > block.timestamp) revert BlockNotMined();
        uint256 epoch = timestamp.div(rewardsDuration).mul(rewardsDuration);
        DelegateeCheckpoint memory ckpt = _checkpointsLookup(_checkpointedVotes[account], epoch);
        votes = ckpt.votes;
        if (votes == 0 || ckpt.epochStart + lockDuration <= epoch) {
            return 0;
        }
        while (epoch > ckpt.epochStart) {
            votes -= delegateeUnlocks[account][epoch];
            epoch -= rewardsDuration;
        }
    }

    /**
     * @dev Retrieve the `totalSupply` at the end of `timestamp`. Note, this value is the sum of all balances.
     * It is but NOT the sum of all the delegated votes!
     */
    function getPastTotalSupply(uint256 timestamp) external view returns (uint256) {
        if (timestamp >= block.timestamp) revert BlockNotMined();
        return totalSupplyAtEpoch(findEpochId(timestamp));
    }

    /**
     * @dev Lookup a value in a list of (sorted) checkpoints.
     *      Copied from oz/ERC20Votes.sol
     */
    function _checkpointsLookup(DelegateeCheckpoint[] storage ckpts, uint256 epochStart)
        private
        view
        returns (DelegateeCheckpoint memory)
    {
        uint256 high = ckpts.length;
        uint256 low = 0;
        while (low < high) {
            uint256 mid = AuraMath.average(low, high);
            if (ckpts[mid].epochStart > epochStart) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        return high == 0 ? DelegateeCheckpoint(0, 0) : ckpts[high - 1];
    }

    /**
     *
     *             VIEWS - BALANCES
     *
     */

    /**
     * @notice  Balance of an account
     * @dev     Balance of an account which only includes properly locked tokens as of the most recent eligible epoch
     * @param   _user  address of the account
     * @return  amount  balance of the account
     */
    function balanceOf(address _user) external view returns (uint256 amount) {
        return balanceAtEpochOf(findEpochId(block.timestamp), _user);
    }

    /**
     * @notice  Balance at the epoch
     * @dev    Balance of an account which only includes properly locked tokens at the given epoch
     * @param   _epoch  Time of the epoch
     * @param   _user  address of the account
     * @return  amount  .
     */
    function balanceAtEpochOf(uint256 _epoch, address _user) public view returns (uint256 amount) {
        uint256 epochStart = uint256(_epochs[0].date).add(uint256(_epoch).mul(rewardsDuration));
        if (epochStart >= block.timestamp) revert FutureEpoch();

        uint256 cutoffEpoch = epochStart.sub(lockDuration);

        LockedBalance[] storage locks = userLocks[_user];

        //need to add up since the range could be in the middle somewhere
        //traverse inversely to make more current queries more gas efficient
        uint256 locksLength = locks.length;
        for (uint256 i = locksLength; i > 0;) {
            uint256 lockEpoch = uint256(locks[i - 1].unlockTime).sub(lockDuration);
            //lock epoch must be less or equal to the epoch we're basing from.
            //also not include the current epoch
            if (lockEpoch < epochStart) {
                if (lockEpoch > cutoffEpoch) {
                    amount = amount.add(locks[i - 1].amount);
                } else {
                    //stop now as no futher checks matter
                    break;
                }
            }
            unchecked {
                --i;
            }
        }

        return amount;
    }

    /**
     * @notice  Locked balances
     * @dev     Information on a user's locked balances
     * @param   _user  address of the account
     * @return  total
     * @return  unlockable  .
     * @return  locked  .
     * @return  lockData  .
     */
    function lockedBalances(address _user)
        external
        view
        returns (uint256 total, uint256 unlockable, uint256 locked, LockedBalance[] memory lockData)
    {
        LockedBalance[] storage locks = userLocks[_user];
        Balances storage userBalance = balances[_user];
        uint256 nextUnlockIndex = userBalance.nextUnlockIndex;
        uint256 idx;
        uint256 length = locks.length;
        for (uint256 i = nextUnlockIndex; i < length;) {
            if (locks[i].unlockTime > block.timestamp) {
                if (idx == 0) {
                    lockData = new LockedBalance[](length - i);
                }
                lockData[idx] = locks[i];
                idx++;
                locked = locked.add(locks[i].amount);
            } else {
                unlockable = unlockable.add(locks[i].amount);
            }
            unchecked {
                ++i;
            }
        }
        return (userBalance.locked, unlockable, locked, lockData);
    }

    /**
     * @notice  Total supply
     * @dev     Total supply of all properly locked balances as of the most recent eligible epoch
     * @return  supply  .
     */
    function totalSupply() external view returns (uint256 supply) {
        return totalSupplyAtEpoch(findEpochId(block.timestamp));
    }

    /**
     * @notice  Total supply at the epoch
     * @dev     Total supply of all properly locked balances at the given epoch
     * @param   _epoch  Time of the epoch
     * @return  supply  .
     */
    function totalSupplyAtEpoch(uint256 _epoch) public view returns (uint256 supply) {
        uint256 epochStart = uint256(_epochs[0].date).add(uint256(_epoch).mul(rewardsDuration));
        if (epochStart >= block.timestamp) revert FutureEpoch();

        uint256 cutoffEpoch = epochStart.sub(lockDuration);
        uint256 lastIndex = _epochs.length - 1;

        uint256 epochIndex = _epoch > lastIndex ? lastIndex : _epoch;

        for (uint256 i = epochIndex + 1; i > 0; i--) {
            Epoch memory e = _epochs[i - 1];
            if (e.date == epochStart) {
                continue;
            } else if (e.date <= cutoffEpoch) {
                break;
            } else {
                supply += e.supply;
            }
        }
    }

    // Get an epoch index based on timestamp
    function findEpochId(uint256 _time) public view returns (uint256 epoch) {
        return _time.sub(_epochs[0].date).div(rewardsDuration);
    }

    /**
     *
     *             VIEWS - GENERAL
     *
     */

    // Number of _epochs
    function epochCount() external view returns (uint256) {
        return _epochs.length;
    }

    function epochs(uint256 i) external view returns (Epoch memory) {
        return _epochs[i];
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    function name() external view returns (string memory) {
        return _name;
    }

    function symbol() external view returns (string memory) {
        return _symbol;
    }

    /**
     *
     *             VIEWS - REWARDS
     *
     */

    /**
     * @notice  Claimable rewards
     * @dev     Get all claimable rewards for the given account
     * @param   _account  address of the account
     * @return  userRewards  .
     */
    function claimableRewards(address _account)
        external
        view
        returns (EarnedData[] memory userRewards)
    {
        userRewards = new EarnedData[](rewardTokens.length);
        Balances storage userBalance = balances[_account];
        uint256 userRewardsLength = userRewards.length;
        for (uint256 i = 0; i < userRewardsLength;) {
            address token = rewardTokens[i];
            userRewards[i].token = token;
            userRewards[i].amount = _earned(_account, token, userBalance.locked);
            unchecked {
                ++i;
            }
        }
        return userRewards;
    }

    /**
     * @notice  Last time reward applicable
     * @param   _rewardsToken  address of the reward token
     * @return  uint256  .
     */
    function lastTimeRewardApplicable(address _rewardsToken) external view returns (uint256) {
        return _lastTimeRewardApplicable(rewardData[_rewardsToken].periodFinish);
    }

    function rewardPerToken(address _rewardsToken) external view returns (uint256) {
        return _rewardPerToken(_rewardsToken);
    }

    /**
     * @notice  Earned rewards
     * @param   _user  address of the account
     * @param   _rewardsToken  address of the reward token
     * @param   _balance  balance of the account
     * @return  uint256  .
     */
    function _earned(address _user, address _rewardsToken, uint256 _balance)
        internal
        view
        returns (uint256)
    {
        UserData memory data = userData[_user][_rewardsToken];
        return _balance.mul(_rewardPerToken(_rewardsToken).sub(data.rewardPerTokenPaid)).div(1e18)
            .add(data.rewards);
    }

    /**
     * @notice  Last time reward applicable
     * @param   _finishTime  finish time of the reward
     * @return  uint256  .
     */
    function _lastTimeRewardApplicable(uint256 _finishTime) internal view returns (uint256) {
        return AuraMath.min(block.timestamp, _finishTime);
    }

    /**
     * @notice  Reward per token
     * @param   _rewardsToken  address of the reward token
     * @return  uint256  .
     */
    function _rewardPerToken(address _rewardsToken) internal view returns (uint256) {
        if (lockedSupply == 0) {
            return rewardData[_rewardsToken].rewardPerTokenStored;
        }
        return uint256(rewardData[_rewardsToken].rewardPerTokenStored).add(
            _lastTimeRewardApplicable(rewardData[_rewardsToken].periodFinish).sub(
                rewardData[_rewardsToken].lastUpdateTime
            ).mul(rewardData[_rewardsToken].rewardRate).mul(1e18).div(lockedSupply)
        );
    }

    /**
     *
     *             REWARD FUNDING
     *
     */

    /**
     * @notice  Queue new reward
     * @param   _rewardsToken  address of the reward token
     * @param   _rewards  amount of rewards
     */
    function queueNewRewards(address _rewardsToken, uint256 _rewards) external nonReentrant {
        if (!rewardDistributors[_rewardsToken][msg.sender]) revert NotAuthorized();
        if (_rewards == 0) revert ZeroAmount();

        RewardData storage rdata = rewardData[_rewardsToken];

        IERC20(_rewardsToken).safeTransferFrom(msg.sender, address(this), _rewards);

        _rewards = _rewards.add(queuedRewards[_rewardsToken]);
        if (_rewards >= 1e25) revert RewardsTooBig();

        if (block.timestamp >= rdata.periodFinish) {
            _notifyReward(_rewardsToken, _rewards);
            queuedRewards[_rewardsToken] = 0;
            return;
        }

        //et = now - (finish-duration)
        uint256 elapsedTime = block.timestamp.sub(rdata.periodFinish.sub(rewardsDuration.to32()));
        //current at now: rewardRate * elapsedTime
        uint256 currentAtNow = rdata.rewardRate * elapsedTime;
        uint256 queuedRatio = currentAtNow.mul(1000).div(_rewards);
        if (queuedRatio < newRewardRatio) {
            _notifyReward(_rewardsToken, _rewards);
            queuedRewards[_rewardsToken] = 0;
        } else {
            queuedRewards[_rewardsToken] = _rewards;
        }
    }

    /**
     * @notice  Notify reward amount
     * @param   _rewardsToken  address of the reward token
     * @param   _reward  amount of rewards
     */
    function _notifyReward(address _rewardsToken, uint256 _reward)
        internal
        updateReward(address(0))
    {
        RewardData storage rdata = rewardData[_rewardsToken];

        if (block.timestamp >= rdata.periodFinish) {
            rdata.rewardRate = _reward.div(rewardsDuration).to96();
        } else {
            uint256 remaining = uint256(rdata.periodFinish).sub(block.timestamp);
            uint256 leftover = remaining.mul(rdata.rewardRate);
            rdata.rewardRate = _reward.add(leftover).div(rewardsDuration).to96();
        }

        // Equivalent to 10 million tokens over a weeks duration
        if (rdata.rewardRate >= 1e20) revert RewardRateTooBig();
        if (lockedSupply < 1e20) revert LockedSupplyTooLow();

        rdata.lastUpdateTime = block.timestamp.to32();
        rdata.periodFinish = block.timestamp.add(rewardsDuration).to32();

        emit RewardAdded(_rewardsToken, _reward);
    }
}
