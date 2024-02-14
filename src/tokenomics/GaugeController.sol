// SPDX-License-Identifier: MIT
pragma solidity >=0.8.16;

// @audit Ownable imported but not used. 
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IVoteLocker} from "src/interfaces/IVoteLocker.sol";
import {IRegistryContract} from "src/interfaces/Registry/IRegistryContract.sol";
import {IRegistryAccess} from "src/interfaces/Registry/IRegistryAccess.sol";
import {SCALED_ONE, CONTRACT_REGISTRY_ACCESS, ROLE_OPAL_TEAM, WEEK} from "src/utils/constants.sol";

contract GaugeController is ReentrancyGuard {
    // Constants
    uint256 public constant WEIGHT_VOTE_DELAY = 10 * 86_400; // 10 days

    // Struct
    struct Unlocks {
        uint208 amount;
        uint48 unlockTime;
    }

    struct UserVote {
        uint256 amount;
        uint256 weight;
    }

    // Storage
    address public immutable token;
    address public immutable voteLocker;

    IRegistryContract public registryContract;
    IRegistryAccess public registryAccess;

    int128 public numberGaugeTypes;
    int128 public numberGauges;
    mapping(int128 => string) public gaugeTypeNames;

    address[] public gauges;
    mapping(address => int128) public gaugeTypes;

    // user -> gauge -> UserVotes
    mapping(address => mapping(address => UserVote)) public userVote;
    // user -> gauge -> UserVotes Unlocks
    mapping(address => mapping(address => Unlocks[])) public userVoteUnlocks;
    // user -> weights
    mapping(address => uint256) public userVotePower;
    // user -> gauge -> timestamp
    mapping(address => mapping(address => uint256)) public lastUserVote;

    // gauge -> timestamp -> votes
    mapping(address => mapping(uint256 => uint256)) public gaugeVotes;
    // gauge -> timestamp -> vote changes
    mapping(address => mapping(uint256 => uint256)) public gaugeVoteChanges;
    mapping(address => uint256) public lastGaugeUpdate; // last scheduled time (next week)

    // gauge type -> timestamp -> votes
    mapping(int128 => mapping(uint256 => uint256)) public typeVotes;
    // gauge type -> timestamp -> vote changes
    mapping(int128 => mapping(uint256 => uint256)) public typeVoteChanges;
    mapping(int128 => uint256) public lastTypeUpdate; // last scheduled time (next week)

    mapping(uint256 => uint256) public totalVotes;
    uint256 public lastUpdate; // last scheduled time (next week)

    // gauge type -> timestamp -> type weight
    mapping(int128 => mapping(uint256 => uint256)) public typeWeights;
    mapping(int128 => uint256) public lastTypeWeightUpdate; // last scheduled time (next week)

    // Events

    event AddType(string name, int128 typeId);
    event NewGauge(address gauge, int128 gaugeType, uint256 weight);
    event NewTypeWeight(int128 typeId, uint256 time, uint256 weight, uint256 totalWeight);
    event NewGaugeWeight(address gauge, uint256 time, uint256 weight, uint256 totalWeight);
    event VoteForGauge(uint256 time, address user, address gauge, uint256 weight);

    // Errors

    error InvalidGaugeType();
    error GaugeAlreadyAdded();
    error NoLocks();
    error NoActiveLocks();
    error InvalidVoteWeight();
    error InvalidGauge();
    error VoteCooldown();
    error VoteWeightOverflow();
    error NotAuthorized();
    error ListSizeMismatch();

    modifier onlyOpalTeam() {
        if (!registryAccess.checkRole(ROLE_OPAL_TEAM, msg.sender)) revert NotAuthorized();
        _;
    }

    // Constructor
    constructor(address _token, address _voteLocker, address _registryContract) {
        // checks params

        token = _token;
        voteLocker = _voteLocker;
        registryContract = IRegistryContract(_registryContract);
        registryAccess = IRegistryAccess(registryContract.getContract(CONTRACT_REGISTRY_ACCESS));

        lastUpdate = (block.timestamp / WEEK) * WEEK;
    }

    // View methods

    /**
     * @notice  Get Gauge type
     * @param   _gauge  The address of the gauge
     * @return  int128  The gauge type
     */
    function getGaugeType(address _gauge) external view returns (int128) {
        if (gaugeTypes[_gauge] == 0) revert InvalidGaugeType();
        return gaugeTypes[_gauge] - 1;
    }

    /**
     * @notice  Get Gauge weight
     * @param   _gauge  The address of the gauge
     * @return  uint256  The gauge weight
     */
    function getGaugeWeight(address _gauge) external view returns (uint256) {
        return gaugeVotes[_gauge][lastGaugeUpdate[_gauge]];
    }

    /**
     * @notice  Get Gauge type weight
     * @param   _type  The type of the gauge
     * @return  uint256  The gauge type weight
     */
    function getTypeWeight(int128 _type) external view returns (uint256) {
        return typeVotes[_type][lastTypeUpdate[_type]];
    }

    /**
     * @notice  Get total weight
     * @return  uint256  The total weight
     */
    function getTotalWeight() external view returns (uint256) {
        return totalVotes[lastUpdate];
    }

    /**
     * @notice  Get total weight
     * @param   _type  The type of the gauge
     * @return  uint256  The total weight
    */
    function getWeightsSumPerType(int128 _type) external view returns (uint256) {
        return typeWeights[_type][lastTypeWeightUpdate[_type]];
    }

    // State-changing methods

    /**
     * @notice  Checkpoint function
     */
    function checkpoint() external nonReentrant {
        _getTotal();
    }

    /**
     * @notice  Checkpoint function
     * @param   gauge  The address of the gauge
     */
    function checkpointGauge(address gauge) external nonReentrant {
        _getWeight(gauge);
        _getTotal();
    }

    /**
     * @notice  Get Gauge relative weight
     * @param   gauge  The address of the gauge
     * @param   timestamp  The timestamp to check
     * @return  uint256  The gauge relative weight
    */
    function gaugeRelativeWeight(address gauge, uint256 timestamp) external view returns (uint256) {
        return _gaugeRelativeWeight(gauge, timestamp);
    }

    /**
     * @notice  Get Gauge relative weigh write
     * @param   gauge  The address of the gauge
     * @param   timestamp  The timestamp to check
     * @return  uint256  .
     */
    function gaugeRelativeWeightWrite(address gauge, uint256 timestamp) external returns (uint256) {
        _getWeight(gauge);
        _getTotal();
        return _gaugeRelativeWeight(gauge, timestamp);
    }

    /**
     * @notice  Vote for gauge weight
     * @param   gauge  Address of the gauge
     * @param   voteWeight  Weight of the voting power to allocate
     */
    function voteForGaugeWeight(address gauge, uint256 voteWeight) external nonReentrant {
        _voteForGaugeweight(msg.sender, gauge, voteWeight);
    }

    /**
     * @notice  Vote for gauge weight
     * @param   gaugeList  List of address of the gauge
     * @param   voteWeights  Weights of the voting power to allocate
     */
    function voteForManyGaugeWeights(address[] calldata gaugeList, uint256[] calldata voteWeights) external nonReentrant {
        uint256 len = gaugeList.length;
        if (len != voteWeights.length) revert ListSizeMismatch();

        for (uint256 i; i < len;) {
            _voteForGaugeweight(msg.sender, gaugeList[i], voteWeights[i]);

            unchecked { 
                ++i; 
            }
        }
    }

    // Internal methods

    /**
     * @notice  Check the Gauge type
     * @param   gaugeType  The type of the gauge
     * @return  uint256  .
     */
    function _getTypeWeight(int128 gaugeType) internal returns (uint256) {
        uint256 timestamp = lastTypeWeightUpdate[gaugeType];
        if (timestamp == 0) return 0;

        uint256 weight = typeWeights[gaugeType][timestamp];
        for (uint256 i; i < 500;) {
            if (timestamp > block.timestamp) break;
            timestamp += WEEK;

            typeWeights[gaugeType][timestamp] = weight;

            if (timestamp > block.timestamp) {
                lastTypeWeightUpdate[gaugeType] = timestamp;
            }

            unchecked {
                ++i;
            }
        }

        return weight;
    }

    /**
     * @notice  Update the votes of a specific timestamp regarding the change votes
     * @param   gaugeType  The type of the gauge
     * @return  uint256  The votes for the current timestamp (ie. lastTypeUptade[gaugeType]])
    */
    function _getSum(int128 gaugeType) internal returns (uint256) {
        uint256 timestamp = lastTypeUpdate[gaugeType];
        if (timestamp == 0) return 0;

        uint256 votes = typeVotes[gaugeType][timestamp];
        for (uint256 i; i < 500;) {
            if (timestamp > block.timestamp) break;
            timestamp += WEEK;

            uint256 voteChanges = typeVoteChanges[gaugeType][timestamp];
            if (voteChanges >= votes) {
                votes = 0;
            } else {
                unchecked {
                    votes -= voteChanges;
                }
            }
            typeVotes[gaugeType][timestamp] = votes;

            if (timestamp > block.timestamp) {
                lastTypeUpdate[gaugeType] = timestamp;
            }

            unchecked {
                ++i;
            }
        }

        return votes;
    }

    /**
     * @notice  Get total
     * @return  uint256  .
    */
    function _getTotal() internal returns (uint256) {
        uint256 timestamp = lastUpdate;
        if (timestamp == 0) return 0;

        int128 _numberGauges = numberGauges;
        for (int128 i; i < _numberGauges;) {
            _getSum(i);
            _getTypeWeight(i);

            unchecked {
                ++i;
            }
        }

        uint256 votesTotal;

        for (uint256 j; j < 500;) {
            if (timestamp > block.timestamp) break;
            timestamp += WEEK;
            votesTotal = 0;

            for (int128 k; k < _numberGauges;) {
                uint256 typeVoteChange = typeVoteChanges[k][timestamp];
                uint256 typeWeight = typeWeights[k][timestamp];

                votesTotal += typeVoteChange * typeWeight;

                unchecked {
                    ++k;
                }
            }

            totalVotes[timestamp] = votesTotal;

            if (timestamp > block.timestamp) {
                lastUpdate = timestamp;
            }

            unchecked {
                ++j;
            }
        }

        return votesTotal;
    }

    /**
     * @notice  Get weight
     * @param   gauge  The address of the gauge
     * @return  uint256  .
    */
    function _getWeight(address gauge) internal returns (uint256) {
        uint256 timestamp = lastGaugeUpdate[gauge];
        if (timestamp == 0) return 0;

        uint256 votes = gaugeVotes[gauge][timestamp];
        for (uint256 i; i < 500;) {
            if (timestamp > block.timestamp) break;
            timestamp += WEEK;

            uint256 voteChanges = gaugeVoteChanges[gauge][timestamp];
            if (voteChanges >= votes) {
                votes = 0;
            } else {
                unchecked {
                    votes -= voteChanges;
                }
            }
            gaugeVotes[gauge][timestamp] = votes;

            if (timestamp > block.timestamp) {
                lastGaugeUpdate[gauge] = timestamp;
            }

            unchecked {
                ++i;
            }
        }

        return votes;
    }

    /**
     * @notice  Get Gauge relative weight
     * @param   gauge  The address of the gauge
     * @param   timestamp  The timestamp to check
     * @return  uint256  .
    */
    function _gaugeRelativeWeight(address gauge, uint256 timestamp) internal view returns (uint256) {
        timestamp = (timestamp / WEEK) * WEEK;
        uint256 totalWeight = totalVotes[timestamp];

        if (totalWeight == 0) return 0;

        int128 gaugeType = gaugeTypes[gauge] - 1;
        uint256 typeWeight = typeWeights[gaugeType][timestamp];
        uint256 gaugeWeight = gaugeVotes[gauge][timestamp];
        return SCALED_ONE * typeWeight * gaugeWeight / totalWeight;
    }

    /**
     * @notice  Change type weight
     * @param   gaugeType  The type of the gauge
     * @param   weight  The weight to change
    */
    function _changeTypeWeight(int128 gaugeType, uint256 weight) internal {
        uint256 oldWeight = _getTypeWeight(gaugeType);
        uint256 oldSum = _getSum(gaugeType);
        uint256 totalWeight = _getTotal();
        uint256 nextTimestamp = ((block.timestamp + WEEK) / WEEK) * WEEK;

        totalWeight += (oldSum * weight) - (oldSum * oldWeight);
        totalVotes[nextTimestamp] = totalWeight;
        typeWeights[gaugeType][nextTimestamp] = weight;
        lastUpdate = nextTimestamp;
        lastTypeWeightUpdate[gaugeType] = nextTimestamp;

        emit NewTypeWeight(gaugeType, nextTimestamp, weight, totalWeight);
    }

    /**
     * @notice  Change gauge weight
     * @param   gauge  The address of the gauge
     * @param   weight  The weight to change
    */
    function _changeGaugeWeight(address gauge, uint256 weight) internal {
        // Change gauge weight
        // Only needed when testing in reality
        int128 gaugeType = gaugeTypes[gauge] - 1;
        uint256 oldGaugeWeight = _getWeight(gauge);
        uint256 typeWeight = _getTypeWeight(gaugeType);
        uint256 oldSum = _getSum(gaugeType);
        uint256 totalWeight = _getTotal();
        uint256 nextTimestamp = ((block.timestamp + WEEK) / WEEK) * WEEK;

        gaugeVotes[gauge][nextTimestamp] = weight;
        lastGaugeUpdate[gauge] = nextTimestamp;

        uint256 newSum = oldSum + (weight - oldGaugeWeight);
        totalWeight += (oldSum * weight) - (oldSum * typeWeight);

        totalVotes[nextTimestamp] = totalWeight;
        typeWeights[gaugeType][nextTimestamp] = newSum;
        lastUpdate = nextTimestamp;
        lastTypeWeightUpdate[gaugeType] = nextTimestamp;

        emit NewGaugeWeight(gauge, block.timestamp, weight, totalWeight);
    }

    // Local vars for _voteForGaugeweight
    struct VoteVars {
        uint256 len;
        uint256 nextTimestamp;
        int128 gaugeType;
        uint256 powerUsed;
        uint256 oldGaugeWeight;
        uint256 oldSum;
        uint256 oldUnlocksLen;
    }

    /**
     * @notice  Vote for gauge weight
     * @param   user  Address of the user
     * @param   gauge  Address of the gauge
     * @param   voteWeight  Weight of the voting power to allocate
    */
    function _voteForGaugeweight(address user, address gauge, uint256 voteWeight) internal {
        VoteVars memory vars;
        (,,, IVoteLocker.LockedBalance[] memory locks) =
            IVoteLocker(voteLocker).lockedBalances(msg.sender);
        vars.len = locks.length;
        if (vars.len == 0) revert NoLocks();
        vars.nextTimestamp = ((block.timestamp + WEEK) / WEEK) * WEEK;
        if (locks[vars.len - 1].unlockTime < vars.nextTimestamp) revert NoActiveLocks();
        if (voteWeight > 10_000) revert InvalidVoteWeight();
        if (block.timestamp < lastUserVote[user][gauge] + WEIGHT_VOTE_DELAY) revert VoteCooldown();

        UserVote memory newUserVote = UserVote({
            amount: 0,
            weight: voteWeight
        });
        Unlocks[] memory unlocks = new Unlocks[](vars.len);
        uint256 i = vars.len - 1;
        IVoteLocker.LockedBalance memory currentLock = locks[i];
        while (currentLock.unlockTime > vars.nextTimestamp) {
            uint256 weightedAmount = currentLock.amount * voteWeight / 10_000;
            newUserVote.amount += weightedAmount;

            unlocks[i] = Unlocks({
                amount: uint208(weightedAmount), 
                unlockTime: currentLock.unlockTime
            });

            if (i > 0) {
                i--;
                currentLock = locks[i];
            } else {
                break;
            }
        }

        vars.gaugeType = gaugeTypes[gauge] - 1;
        if (vars.gaugeType < 0) revert InvalidGauge();

        UserVote memory lastVote = userVote[user][gauge];

        vars.powerUsed = userVotePower[user];
        vars.powerUsed = vars.powerUsed + voteWeight - lastVote.weight;
        if (vars.powerUsed > 10_000 || vars.powerUsed < 0) {
            revert VoteWeightOverflow();
        }
        userVotePower[user] = vars.powerUsed;

        vars.oldGaugeWeight = _getWeight(gauge);
        vars.oldSum = _getSum(vars.gaugeType);

        // remove past vote changes
        Unlocks[] memory oldUnlocks = userVoteUnlocks[user][gauge];
        vars.oldUnlocksLen = oldUnlocks.length;
        for (uint256 j; j < vars.oldUnlocksLen; j++) {
            // Also covers case were unlockTime is 0 (empty array item)
            if (oldUnlocks[j].unlockTime <= block.timestamp) continue;

            gaugeVoteChanges[gauge][oldUnlocks[j].unlockTime] -= oldUnlocks[j].amount;
            typeVoteChanges[vars.gaugeType][oldUnlocks[j].unlockTime] -= oldUnlocks[j].amount;

            // Other previous vote amounts are already accounted for
            // if unlocks timestamp is in the past
            vars.oldGaugeWeight -= oldUnlocks[j].amount;
            vars.oldSum -= oldUnlocks[j].amount;
        }

        gaugeVotes[gauge][vars.nextTimestamp] = vars.oldGaugeWeight + newUserVote.amount;
        typeVotes[vars.gaugeType][vars.nextTimestamp] = vars.oldSum + newUserVote.amount;

        for (uint256 k; k < vars.len; k++) {
            // Also covers case were unlockTime is 0 (empty array item)
            if (unlocks[k].unlockTime <= block.timestamp) continue;

            gaugeVoteChanges[gauge][unlocks[k].unlockTime] += unlocks[k].amount;
            typeVoteChanges[vars.gaugeType][unlocks[k].unlockTime] += unlocks[k].amount;
        }

        _getTotal();

        lastUserVote[user][gauge] = block.timestamp;
        userVote[user][gauge] = newUserVote;

        delete userVoteUnlocks[user][gauge];
        for (uint256 l; l < vars.len; l++) {
            // Also covers case were unlockTime is 0 (empty array item)
            if (unlocks[l].unlockTime <= block.timestamp) continue;

            userVoteUnlocks[user][gauge].push(unlocks[l]);
        }

        emit VoteForGauge(block.timestamp, user, gauge, voteWeight);
    }

    // Admin methods

    /**
     * @notice  Add gauge
     * @param   gauge  The gauge to add
     * @param   gaugeType  The type of the gauge
     * @param   weight  The weight to add
    */
    function addGauge(address gauge, int128 gaugeType, uint256 weight) external nonReentrant onlyOpalTeam {
        if (gaugeType < 0 || gaugeType > numberGaugeTypes) revert InvalidGaugeType();

        if (gaugeTypes[gauge] != 0) revert GaugeAlreadyAdded();

        numberGauges++;
        gauges.push(gauge);

        gaugeTypes[gauge] = gaugeType + 1;
        uint256 nextTimestamp = ((block.timestamp + WEEK) / WEEK) * WEEK;

        if (weight > 0) {
            uint256 typeWeight = _getTypeWeight(gaugeType);
            uint256 oldSum = _getSum(gaugeType);
            uint256 olTotal = _getTotal();

            typeVotes[gaugeType][nextTimestamp] = oldSum + weight;
            lastTypeUpdate[gaugeType] = nextTimestamp;
            totalVotes[nextTimestamp] = olTotal + (weight * typeWeight);
            lastUpdate = nextTimestamp;

            gaugeVotes[gauge][nextTimestamp] = weight;
        }

        if (lastTypeUpdate[gaugeType] == 0) {
            lastTypeUpdate[gaugeType] = nextTimestamp;
        }
        lastGaugeUpdate[gauge] = nextTimestamp;

        emit NewGauge(gauge, gaugeType, weight);
    }

    /**
     * @notice  Add Type for gauge
     * @param   name  The name of the gauge
     * @param   weight  The weight to add
    */
    function addType(string memory name, uint256 weight) external nonReentrant onlyOpalTeam {
        int128 newGaugeType = numberGaugeTypes;
        numberGaugeTypes++;
        gaugeTypeNames[newGaugeType] = name;

        if (weight != 0) {
            _changeTypeWeight(newGaugeType, weight);
        }

        emit AddType(name, newGaugeType);
    }

    /**
     * @notice  Change type weight
     * @param   gaugeType  The type of the gauge
     * @param   weight  The weight to change
    */
    function changeTypeWeight(int128 gaugeType, uint256 weight) external nonReentrant onlyOpalTeam {
        _changeTypeWeight(gaugeType, weight);
    }

    function changeGaugeWeight(address gauge, uint256 weight) external nonReentrant onlyOpalTeam {
        _changeGaugeWeight(gauge, weight);
    }
}
