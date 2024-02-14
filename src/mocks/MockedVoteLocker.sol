// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockedVoteLocker is ERC20 {

    struct LockedBalance {
        uint208 amount;
        uint48 unlockTime;
    }
    
    mapping(address => LockedBalance[]) public userLocks;

    constructor() ERC20("MockedVoteLocker", "MockedVoteLocker") {}

    function mint(address account, uint256 amount) external {
        _mint(account, amount);
    }

    function lockedBalances(address _user) external view returns (
        uint256 total,
        uint256 unlockable,
        uint256 locked,
        LockedBalance[] memory lockData
    ) {
        LockedBalance[] storage locks = userLocks[_user];
        uint256 nextUnlockIndex = 0;
        uint256 idx;
        uint256 length = locks.length;
        for (uint256 i = nextUnlockIndex; i < length;) {
            if (locks[i].unlockTime > block.timestamp) {
                if (idx == 0) {
                    lockData = new LockedBalance[](length - i);
                }
                lockData[idx] = locks[i];
                idx++;
            }
            unchecked {
                ++i;
            }
        }
        return (0, 0, 0, lockData);
    }

    function setUserLocks(address _user, LockedBalance[] memory _locks) external {
        uint256 length = _locks.length;
        for (uint256 i = 0; i < length; i++) {
            userLocks[_user].push(_locks[i]);
        }
    }
}
