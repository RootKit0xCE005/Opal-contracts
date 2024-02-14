// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockedRewardToken} from "./MockedRewardToken.sol";
import {MockedERC20} from "./MockedERC20.sol";

contract MockedAuraRewarder {
    address[] public extraRewardTokens;
    uint256 public extraRewardTokensLength;

    address public rewardToken;

    constructor(
        address bal,
        address aura,
        address rewardToken1,
        address rewardToken2,
        address rewardToken3
    ) {
        rewardToken = bal;

        extraRewardTokens.push(aura);
        extraRewardTokensLength++;

        if (rewardToken1 != address(0)) {
            extraRewardTokens.push(rewardToken1);
            extraRewardTokensLength++;
        }
        if (rewardToken2 != address(0)) {
            extraRewardTokens.push(rewardToken2);
            extraRewardTokensLength++;
        }
        if (rewardToken3 != address(0)) {
            extraRewardTokens.push(rewardToken3);
            extraRewardTokensLength++;
        }
    }

    function updateRewardTokens(
        address bal,
        address aura,
        address rewardToken1,
        address rewardToken2,
        address rewardToken3
    ) external {
        rewardToken = bal;

        extraRewardTokens = new address[](0);
        extraRewardTokensLength = 0;

        extraRewardTokens.push(aura);
        extraRewardTokensLength++;

        if (rewardToken1 != address(0)) {
            extraRewardTokens.push(rewardToken1);
            extraRewardTokensLength++;
        }
        if (rewardToken2 != address(0)) {
            extraRewardTokens.push(rewardToken2);
            extraRewardTokensLength++;
        }
        if (rewardToken3 != address(0)) {
            extraRewardTokens.push(rewardToken3);
            extraRewardTokensLength++;
        }
    }

    function getMintValue() external pure returns (uint256) {
        return 1;
    }

    function getExtraMintValue() external pure returns (uint256) {
        return 1;
    }

    // Mint one token of each reward token
    function getReward(address addr, bool bol) external returns (bool) {
        address bal = MockedRewardToken(rewardToken).getERC20();
        MockedERC20(bal).mint(addr, this.getMintValue());
        if (!bol) return true;
        for (uint256 i = 0; i < extraRewardTokensLength; i++) {
            address rewardTokenAddr = MockedRewardToken(extraRewardTokens[i]).getERC20();
            MockedERC20(rewardTokenAddr).mint(addr, this.getExtraMintValue());
        }
        return true;
    }

    function extraRewardsLength() external view returns (uint256) {
        return extraRewardTokensLength;
    }

    function extraRewards(uint256 input) external view returns (address) {
        return extraRewardTokens[input];
    }
}
