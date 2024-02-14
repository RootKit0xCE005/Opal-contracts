// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "src/interfaces/Balancer/IBalancerVault.sol";

interface IRewardPoolDepositWrapper {
    struct JoinPoolRequest {
        IAsset[] assets;
        uint256[] maxAmountsIn;
        bytes userData;
        bool fromInternalBalance;
    }

    struct ExitPoolRequest {
        IAsset[] assets;
        uint256[] minAmountsOut;
        bytes userData;
        bool toInternalBalance;
    }

    function depositSingle(
        address _rewardPoolAddress,
        IERC20 _inputToken,
        uint256 _inputAmount,
        bytes32 _balancerPoolId,
        JoinPoolRequest memory _request
    ) external;
}
