// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* Role */
bytes32 constant ROLE_ADMIN = keccak256("ROLE_ADMIN");
bytes32 constant ROLE_OPAL_TEAM = keccak256("ROLE_OPAL_TEAM");
bytes32 constant ROLE_OMNIPOOL = keccak256("ROLE_OMNIPOOL");
bytes32 constant ROLE_OMNIPOOL_CONTROLLER = keccak256("ROLE_OMNIPOOL_CONTROLLER");
bytes32 constant ROLE_REWARD_MANAGER = keccak256("ROLE_REWARD_MANAGER");
bytes32 constant ROLE_MINT_LP_TOKEN = keccak256("ROLE_MINT_LP_TOKEN");
bytes32 constant ROLE_BURN_LP_TOKEN = keccak256("ROLE_BURN_LP_TOKEN");
bytes32 constant ROLE_MINT_ESCROW_TOKEN = keccak256("ROLE_MINT_ESCROW_TOKEN");
bytes32 constant ROLE_MINTER_ESCROW = keccak256("ROLE_MINTER_ESCROW");
bytes32 constant ROLE_DAO = keccak256("ROLE_DAO");
bytes32 constant ROLE_GEM_MINTER = keccak256("ROLE_MINTER_ESCROW");

/* Contracts */

bytes32 constant CONTRACT_GEM_TOKEN = keccak256("CONTRACT_GEM_TOKEN");
bytes32 constant CONTRACT_BAL_TOKEN = keccak256("CONTRACT_BAL_TOKEN");
bytes32 constant CONTRACT_AURA_TOKEN = keccak256("CONTRACT_AURA_TOKEN");
bytes32 constant CONTRACT_PRICE_FEED_ORACLE = keccak256("PRICE_FEED_ORACLE");
bytes32 constant CONTRACT_BPT_ORACLE = keccak256("CONTRACT_BPT_ORACLE");
bytes32 constant CONTRACT_REGISTRY_ACCESS = keccak256("CONTRACT_REGISTRY_ACCESS");
bytes32 constant CONTRACT_GAUGE_CONTROLLER = keccak256("CONTRACT_GAUGE_CONTROLLER");
bytes32 constant CONTRACT_OMNIPOOL = keccak256("CONTRACT_OMNIPOOL");
bytes32 constant CONTRACT_OMNIPOOL_CONTROLLER = keccak256("CONTRACT_OMNIPOOL_CONTROLLER");
bytes32 constant CONTRACT_BALANCER_VAULT = keccak256("CONTRACT_BALANCER_VAULT");
bytes32 constant CONTRACT_AURA_DEPOSIT_WRAPPER = keccak256("CONTRACT_AURA_DEPOSIT_WRAPPER");
bytes32 constant CONTRACT_OPAL_TREASURY = keccak256("CONTRACT_OPAL_TREASURY");
bytes32 constant CONTRACT_VOTE_LOCKER = keccak256("CONTRACT_VOTE_LOCKER");
bytes32 constant CONTRACT_GEM_MINTER_REBALANCING_REWARD = keccak256("CONTRACT_GEM_MINTER_REBALANCING_REWARD");
bytes32 constant CONTRACT_WETH = keccak256("CONTRACT_WETH");
bytes32 constant CONTRACT_INCENTIVES_MS = keccak256("CONTRACT_INCENTIVES_MS");

/* Constants */

uint256 constant SCALED_ONE = 1e18;

uint256 constant GEM_TOTAL_SUPPLY = 50_000_000 * SCALED_ONE;
uint256 constant LPB_SUPPLY = 5_000_000 * SCALED_ONE; // 10% of total supply
uint256 constant SEED_SUPPLY = 2_500_000 * SCALED_ONE; // 5% of total supply
uint256 constant LIQUIDITY_MINING_SUPPLY = 8_100_000 * SCALED_ONE; // 16.2% of total supply
uint256 constant VLGEM_BOOST_SUPPLY = 9_400_000 * SCALED_ONE; // 18.8% of total supply
uint256 constant TREASURY_SUPPLY = 3_000_000 * SCALED_ONE; // 6% of total supply
uint256 constant TEAM_SUPPLY = 7_500_000 * SCALED_ONE; // 15% of total supply
uint256 constant AIRDROP_SUPPLY = 5_000_000 * SCALED_ONE; // 10% of total supply
uint256 constant REBALANCING_SUPPLY = 9_500_000 * SCALED_ONE; // 19% of total supply

uint256 constant WEEK = 604_800;

/* Minter */
uint256 constant INITIAL_MINTER_RATE = (2_250_000 * SCALED_ONE) / uint256(52 weeks);
uint256 constant RATE_REDUCTION_TIME = 365 days;
uint256 constant RATE_REDUCTION_COEFFICIENT = 0.75 * 1e18; // 25% reduction

/* Minter Escrow */
uint256 constant MINTER_ESCROW_RATE = (9_400_000 * SCALED_ONE) / uint256(104 weeks);
uint256 constant RATE_END_TIMESTAMP = 2 * 365 days;
uint256 constant INFLATION_DELAY = 1 days;

/* Reward Manager */
uint256 constant REWARD_FEES = 900 * SCALED_ONE / 10_000; // 9%

/* Omnipool */
uint256 constant WITHDRAW_FEES = 50 * SCALED_ONE / 10_000; // 0.5%

/* Enum */
enum PoolType {
    WEIGHTED,
    STABLE,
    COMPOSABLE
}
