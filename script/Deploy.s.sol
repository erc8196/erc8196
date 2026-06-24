// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {ERC8196Wallet} from "../src/ERC8196Wallet.sol";
import {ERC8126ScoreAnchor} from "../src/ERC8126ScoreAnchor.sol";

/// @title Deploy — testnet/mainnet deployment of the functioning (self-contained) stack.
/// @notice Deploys the ERC8126ScoreAnchor (admin/oracle role split) and the ERC8196Wallet
///         pointed at a LIVE ERC-8004 Identity Registry. Until the ERC-8004 Validation
///         Registry is live, pass VALIDATION_REGISTRY=0 (the wallet holds it dormant) and
///         use the anchor as the verifier. Swap to ValidationRegistryAdapter later.
///
/// Env:
///   PRIVATE_KEY          deployer key (also default anchor admin)
///   IDENTITY_REGISTRY    live ERC-8004 Identity Registry address (required)
///   ANCHOR_ORACLE        relayer hot key address that may write scores (required)
///   ANCHOR_ADMIN         cold key / multisig (optional; defaults to deployer)
///   VALIDATION_REGISTRY  ERC-8004 Validation Registry (optional; 0 until live)
///
/// Run:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
contract Deploy is Script {
    function run() external returns (ERC8126ScoreAnchor anchor, ERC8196Wallet wallet) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address identity = vm.envAddress("IDENTITY_REGISTRY");
        address oracle = vm.envAddress("ANCHOR_ORACLE");
        address admin = vm.envOr("ANCHOR_ADMIN", vm.addr(pk));
        address validation = vm.envOr("VALIDATION_REGISTRY", address(0));

        vm.startBroadcast(pk);
        anchor = new ERC8126ScoreAnchor(admin, oracle);
        wallet = new ERC8196Wallet(identity, address(anchor), validation);
        vm.stopBroadcast();

        console2.log("ERC8126ScoreAnchor:", address(anchor));
        console2.log("ERC8196Wallet:     ", address(wallet));
        console2.log("  admin (cold):    ", admin);
        console2.log("  oracle (relayer):", oracle);
        console2.log("  identityRegistry:", identity);
    }
}
