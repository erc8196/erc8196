// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {ERC8196Wallet} from "../src/ERC8196Wallet.sol";
import {ERC8126ScoreAnchor} from "../src/ERC8126ScoreAnchor.sol";
import {MockValidationRegistry, MockTarget} from "../test/mocks/Mocks.sol";

/// @title Demo — runnable end-to-end reference of the ERC-8196 trust stack.
/// @notice Self-contained path (works TODAY, no external infra): scores live in the
///         ERC8126ScoreAnchor written by the relayer/oracle. The ValidationRegistryAdapter
///         is the drop-in replacement once the ERC-8004 Validation Registry is deployed —
///         same IERC8126 surface, wallet unchanged.
///         Walks: Register (ERC-8004 id) -> Verify (ERC-8126 score -> anchor) -> Execute.
///         Run:  forge script script/Demo.s.sol -v
contract Demo is Script {
    bytes32 constant TYPEHASH = keccak256(
        "AgentAction(address agent,string action,address target,uint256 value,"
        "bytes data,uint256 nonce,uint256 validUntil,bytes32 policyHash,bytes32 entropyCommitment)"
    );

    uint256 constant AGENT_PK = 0xA11CE;
    uint256 constant AGENT_ID = 1;

    function run() external {
        address agent = vm.addr(AGENT_PK);
        address admin = makeAddr("admin"); // cold key (CENTRY / multisig)
        address relayer = makeAddr("relayer"); // hot oracle key

        // --- Deploy the stack -------------------------------------------------
        MockValidationRegistry validation = new MockValidationRegistry(); // dormant until 8004 is live
        ERC8126ScoreAnchor anchor = new ERC8126ScoreAnchor(admin, relayer);
        ERC8196Wallet wallet = new ERC8196Wallet(address(anchor), address(validation));
        MockTarget target = new MockTarget();
        vm.deal(address(wallet), 10 ether);

        console2.log("=== Deployed ===");
        console2.log("wallet ", address(wallet));
        console2.log("anchor ", address(anchor));

        // --- [1] Agent identity (ERC-8004, off-chain) ------------------------
        // The agent is registered in ERC-8004 out-of-band; the owner supplies its agentId
        // to registerPolicy below. The wallet itself makes no ERC-8004 call.
        console2.log("\n[1] Agent's ERC-8004 agentId =", AGENT_ID, "(supplied by owner)");

        // --- [2] Owner registers a policy (ERC-8196) -------------------------
        uint256 validUntil = block.timestamp + 30 days;
        string[] memory actions = new string[](1);
        actions[0] = "transfer";
        address[] memory allowed = new address[](1);
        allowed[0] = address(target);
        address[] memory blocked = new address[](0);
        bytes32 policyHash =
            wallet.registerPolicy(agent, AGENT_ID, actions, allowed, blocked, 1 ether, 2 ether, 0, validUntil, 50);
        console2.log("[2] Policy registered. risk ceiling = 50, maxPerTx = 1 ETH");

        bytes memory sig = _sign(agent, address(wallet), address(target), 0.5 ether, 1, validUntil, policyHash);

        // --- [3] Execute while UNVERIFIED -> blocked -------------------------
        console2.log("\n[3] Agent acts while UNVERIFIED (no ERC-8126 score yet)...");
        console2.log("    anchor.getLatestRiskScore =", anchor.getLatestRiskScore(AGENT_ID), "(fail-closed)");
        try wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig) {
            console2.log("    UNEXPECTED: action succeeded");
        } catch {
            console2.log("    -> BLOCKED. Unverified = max risk. OK");
        }

        // --- [4] Verify: relayer publishes a low-risk score ------------------
        uint8 risk = 15; // Low Risk
        vm.prank(relayer);
        anchor.setScore(AGENT_ID, risk);
        console2.log("\n[4] Relayer (oracle) published score. risk =", risk);
        console2.log("    anchor.getLatestRiskScore =", anchor.getLatestRiskScore(AGENT_ID));

        // --- [5] Execute while VERIFIED low-risk -> allowed ------------------
        console2.log("\n[5] Agent acts while VERIFIED low-risk...");
        uint256 balBefore = address(target).balance;
        (bool ok,) = wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
        console2.log("    success     =", ok);
        console2.log("    target +ETH =", address(target).balance - balBefore);
        console2.log("\n=== Reference flow complete: unverified blocked, verified allowed ===");
    }

    function _sign(
        address agent,
        address walletAddr,
        address target,
        uint256 value,
        uint256 nonce,
        uint256 validUntil,
        bytes32 policyHash
    ) internal view returns (bytes memory) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("ERC8196Wallet")),
                keccak256(bytes("1")),
                block.chainid,
                walletAddr
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                TYPEHASH,
                agent,
                keccak256(bytes("transfer")),
                target,
                value,
                keccak256(""),
                nonce,
                validUntil,
                policyHash,
                bytes32(0)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, digest);
        return abi.encodePacked(r, s, v);
    }
}
