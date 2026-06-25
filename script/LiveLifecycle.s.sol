// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {ERC8196Wallet} from "../src/ERC8196Wallet.sol";

/// @title LiveLifecycle — full executeAction gate against a deployed wallet.
/// @notice Owner registers a policy, funds the wallet, the agent signs an AgentAction,
///         and executeAction runs (value moves). Score for the agentId must already be set
///         on the verifier (<= the policy ceiling).
/// Env: PRIVATE_KEY (owner), AGENT_PK (agent signer), WALLET (deployed), AGENT_ID
contract LiveLifecycle is Script {
    bytes32 constant TYPEHASH = keccak256(
        "AgentAction(address agent,string action,address target,uint256 value,"
        "bytes data,uint256 nonce,uint256 validUntil,bytes32 policyHash,bytes32 entropyCommitment)"
    );

    function run() external {
        uint256 ownerPk = vm.envUint("PRIVATE_KEY");
        uint256 agentPk = vm.envUint("AGENT_PK");
        address payable wallet = payable(vm.envAddress("WALLET"));
        uint256 agentId = vm.envUint("AGENT_ID");

        address agent = vm.addr(agentPk);
        address target = vm.addr(ownerPk); // send value back to the owner (no funds lost)
        ERC8196Wallet w = ERC8196Wallet(wallet);
        uint256 validUntil = block.timestamp + 1 hours;
        uint256 value = 0.001 ether;
        uint256 nonce = 1;

        string[] memory actions = new string[](1);
        actions[0] = "transfer";
        address[] memory allowed = new address[](1);
        allowed[0] = target;
        address[] memory blocked = new address[](0);

        // --- owner: fund wallet + register policy ---
        vm.startBroadcast(ownerPk);
        (bool funded,) = wallet.call{value: 0.003 ether}("");
        require(funded, "fund failed");
        bytes32 policyHash =
            w.registerPolicy(agent, agentId, actions, allowed, blocked, 0.002 ether, 0.002 ether, 0, validUntil, 50);
        vm.stopBroadcast();

        console2.log("agent       :", agent);
        console2.log("agentId     :", agentId);
        console2.log("verifier risk:", w.verifier().getLatestRiskScore(agentId));
        console2.log("policyHash  :");
        console2.logBytes32(policyHash);

        // --- agent signs the AgentAction (off-chain) ---
        bytes memory sig = _sign(agentPk, agent, wallet, target, value, nonce, validUntil, policyHash);

        // --- submit executeAction (anyone may; owner relays) ---
        uint256 before = target.balance;
        vm.broadcast(ownerPk);
        (bool ok,) = w.executeAction(policyHash, target, value, "", nonce, bytes32(0), sig);
        console2.log("executeAction success:", ok);
        console2.log("target +wei          :", target.balance - before);
    }

    function _sign(
        uint256 pk,
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
