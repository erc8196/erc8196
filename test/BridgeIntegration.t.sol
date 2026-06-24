// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC8196Wallet} from "../src/ERC8196Wallet.sol";
import {IERC8196} from "../src/interfaces/IERC8196.sol";
import {ERC8126ScoreAnchor} from "../src/ERC8126ScoreAnchor.sol";
import {MockIdentityRegistry, MockValidationRegistry, MockTarget} from "./mocks/Mocks.sol";

/// @title Bridge integration — ERC8196Wallet reads risk from a real ERC8126ScoreAnchor.
/// @notice Proves the end-to-end rule at the point of execution:
///         no attestation -> 100 -> BLOCKED; verified low risk -> ALLOWED;
///         verified high risk -> BLOCKED; revoked -> BLOCKED again.
contract BridgeIntegrationTest is Test {
    bytes32 internal constant AGENT_ACTION_TYPEHASH = keccak256(
        "AgentAction(address agent,string action,address target,uint256 value,"
        "bytes data,uint256 nonce,uint256 validUntil,bytes32 policyHash," "bytes32 entropyCommitment)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    ERC8196Wallet internal wallet;
    ERC8126ScoreAnchor internal anchor;
    MockIdentityRegistry internal identity;
    MockValidationRegistry internal validation;
    MockTarget internal target;

    address internal admin = makeAddr("admin"); // cold key (stands in for CENTRY/multisig)
    address internal relayer = makeAddr("relayer"); // hot oracle key

    uint256 internal constant AGENT_PK = 0xA11CE;
    address internal agent;
    uint256 internal constant AGENT_ID = 1;
    uint8 internal constant MAX_RISK = 50; // policy ceiling

    uint256 internal validUntil;
    bytes32 internal policyHash;

    function setUp() public {
        vm.warp(1_000_000);
        agent = vm.addr(AGENT_PK);

        identity = new MockIdentityRegistry();
        validation = new MockValidationRegistry();
        // admin deploys the anchor and names the relayer as oracle (role split).
        vm.prank(admin);
        anchor = new ERC8126ScoreAnchor(admin, relayer);

        // wallet uses the anchor as its ERC-8126 verifier
        wallet = new ERC8196Wallet(address(identity), address(anchor), address(validation));

        identity.setAgentId(agent, AGENT_ID);
        target = new MockTarget();
        vm.deal(address(wallet), 100 ether);

        validUntil = block.timestamp + 10 days;
        policyHash = _register();
    }

    function _register() internal returns (bytes32) {
        string[] memory actions = new string[](1);
        actions[0] = "transfer";
        address[] memory allowed = new address[](1);
        allowed[0] = address(target);
        address[] memory blocked = new address[](0);
        return wallet.registerPolicy(agent, actions, allowed, blocked, 1 ether, 2 ether, 0, validUntil, MAX_RISK);
    }

    function _sign(uint256 value, uint256 nonce) internal view returns (bytes memory) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("ERC8196Wallet")),
                keccak256(bytes("1")),
                block.chainid,
                address(wallet)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                AGENT_ACTION_TYPEHASH,
                agent,
                keccak256(bytes("transfer")),
                address(target),
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

    function _exec(uint256 value, uint256 nonce) internal returns (bool) {
        (bool ok,) =
            wallet.executeAction(policyHash, address(target), value, "", nonce, bytes32(0), _sign(value, nonce));
        return ok;
    }

    /// @dev The whole point: a never-verified agent is blocked at execution, because the
    ///      anchor returns 100 (fail-closed) and the policy ceiling is 50.
    function test_Unverified_IsBlocked() public {
        assertEq(anchor.getLatestRiskScore(AGENT_ID), 100, "unverified should read 100");
        vm.expectRevert(
            abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "risk score exceeds threshold")
        );
        _exec(0.5 ether, 1);
    }

    function test_VerifiedLowRisk_IsAllowed() public {
        vm.prank(relayer);
        anchor.setScore(AGENT_ID, 15); // Low Risk

        assertTrue(_exec(0.5 ether, 1));
        assertEq(address(target).balance, 0.5 ether);
    }

    function test_VerifiedHighRisk_IsBlocked() public {
        vm.prank(relayer);
        anchor.setScore(AGENT_ID, 60); // above the 50 ceiling

        vm.expectRevert(
            abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "risk score exceeds threshold")
        );
        _exec(0.5 ether, 1);
    }

    function test_Revoked_IsBlockedAgain() public {
        vm.prank(relayer);
        anchor.setScore(AGENT_ID, 15);
        assertTrue(_exec(0.5 ether, 1)); // works while verified

        vm.prank(relayer);
        anchor.revoke(AGENT_ID); // agent went bad / score expired

        vm.expectRevert(
            abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "risk score exceeds threshold")
        );
        _exec(0.5 ether, 2);
    }

    /// @dev A score that ages past the anchor's 24h TTL blocks execution trustlessly —
    ///      even though the relayer never revoked it.
    function test_StaleScore_IsBlocked() public {
        vm.prank(relayer);
        anchor.setScore(AGENT_ID, 10);
        assertTrue(_exec(0.5 ether, 1)); // fresh -> allowed

        vm.warp(block.timestamp + 25 hours); // exceeds the 24h TTL

        vm.expectRevert(
            abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "risk score exceeds threshold")
        );
        _exec(0.5 ether, 2);
    }

    /// @dev Only the named relayer can publish scores that the wallet will trust.
    function test_RandomAddressCannotForgeScore() public {
        vm.prank(makeAddr("attacker"));
        vm.expectRevert(ERC8126ScoreAnchor.NotOracle.selector);
        anchor.setScore(AGENT_ID, 0);
    }
}
