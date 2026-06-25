// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ValidationRegistryAdapter} from "../src/ValidationRegistryAdapter.sol";
import {ERC8196Wallet} from "../src/ERC8196Wallet.sol";
import {IERC8196} from "../src/interfaces/IERC8196.sol";
import {MockValidationRegistry, MockTarget} from "./mocks/Mocks.sol";

/// @title ValidationRegistryAdapter tests — ERC-8004 as the store, ERC-8126 as the surface.
/// @notice Covers polarity inversion, fail-closed (missing/wrong-validator/out-of-range/stale),
///         admin controls, and an end-to-end gate through the real wallet.
contract ValidationRegistryAdapterTest is Test {
    MockValidationRegistry internal registry;
    ValidationRegistryAdapter internal adapter;

    address internal validator = makeAddr("erc8126scan"); // the trusted ERC-8126 validator
    address internal admin = makeAddr("admin");
    address internal stranger = makeAddr("stranger");
    string internal constant TAG = "ERC8126-RISK";

    uint256 internal constant AGENT_ID = 7;

    function setUp() public {
        vm.warp(1_000_000);
        registry = new MockValidationRegistry();
        adapter = new ValidationRegistryAdapter(address(registry), validator, TAG, admin);
    }

    /// @dev Write a passed-polarity score (100 - risk) into 8004 at the canonical hash.
    function _attest(uint256 agentId, uint8 risk, address asValidator) internal {
        bytes32 rh = adapter.requestHashFor(agentId);
        registry.validationRequest(asValidator, agentId, "", rh);
        registry.validationResponse(rh, uint8(100 - risk), "", bytes32(0), TAG);
    }

    /* ------------------------------ polarity ------------------------------ */

    function test_PassedScoreInvertsToRisk() public {
        _attest(AGENT_ID, 15, validator); // risk 15 -> passed 85 in the registry
        assertEq(adapter.getLatestRiskScore(AGENT_ID), 15);
        (uint8 risk, bool verified,) = adapter.getAttestation(AGENT_ID);
        assertEq(risk, 15);
        assertTrue(verified);
    }

    /* ------------------------------ fail-closed ------------------------------ */

    function test_NoValidation_FailClosed() public view {
        assertEq(adapter.getLatestRiskScore(AGENT_ID), 100);
    }

    function test_WrongValidator_FailClosed() public {
        // An attacker writes a clean score, but as themselves, not the trusted validator.
        _attest(AGENT_ID, 0, stranger); // passed 100 / risk 0 — should be ignored
        assertEq(adapter.getLatestRiskScore(AGENT_ID), 100, "untrusted validator must be ignored");
    }

    function test_OutOfRangeResponse_FailClosed() public {
        bytes32 rh = adapter.requestHashFor(AGENT_ID);
        registry.validationRequest(validator, AGENT_ID, "", rh);
        registry.validationResponse(rh, 200, "", bytes32(0), TAG); // invalid passed score
        assertEq(adapter.getLatestRiskScore(AGENT_ID), 100);
    }

    function test_StaleValidation_FailClosed() public {
        _attest(AGENT_ID, 10, validator);
        assertEq(adapter.getLatestRiskScore(AGENT_ID), 10);
        vm.warp(block.timestamp + 1 days + 1);
        assertEq(adapter.getLatestRiskScore(AGENT_ID), 100);
    }

    function test_FreshWithinTTL() public {
        _attest(AGENT_ID, 10, validator);
        vm.warp(block.timestamp + 23 hours);
        assertEq(adapter.getLatestRiskScore(AGENT_ID), 10);
    }

    /* ------------------------------ admin ------------------------------ */

    function test_SetMaxScoreAge_OnlyAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(ValidationRegistryAdapter.NotAdmin.selector);
        adapter.setMaxScoreAge(1 hours);
    }

    function test_TwoStepAdminTransfer() public {
        address newAdmin = makeAddr("newAdmin");
        vm.prank(admin);
        adapter.transferAdmin(newAdmin);
        assertEq(adapter.admin(), admin);
        vm.prank(newAdmin);
        adapter.acceptAdmin();
        assertEq(adapter.admin(), newAdmin);
    }

    function test_Constructor_RejectsZeroAddresses() public {
        vm.expectRevert(ValidationRegistryAdapter.ZeroAddress.selector);
        new ValidationRegistryAdapter(address(0), validator, TAG, admin);
    }

    /* ------------------------------ end-to-end through the wallet ------------------------------ */

    function test_EndToEnd_WalletGatesOnAdapter() public {
        uint256 agentPk = 0xA11CE;
        address agent = vm.addr(agentPk);

        MockTarget target = new MockTarget();

        // Wallet uses the ADAPTER (8004-backed) as its ERC-8126 verifier.
        ERC8196Wallet wallet = new ERC8196Wallet(address(adapter), address(registry));
        vm.deal(address(wallet), 10 ether);

        uint256 validUntil = block.timestamp + 10 days;
        string[] memory actions = new string[](1);
        actions[0] = "transfer";
        address[] memory allowed = new address[](1);
        allowed[0] = address(target);
        address[] memory blocked = new address[](0);
        bytes32 policyHash =
            wallet.registerPolicy(agent, AGENT_ID, actions, allowed, blocked, 1 ether, 2 ether, 0, validUntil, 50);

        bytes memory sig = _sign(agentPk, agent, address(wallet), address(target), 0.5 ether, 1, validUntil, policyHash);

        // No validation in 8004 yet -> adapter returns 100 -> blocked.
        vm.expectRevert(
            abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "risk score exceeds threshold")
        );
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);

        // erc8126scan validates the agent as low risk (15) in the 8004 registry.
        _attest(AGENT_ID, 15, validator);

        (bool ok,) = wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
        assertTrue(ok);
        assertEq(address(target).balance, 0.5 ether);
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
        bytes32 typehash = keccak256(
            "AgentAction(address agent,string action,address target,uint256 value,"
            "bytes data,uint256 nonce,uint256 validUntil,bytes32 policyHash,bytes32 entropyCommitment)"
        );
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
                typehash,
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
