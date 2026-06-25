// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC8196Wallet} from "../src/ERC8196Wallet.sol";
import {IERC8196} from "../src/interfaces/IERC8196.sol";
import {MockVerifier, MockValidationRegistry, MockTarget, ReentrantTarget} from "./mocks/Mocks.sol";

/// @title ERC8196Wallet local test harness — fully offline, deterministic, no funds.
/// @notice Every gate in executeAction has a dedicated revert test, plus a happy
///         path and a polarity test that documents ERC-8126's risk-score semantics
///         (reject when risk exceeds the policy ceiling; no inversion).
contract ERC8196WalletTest is Test {
    bytes32 internal constant AGENT_ACTION_TYPEHASH = keccak256(
        "AgentAction(address agent,string action,address target,uint256 value,"
        "bytes data,uint256 nonce,uint256 validUntil,bytes32 policyHash," "bytes32 entropyCommitment)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    ERC8196Wallet internal wallet;
    MockVerifier internal verifier;
    MockValidationRegistry internal validation;
    MockTarget internal target;

    uint256 internal constant AGENT_PK = 0xA11CE;
    address internal agent;
    address internal owner; // = address(this)

    uint256 internal constant AGENT_ID = 1;
    uint256 internal validUntil;
    bytes32 internal policyHash;

    // shared policy params
    uint256 internal constant MAX_PER_TX = 1 ether;
    uint256 internal constant MAX_PER_DAY = 2 ether;
    // minVerificationScore is a RISK ceiling (ERC-8126 polarity): reject if risk > this.
    uint8 internal constant MAX_RISK = 50;

    function setUp() public {
        vm.warp(1_000_000); // leave room below/above the validity window
        agent = vm.addr(AGENT_PK);
        owner = address(this);

        verifier = new MockVerifier();
        validation = new MockValidationRegistry();
        wallet = new ERC8196Wallet(address(verifier), address(validation));

        verifier.setRisk(AGENT_ID, 10); // low risk, comfortably under MAX_RISK
        target = new MockTarget();
        vm.deal(address(wallet), 100 ether);

        validUntil = block.timestamp + 10 days; // room to warp for the daily-reset test
        policyHash = _register();
    }

    /* --------------------------- helpers --------------------------- */

    function _register() internal returns (bytes32) {
        string[] memory actions = new string[](1);
        actions[0] = "transfer";
        address[] memory allowed = new address[](1);
        allowed[0] = address(target);
        address[] memory blocked = new address[](0);
        return wallet.registerPolicy(
            agent, AGENT_ID, actions, allowed, blocked, MAX_PER_TX, MAX_PER_DAY, 0, validUntil, MAX_RISK
        );
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("ERC8196Wallet")),
                keccak256(bytes("1")),
                block.chainid,
                address(wallet)
            )
        );
    }

    /// @dev Build a signature for `action` over the given call. `signerPk` lets a
    ///      test sign with the wrong key to exercise InvalidSignature.
    function _sign(
        uint256 signerPk,
        string memory action,
        address tgt,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        bytes32 entropyCommitment
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                AGENT_ACTION_TYPEHASH,
                agent,
                keccak256(bytes(action)),
                tgt,
                value,
                keccak256(data),
                nonce,
                validUntil,
                policyHash,
                entropyCommitment
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Convenience: sign a valid "transfer" of `value` to `target` at `nonce`.
    function _validSig(uint256 value, uint256 nonce) internal view returns (bytes memory) {
        return _sign(AGENT_PK, "transfer", address(target), value, "", nonce, bytes32(0));
    }

    /* --------------------------- happy path --------------------------- */

    function test_Execute_HappyPath() public {
        bytes memory sig = _validSig(0.5 ether, 1);

        vm.expectEmit(true, true, false, false);
        emit IERC8196.ActionExecuted(policyHash, agent, address(target), 0.5 ether, bytes32(0));

        (bool success,) = wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
        assertTrue(success);
        assertEq(address(target).balance, 0.5 ether);
        assertEq(target.callCount(), 1);
    }

    /* --------------------------- gate reverts --------------------------- */

    function test_Revert_InactivePolicy() public {
        wallet.revokePolicy(policyHash, "done");
        bytes memory sig = _validSig(0.5 ether, 1);
        vm.expectRevert(abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "inactive policy"));
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
    }

    function test_Revert_Expired() public {
        vm.warp(validUntil + 1);
        bytes memory sig = _validSig(0.5 ether, 1);
        vm.expectRevert(abi.encodeWithSelector(IERC8196.PolicyExpired.selector, policyHash, validUntil));
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
    }

    function test_Revert_TargetNotAllowed() public {
        address stranger = address(0xBEEF);
        bytes memory sig = _sign(AGENT_PK, "transfer", stranger, 0.5 ether, "", 1, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "target not allowed"));
        wallet.executeAction(policyHash, stranger, 0.5 ether, "", 1, bytes32(0), sig);
    }

    function test_Revert_ValueExceedsPerTx() public {
        uint256 tooMuch = MAX_PER_TX + 1;
        bytes memory sig = _validSig(tooMuch, 1);
        vm.expectRevert(abi.encodeWithSelector(IERC8196.ValueExceedsLimit.selector, tooMuch, MAX_PER_TX));
        wallet.executeAction(policyHash, address(target), tooMuch, "", 1, bytes32(0), sig);
    }

    function test_Revert_DailyCapExceeded() public {
        // First 1 ETH ok (== per-tx limit, under daily 2 ETH).
        wallet.executeAction(policyHash, address(target), 1 ether, "", 1, bytes32(0), _validSig(1 ether, 1));
        // Second 1.5 ETH exceeds per-tx limit first; use 1 ETH again -> daily total 2 ETH ok,
        // then a third pushes over the daily cap.
        wallet.executeAction(policyHash, address(target), 1 ether, "", 2, bytes32(0), _validSig(1 ether, 2));
        bytes memory sig = _validSig(1 ether, 3);
        vm.expectRevert(abi.encodeWithSelector(IERC8196.ValueExceedsLimit.selector, 1 ether, MAX_PER_DAY));
        wallet.executeAction(policyHash, address(target), 1 ether, "", 3, bytes32(0), sig);
    }

    function test_DailyCapResetsNextDay() public {
        wallet.executeAction(policyHash, address(target), 1 ether, "", 1, bytes32(0), _validSig(1 ether, 1));
        wallet.executeAction(policyHash, address(target), 1 ether, "", 2, bytes32(0), _validSig(1 ether, 2));
        vm.warp(block.timestamp + 1 days);
        // New UTC day -> bucket resets, another 1 ETH succeeds.
        (bool ok,) =
            wallet.executeAction(policyHash, address(target), 1 ether, "", 3, bytes32(0), _validSig(1 ether, 3));
        assertTrue(ok);
    }

    function test_Revert_NonceReplay() public {
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), _validSig(0.5 ether, 1));
        bytes memory sig = _validSig(0.5 ether, 1);
        vm.expectRevert(abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "nonce used"));
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
    }

    function test_Revert_RiskExceedsThreshold() public {
        verifier.setRisk(AGENT_ID, MAX_RISK + 1); // 51 > 50 ceiling
        bytes memory sig = _validSig(0.5 ether, 1);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "risk score exceeds threshold")
        );
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
    }

    function test_Revert_BadSignature() public {
        uint256 wrongPk = 0xBADBAD;
        bytes memory sig = _sign(wrongPk, "transfer", address(target), 0.5 ether, "", 1, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(IERC8196.InvalidSignature.selector, address(0), agent));
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
    }

    function test_Revert_ActionNotInAllowedSet() public {
        // Correctly signed, but "withdraw" is not in allowedActions -> no candidate matches.
        bytes memory sig = _sign(AGENT_PK, "withdraw", address(target), 0.5 ether, "", 1, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(IERC8196.InvalidSignature.selector, address(0), agent));
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
    }

    function test_Revert_RevokeNotOwner() public {
        vm.prank(address(0xD00D));
        vm.expectRevert(abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "not owner"));
        wallet.revokePolicy(policyHash, "nope");
    }

    function test_RegisterUnregisteredAgent_NoLongerReverts() public {
        // Registration MUST removed (ERC-8196): registering an unregistered agent succeeds,
        // but it is blocked at execution by the fail-closed ERC-8126 gate (see BridgeIntegration).
        address ghost = address(0x9999);
        string[] memory actions = new string[](1);
        actions[0] = "transfer";
        address[] memory allowed = new address[](0);
        address[] memory blocked = new address[](0);
        bytes32 ph =
            wallet.registerPolicy(ghost, 999, actions, allowed, blocked, 1 ether, 2 ether, 0, validUntil, MAX_RISK);
        assertTrue(ph != bytes32(0));
    }

    function test_Revert_PolicyListTooLarge() public {
        // SCSVS S8.1.A: 101 allowed actions exceeds the MAX_POLICY_ENTRIES bound (100).
        string[] memory actions = new string[](101);
        for (uint256 i; i < actions.length; ++i) {
            actions[i] = "transfer";
        }
        address[] memory allowed = new address[](1);
        allowed[0] = address(target);
        address[] memory blocked = new address[](0);
        vm.expectRevert(abi.encodeWithSelector(IERC8196.PolicyViolation.selector, bytes32(0), "policy list too large"));
        wallet.registerPolicy(agent, AGENT_ID, actions, allowed, blocked, 1 ether, 2 ether, 0, validUntil, MAX_RISK);
    }

    function test_Revert_MaxValuePerDayTooLarge() public {
        // SCSVS S7.1.A1: above uint192 max -> rejected at registration, never at cast time.
        uint256 tooBig = uint256(type(uint192).max) + 1;
        string[] memory actions = new string[](1);
        actions[0] = "transfer";
        address[] memory allowed = new address[](1);
        allowed[0] = address(target);
        address[] memory blocked = new address[](0);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8196.PolicyViolation.selector, bytes32(0), "maxValuePerDay too large")
        );
        wallet.registerPolicy(agent, AGENT_ID, actions, allowed, blocked, 1 ether, tooBig, 0, validUntil, MAX_RISK);
    }

    function test_Revert_Reentrancy() public {
        ReentrantTarget attacker = new ReentrantTarget(wallet);
        // Register a policy whose target is the attacker.
        string[] memory actions = new string[](1);
        actions[0] = "transfer";
        address[] memory allowed = new address[](1);
        allowed[0] = address(attacker);
        address[] memory blocked = new address[](0);
        bytes32 ph = wallet.registerPolicy(
            agent, AGENT_ID, actions, allowed, blocked, MAX_PER_TX, MAX_PER_DAY, 0, validUntil, MAX_RISK
        );

        // Re-sign against the new policyHash.
        policyHash = ph; // _sign reads policyHash
        bytes memory sig = _sign(AGENT_PK, "transfer", address(attacker), 0.5 ether, "", 1, bytes32(0));

        // Re-entry trips ReentrancyGuard -> inner call reverts -> outer "call failed".
        vm.expectRevert(abi.encodeWithSelector(IERC8196.PolicyViolation.selector, ph, "call failed"));
        wallet.executeAction(ph, address(attacker), 0.5 ether, "", 1, bytes32(0), sig);
    }

    /* --------------------------- owner withdraw --------------------------- */

    function test_Withdraw_OwnerCanReclaim() public {
        address recipient = makeAddr("recipient");
        // owner == address(this), the deployer in setUp.
        vm.expectEmit(true, false, false, true);
        emit ERC8196Wallet.Withdrawal(recipient, 1 ether);
        wallet.withdraw(recipient, 1 ether);
        assertEq(recipient.balance, 1 ether);
    }

    function test_Withdraw_OnlyOwner() public {
        vm.prank(makeAddr("notOwner"));
        vm.expectRevert(ERC8196Wallet.NotOwner.selector);
        wallet.withdraw(makeAddr("recipient"), 1 ether);
    }

    /* --------------------------- pause (kill-switch) --------------------------- */

    function test_Paused_BlocksExecution() public {
        wallet.setPaused(true); // owner == address(this)
        bytes memory sig = _validSig(0.5 ether, 1);
        vm.expectRevert(ERC8196Wallet.WalletPaused.selector);
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
    }

    function test_Unpause_RestoresExecution() public {
        wallet.setPaused(true);
        wallet.setPaused(false);
        (bool ok,) =
            wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), _validSig(0.5 ether, 1));
        assertTrue(ok);
    }

    function test_SetPaused_OnlyOwner() public {
        vm.prank(makeAddr("notOwner"));
        vm.expectRevert(ERC8196Wallet.NotOwner.selector);
        wallet.setPaused(true);
    }

    /* --------------------------- verifier migration --------------------------- */

    function test_SetVerifier_Migration() public {
        // Migrate to a verifier that reports the agent as high risk -> gate now blocks.
        MockVerifier v2 = new MockVerifier();
        v2.setRisk(AGENT_ID, 90);
        wallet.setVerifier(address(v2));
        assertEq(address(wallet.verifier()), address(v2));
        bytes memory sig = _validSig(0.5 ether, 1);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "risk score exceeds threshold")
        );
        wallet.executeAction(policyHash, address(target), 0.5 ether, "", 1, bytes32(0), sig);
    }

    function test_SetVerifier_OnlyOwner() public {
        vm.prank(makeAddr("notOwner"));
        vm.expectRevert(ERC8196Wallet.NotOwner.selector);
        wallet.setVerifier(address(verifier));
    }

    function test_SetVerifier_RejectsZero() public {
        vm.expectRevert(ERC8196Wallet.ZeroAddress.selector);
        wallet.setVerifier(address(0));
    }

    /* --------------------------- fuzz --------------------------- */

    /// @dev Per-tx limit holds for any value: above the cap reverts, at/under executes.
    function testFuzz_PerTxLimit(uint96 value) public {
        value = uint96(bound(value, 0, 5 ether));
        bytes memory sig = _validSig(value, 1);
        if (value > MAX_PER_TX) {
            vm.expectRevert(abi.encodeWithSelector(IERC8196.ValueExceedsLimit.selector, uint256(value), MAX_PER_TX));
            wallet.executeAction(policyHash, address(target), value, "", 1, bytes32(0), sig);
        } else {
            (bool ok,) = wallet.executeAction(policyHash, address(target), value, "", 1, bytes32(0), sig);
            assertTrue(ok);
            assertEq(address(target).balance, value);
        }
    }

    /// @dev Risk ceiling holds for any score: strictly above the ceiling is blocked.
    function testFuzz_RiskCeiling(uint8 risk) public {
        verifier.setRisk(AGENT_ID, risk);
        bytes memory sig = _validSig(0.1 ether, 1);
        if (risk > MAX_RISK) {
            vm.expectRevert(
                abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "risk score exceeds threshold")
            );
            wallet.executeAction(policyHash, address(target), 0.1 ether, "", 1, bytes32(0), sig);
        } else {
            (bool ok,) = wallet.executeAction(policyHash, address(target), 0.1 ether, "", 1, bytes32(0), sig);
            assertTrue(ok);
        }
    }

    /* --------------------------- polarity --------------------------- */

    /// @notice Documents the ERC-8126 (Final) contract: the verifier returns a RISK
    ///         score (0 safe .. 100 dangerous) directly — NO `100 - risk` inversion. The
    ///         wallet rejects when risk EXCEEDS the policy's minVerificationScore (the
    ///         max tolerated risk). With a ceiling of 50: a "Low Risk" agent (risk 15)
    ///         passes; an "Elevated" agent (risk 55) is blocked.
    function test_Polarity_RiskCeilingGatesCorrectly() public {
        // Low Risk: risk = 15 <= 50 -> passes.
        verifier.setRisk(AGENT_ID, 15);
        (bool ok,) =
            wallet.executeAction(policyHash, address(target), 0.1 ether, "", 1, bytes32(0), _validSig(0.1 ether, 1));
        assertTrue(ok, "low-risk agent should pass");

        // Elevated: risk = 55 > 50 -> blocked.
        verifier.setRisk(AGENT_ID, 55);
        bytes memory sig = _validSig(0.1 ether, 2);
        vm.expectRevert(
            abi.encodeWithSelector(IERC8196.PolicyViolation.selector, policyHash, "risk score exceeds threshold")
        );
        wallet.executeAction(policyHash, address(target), 0.1 ether, "", 2, bytes32(0), sig);
    }
}
