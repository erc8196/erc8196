// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC8126ScoreAnchor} from "../src/ERC8126ScoreAnchor.sol";

/// @title ERC8126ScoreAnchor unit tests — access control, fail-closed, freshness.
contract ERC8126ScoreAnchorTest is Test {
    ERC8126ScoreAnchor internal anchor;

    address internal admin = makeAddr("admin"); // cold key / multisig
    address internal oracle = makeAddr("oracle"); // relayer hot key
    address internal stranger = makeAddr("stranger");

    uint256 internal constant AGENT_ID = 42;

    function setUp() public {
        vm.warp(1_000_000);
        anchor = new ERC8126ScoreAnchor(admin, oracle);
    }

    /* ----------------------------- fail-closed ----------------------------- */

    function test_Unverified_ReadsAsMaxRisk() public view {
        // Never attested -> 100, not 0.
        assertEq(anchor.getLatestRiskScore(AGENT_ID), 100);
        (uint8 risk, bool verified, uint64 updatedAt) = anchor.getAttestation(AGENT_ID);
        assertEq(risk, 100);
        assertFalse(verified);
        assertEq(updatedAt, 0);
    }

    function test_Revoke_RevertsToFailClosed() public {
        vm.prank(oracle);
        anchor.setScore(AGENT_ID, 10);
        assertEq(anchor.getLatestRiskScore(AGENT_ID), 10);

        vm.prank(oracle);
        anchor.revoke(AGENT_ID);
        assertEq(anchor.getLatestRiskScore(AGENT_ID), 100);
        (, bool verified,) = anchor.getAttestation(AGENT_ID);
        assertFalse(verified);
    }

    /* ----------------------------- oracle writes ----------------------------- */

    function test_SetScore_StoresValueAndFreshness() public {
        vm.prank(oracle);
        anchor.setScore(AGENT_ID, 35);

        (uint8 risk, bool verified, uint64 updatedAt) = anchor.getAttestation(AGENT_ID);
        assertEq(risk, 35);
        assertTrue(verified);
        assertEq(updatedAt, uint64(block.timestamp));
    }

    function test_SetScore_AcceptsDowngrade() public {
        vm.startPrank(oracle);
        anchor.setScore(AGENT_ID, 5); // clean
        anchor.setScore(AGENT_ID, 90); // went bad -> must overwrite
        vm.stopPrank();
        assertEq(anchor.getLatestRiskScore(AGENT_ID), 90);
    }

    function test_SetScore_RevertsAbove100() public {
        vm.prank(oracle);
        vm.expectRevert(abi.encodeWithSelector(ERC8126ScoreAnchor.InvalidRisk.selector, uint8(101)));
        anchor.setScore(AGENT_ID, 101);
    }

    /* ----------------------------- access control ----------------------------- */

    function test_SetScore_OnlyOracle() public {
        vm.prank(stranger);
        vm.expectRevert(ERC8126ScoreAnchor.NotOracle.selector);
        anchor.setScore(AGENT_ID, 10);
    }

    function test_Revoke_OnlyOracle() public {
        vm.prank(stranger);
        vm.expectRevert(ERC8126ScoreAnchor.NotOracle.selector);
        anchor.revoke(AGENT_ID);
    }

    function test_SetOracle_OnlyAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(ERC8126ScoreAnchor.NotAdmin.selector);
        anchor.setOracle(stranger);
    }

    function test_OracleRotation_OldKeyLosesAccess() public {
        address newOracle = makeAddr("newOracle");
        vm.prank(admin);
        anchor.setOracle(newOracle);

        // old oracle can no longer write
        vm.prank(oracle);
        vm.expectRevert(ERC8126ScoreAnchor.NotOracle.selector);
        anchor.setScore(AGENT_ID, 10);

        // new oracle can
        vm.prank(newOracle);
        anchor.setScore(AGENT_ID, 10);
        assertEq(anchor.getLatestRiskScore(AGENT_ID), 10);
    }

    /* ----------------------------- freshness (TTL) ----------------------------- */

    function test_DefaultMaxScoreAgeIs24h() public view {
        assertEq(anchor.maxScoreAge(), 1 days);
    }

    function test_FreshScore_WithinTTL_IsLive() public {
        vm.prank(oracle);
        anchor.setScore(AGENT_ID, 15);
        vm.warp(block.timestamp + 23 hours);
        assertEq(anchor.getLatestRiskScore(AGENT_ID), 15);
    }

    function test_StaleScore_ReadsAsMaxRisk() public {
        vm.prank(oracle);
        anchor.setScore(AGENT_ID, 15);
        vm.warp(block.timestamp + 1 days + 1);
        assertEq(anchor.getLatestRiskScore(AGENT_ID), 100);
        (uint8 risk, bool verified,) = anchor.getAttestation(AGENT_ID);
        assertEq(risk, 100);
        assertFalse(verified, "stale attestation must read as not-live");
    }

    function test_MaxScoreAgeZero_DisablesExpiry() public {
        vm.prank(admin);
        anchor.setMaxScoreAge(0);
        vm.prank(oracle);
        anchor.setScore(AGENT_ID, 15);
        vm.warp(block.timestamp + 3650 days);
        assertEq(anchor.getLatestRiskScore(AGENT_ID), 15);
    }

    function test_SetMaxScoreAge_OnlyAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(ERC8126ScoreAnchor.NotAdmin.selector);
        anchor.setMaxScoreAge(1 hours);
    }

    /* ----------------------------- two-step admin ----------------------------- */

    function test_TwoStepAdminTransfer() public {
        address newAdmin = makeAddr("newAdmin");

        // step 1: current admin nominates; admin does NOT change yet
        vm.prank(admin);
        anchor.transferAdmin(newAdmin);
        assertEq(anchor.admin(), admin, "admin must not change on nomination");
        assertEq(anchor.pendingAdmin(), newAdmin);

        // a non-nominee cannot accept
        vm.prank(stranger);
        vm.expectRevert(ERC8126ScoreAnchor.NotPendingAdmin.selector);
        anchor.acceptAdmin();

        // step 2: nominee accepts -> becomes admin, pending cleared
        vm.prank(newAdmin);
        anchor.acceptAdmin();
        assertEq(anchor.admin(), newAdmin);
        assertEq(anchor.pendingAdmin(), address(0));

        // old admin has lost privileges
        vm.prank(admin);
        vm.expectRevert(ERC8126ScoreAnchor.NotAdmin.selector);
        anchor.setOracle(stranger);
    }

    function test_TransferAdmin_OnlyAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(ERC8126ScoreAnchor.NotAdmin.selector);
        anchor.transferAdmin(stranger);
    }

    function test_Constructor_RejectsZeroAddresses() public {
        vm.expectRevert(ERC8126ScoreAnchor.ZeroAddress.selector);
        new ERC8126ScoreAnchor(address(0), oracle);
        vm.expectRevert(ERC8126ScoreAnchor.ZeroAddress.selector);
        new ERC8126ScoreAnchor(admin, address(0));
    }
}
