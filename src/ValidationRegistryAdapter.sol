// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IERC8126} from "./interfaces/IERC8126.sol";
import {IERC8004Validation} from "./interfaces/IERC8004Validation.sol";

/// @title ValidationRegistryAdapter — ERC-8126 read surface over the ERC-8004 Validation Registry.
/// @notice Lets an ERC-8196 wallet consume risk scores that an ERC-8126 provider (erc8126scan)
///         writes into the canonical ERC-8004 Validation Registry — WITHOUT this contract
///         storing any score itself. The registry is the single source of truth; this is a
///         thin, read-only adapter that presents the bare `getLatestRiskScore` surface so the
///         wallet stays provider-agnostic.
/// @dev    NON-NORMATIVE. Verified against OWASP SCSVS 0.0.1:
///           - S5.1.B minimal trusted surface: binds to ONE immutable validator + registry.
///           - S5.2.A2 validate oracle data: rejects out-of-range responses (>100).
///           - S5.2.A3 fallback on oracle failure: missing/stale/invalid → fail-closed (100).
///           - S5.2 latency: `maxScoreAge` TTL (admin-settable, default 24h).
///           - S1.1.A5 two-step admin transfer.
///           - S9.3.A events for all critical changes.
///
///         POLARITY: ERC-8004 `response` is "passed" polarity (0 = failed .. 100 = passed,
///         high = GOOD). ERC-8126/ERC-8196 use RISK polarity (high = BAD). The inversion
///         `risk = 100 - response` happens HERE, in one place. An agent with no validation
///         reads `response = 0` → `risk = 100` → blocked: fail-closed for free.
contract ValidationRegistryAdapter is IERC8126 {
    /// @dev Sentinel risk for any agent without a live, valid, in-range, fresh attestation.
    uint8 public constant UNVERIFIED_RISK = 100;

    /// @notice The canonical ERC-8004 Validation Registry (single source of truth).
    IERC8004Validation public immutable validationRegistry;
    /// @notice The one ERC-8126 validator whose responses are trusted (erc8126scan).
    address public immutable validator;
    /// @notice Tag binding the canonical per-agent risk validation.
    string public tag;

    address public admin;
    address public pendingAdmin;
    /// @notice Max age of a validation before it is treated as stale (0 disables). Default 24h.
    uint64 public maxScoreAge;

    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event MaxScoreAgeUpdated(uint64 previousMaxScoreAge, uint64 newMaxScoreAge);

    error NotAdmin();
    error NotPendingAdmin();
    error ZeroAddress();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(address validationRegistry_, address validator_, string memory tag_, address admin_) {
        if (validationRegistry_ == address(0) || validator_ == address(0) || admin_ == address(0)) {
            revert ZeroAddress();
        }
        validationRegistry = IERC8004Validation(validationRegistry_);
        validator = validator_;
        tag = tag_;
        admin = admin_;
        maxScoreAge = 1 days;
        emit AdminTransferred(address(0), admin_);
        emit MaxScoreAgeUpdated(0, 1 days);
    }

    /* ------------------------------ admin (cold) ------------------------------ */

    /// @notice Step 1: nominate a new admin. Two-step (SCSVS S1.1.A5).
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    /// @notice Step 2: nominee accepts and becomes admin.
    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        emit AdminTransferred(admin, pendingAdmin);
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }

    /// @notice Set the staleness window (0 disables expiry). (SCSVS S5.2 — handle latency.)
    function setMaxScoreAge(uint64 newMaxScoreAge) external onlyAdmin {
        emit MaxScoreAgeUpdated(maxScoreAge, newMaxScoreAge);
        maxScoreAge = newMaxScoreAge;
    }

    /* -------------------------------- reads -------------------------------- */

    /// @notice Deterministic requestHash binding an agent's canonical risk validation.
    ///         The relayer/validator MUST use this same hash when writing to ERC-8004.
    function requestHashFor(uint256 agentId) public view returns (bytes32) {
        return keccak256(abi.encode(validator, agentId, tag));
    }

    /// @inheritdoc IERC8126
    /// @dev Fail-closed: no validation, wrong validator, out-of-range, or stale → 100.
    function getLatestRiskScore(uint256 agentId) external view returns (uint8) {
        (uint8 risk, bool live,) = _read(agentId);
        return live ? risk : UNVERIFIED_RISK;
    }

    /// @notice Full attestation for consumers wanting explicit verification/freshness.
    function getAttestation(uint256 agentId) external view returns (uint8 risk, bool verified, uint64 updatedAt) {
        (uint8 r, bool live, uint64 ts) = _read(agentId);
        return (live ? r : UNVERIFIED_RISK, live, ts);
    }

    /// @dev Reads the canonical 8004 validation, validates it, and inverts polarity.
    function _read(uint256 agentId) internal view returns (uint8 risk, bool live, uint64 updatedAt) {
        (address v, uint256 aId, uint8 response,,, uint256 lastUpdate) =
            validationRegistry.getValidationStatus(requestHashFor(agentId));
        updatedAt = uint64(lastUpdate);

        // S5.1.B / S5.2.A2: only the trusted validator, for this exact agent.
        if (v != validator || aId != agentId) return (UNVERIFIED_RISK, false, updatedAt);
        // S5.2.A2: validate range — passed score must be 0..100.
        if (response > 100) return (UNVERIFIED_RISK, false, updatedAt);
        // S5.2: staleness.
        if (maxScoreAge != 0 && block.timestamp - lastUpdate > maxScoreAge) {
            return (UNVERIFIED_RISK, false, updatedAt);
        }
        // ERC-8004 passed-polarity -> ERC-8126 risk polarity.
        return (100 - response, true, updatedAt);
    }
}
