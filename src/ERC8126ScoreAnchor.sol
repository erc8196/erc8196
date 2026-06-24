// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IERC8126} from "./interfaces/IERC8126.sol";

/// @title ERC8126ScoreAnchor — on-chain anchor for off-chain ERC-8126 risk scores.
/// @notice The on-chain half of the verification "bridge". An off-chain relayer (fed by
///         the erc8126scan verification provider) writes each agent's latest MEAN risk
///         score here, so ERC-8196 wallets can read it trustlessly through the ERC-8126
///         `getLatestRiskScore` surface.
/// @dev    NON-NORMATIVE reference component (the bridge's on-chain side).
///
///         ROLE SPLIT (security):
///           - `admin`  — cold key / multisig (e.g. the CENTRY deployer). Deploys this
///                        contract and may ROTATE the oracle. Does not write scores.
///           - `oracle` — the relayer's HOT key. May ONLY write/revoke scores. Disposable;
///                        if compromised, the worst case is wrong scores until rotated.
///
///         FAIL-CLOSED: an agent with no attestation (or a revoked one) reads as 100
///         (max risk). So an unverified agent is blocked by any policy with
///         maxRisk < 100 — "no verification = treated as maximum risk = blocked".
///
///         FRESHNESS: attestations expire after `maxScoreAge` (admin-settable, default
///         24h). Past that age `getLatestRiskScore` returns 100 (fail-closed) — so a
///         stale score blocks execution trustlessly, even if the relayer stops. This is
///         enforced behind the plain ERC-8126 `getLatestRiskScore` surface, so the wallet
///         needs no extra interface and stays provider-agnostic. `getAttestation` also
///         exposes `updatedAt` for consumers wanting their own age checks.
contract ERC8126ScoreAnchor is IERC8126 {
    /// @dev Sentinel returned for any agent without a live attestation (fail-closed).
    uint8 public constant UNVERIFIED_RISK = 100;

    struct Attestation {
        uint8 risk; // 0..100 mean risk, ERC-8126 polarity (higher = worse)
        bool verified; // false until the oracle attests; false again once revoked
        uint64 updatedAt; // block timestamp of the last write (freshness)
    }

    address public admin;
    address public pendingAdmin;
    address public oracle;
    /// @notice Max age of an attestation before it is treated as stale (fail-closed).
    ///         0 disables expiry. Admin-settable; defaults to 24h.
    uint64 public maxScoreAge;
    mapping(uint256 => Attestation) private _attestations;

    event OracleUpdated(address indexed previousOracle, address indexed newOracle);
    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event MaxScoreAgeUpdated(uint64 previousMaxScoreAge, uint64 newMaxScoreAge);
    event ScoreUpdated(uint256 indexed agentId, uint8 risk, uint64 updatedAt);
    event ScoreRevoked(uint256 indexed agentId);

    error NotAdmin();
    error NotPendingAdmin();
    error NotOracle();
    error ZeroAddress();
    error InvalidRisk(uint8 risk);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyOracle() {
        if (msg.sender != oracle) revert NotOracle();
        _;
    }

    constructor(address admin_, address oracle_) {
        if (admin_ == address(0) || oracle_ == address(0)) revert ZeroAddress();
        admin = admin_;
        oracle = oracle_;
        maxScoreAge = 1 days;
        emit AdminTransferred(address(0), admin_);
        emit OracleUpdated(address(0), oracle_);
        emit MaxScoreAgeUpdated(0, 1 days);
    }

    /* ----------------------------- admin (cold) ----------------------------- */

    /// @notice Rotate the relayer/oracle key. Use after a suspected hot-key compromise.
    function setOracle(address newOracle) external onlyAdmin {
        if (newOracle == address(0)) revert ZeroAddress();
        emit OracleUpdated(oracle, newOracle);
        oracle = newOracle;
    }

    /// @notice Set the staleness window. Past this age an attestation reads fail-closed
    ///         (100 / unverified). 0 disables expiry. (SCSVS S5.2 — handle data latency.)
    function setMaxScoreAge(uint64 newMaxScoreAge) external onlyAdmin {
        emit MaxScoreAgeUpdated(maxScoreAge, newMaxScoreAge);
        maxScoreAge = newMaxScoreAge;
    }

    /// @notice Step 1 of admin handover: nominate a new admin (cold key / multisig).
    ///         Two-step (SCSVS S1.1.A5) so a typo'd address can't brick the contract —
    ///         the nominee must call `acceptAdmin` to take over.
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    /// @notice Step 2 of admin handover: the nominee accepts and becomes admin.
    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        emit AdminTransferred(admin, pendingAdmin);
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }

    /* ----------------------------- oracle (hot) ----------------------------- */

    /// @notice Publish/refresh an agent's latest mean risk score and mark it verified.
    ///         Accepts downgrades (clean -> risky) as well as improvements.
    function setScore(uint256 agentId, uint8 risk) external onlyOracle {
        if (risk > 100) revert InvalidRisk(risk);
        _attestations[agentId] = Attestation({risk: risk, verified: true, updatedAt: uint64(block.timestamp)});
        emit ScoreUpdated(agentId, risk, uint64(block.timestamp));
    }

    /// @notice Revoke an attestation (expired/stale, or agent went bad with no fresh score).
    ///         Reverts the agent to fail-closed: it reads as 100 / unverified again.
    function revoke(uint256 agentId) external onlyOracle {
        delete _attestations[agentId];
        emit ScoreRevoked(agentId);
    }

    /* -------------------------------- reads -------------------------------- */

    /// @dev An attestation is "live" only if it is verified AND within `maxScoreAge`
    ///      (or expiry is disabled). Stale/unverified/revoked → not live → fail-closed.
    function _isLive(Attestation storage a) internal view returns (bool) {
        if (!a.verified) return false;
        if (maxScoreAge != 0 && block.timestamp - a.updatedAt > maxScoreAge) return false;
        return true;
    }

    /// @inheritdoc IERC8126
    /// @dev Fail-closed: unverified, revoked, or stale agents read as `UNVERIFIED_RISK` (100).
    function getLatestRiskScore(uint256 agentId) external view returns (uint8) {
        return _isLive(_attestations[agentId]) ? _attestations[agentId].risk : UNVERIFIED_RISK;
    }

    /// @notice Full attestation for consumers enforcing verification + freshness explicitly.
    /// @return risk      Effective risk (sentinel 100 if not live).
    /// @return verified  Whether a live (verified AND fresh) attestation exists.
    /// @return updatedAt Timestamp of the last write (0 if never written), even if now stale.
    function getAttestation(uint256 agentId) external view returns (uint8 risk, bool verified, uint64 updatedAt) {
        Attestation storage a = _attestations[agentId];
        bool live = _isLive(a);
        return (live ? a.risk : UNVERIFIED_RISK, live, a.updatedAt);
    }
}
