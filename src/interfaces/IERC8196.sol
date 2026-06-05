// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC8196 — AI Agent Authenticated Wallet (execution layer)
/// @notice External interface as defined by ERC-8196. Signatures are reproduced
///         verbatim from the specification so that conforming wallets are ABI-compatible.
/// @dev    Spec: https://eips.ethereum.org/EIPS/eip-8196 (Draft, Leigh Cronian / @cybercentry)
///         This file is the normative surface. Internal realisation (and the documented
///         deviations required to make the spec self-consistent) lives in ERC8196Wallet.sol;
///         see NOTES.md for the gap analysis and recommended spec corrections.
interface IERC8196 {
    /* ------------------------------------------------------------------ */
    /*                               EVENTS                                */
    /* ------------------------------------------------------------------ */

    event PolicyRegistered(
        bytes32 indexed policyHash,
        address indexed owner,
        address indexed agent,
        uint256 validUntil
    );

    event ActionExecuted(
        bytes32 indexed policyHash,
        address indexed agent,
        address target,
        uint256 value,
        bytes32 auditEntryId
    );

    event PolicyRevoked(bytes32 indexed policyHash, string reason);

    event AuditEntryLogged(
        bytes32 indexed entryId,
        uint256 sequence,
        bytes32 sessionId,
        string actionType
    );

    /* ------------------------------------------------------------------ */
    /*                               ERRORS                                */
    /* ------------------------------------------------------------------ */

    error PolicyExpired(bytes32 policyHash, uint256 validUntil);
    error ValueExceedsLimit(uint256 value, uint256 maxValue);
    error InvalidSignature(address recovered, address expected);
    error EntropyVerificationFailed(bytes32 commitment, bytes32 revealed);
    error AgentNotRegistered(address agent);
    error PolicyViolation(bytes32 policyHash, string reason);

    /* ------------------------------------------------------------------ */
    /*                            CORE FUNCTIONS                           */
    /* ------------------------------------------------------------------ */

    /// @notice Owner delegates constrained authority to `agent`.
    /// @return policyHash Canonical identifier / commitment of the policy.
    function registerPolicy(
        address agent,
        string[] calldata allowedActions,
        address[] calldata allowedContracts,
        address[] calldata blockedContracts,
        uint256 maxValuePerTx,
        uint256 maxValuePerDay,
        uint256 validAfter,
        uint256 validUntil,
        uint8 minVerificationScore
    ) external returns (bytes32 policyHash);

    /// @notice Execute an agent action iff signature + policy + verification all pass.
    /// @return success    Whether the external call to `target` succeeded.
    /// @return auditEntryId Hash-chained audit entry id for this action.
    function executeAction(
        bytes32 policyHash,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        bytes32 entropyCommitment,
        bytes calldata signature
    ) external returns (bool success, bytes32 auditEntryId);

    /// @notice Owner terminates a delegation, recording a reason for the audit trail.
    function revokePolicy(bytes32 policyHash, string calldata reason) external;

    /// @notice Read-only summary of a policy.
    function getPolicy(bytes32 policyHash)
        external
        view
        returns (address agent, address owner, uint256 maxValuePerTx, uint256 validUntil, bool isActive);
}
