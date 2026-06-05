// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC8126 — AI Agent Verification (on-chain query surface)
/// @notice ERC-8196 states: "Implementations MUST perform a verification check using
///         ERC-8126 before executing any agent action. The policy's
///         `minVerificationScore` field MUST be enforced."
/// @dev    Spec: https://eips.ethereum.org/EIPS/eip-8126
///         ERC-8126 is primarily an OFF-CHAIN specification; its optional on-chain
///         component records final scores / emits verification events, and providers
///         write scores into the ERC-8004 Validation Registry. This interface is the
///         minimal on-chain query surface ERC-8196 depends on. A conforming verifier
///         MAY simply proxy ERC-8004's Validation Registry (see IERC8004Validation).
///
///         POLARITY: `score` here is the value ERC-8196 compares with
///         `minVerificationScore` using `>=`, i.e. higher = more trustworthy
///         (ERC-8004 "passed" polarity), NOT ERC-8126's raw risk score. The provider
///         is responsible for the `100 - risk` inversion. See NOTES.md.
interface IERC8126 {
    /// @notice Current verification score for an agent.
    /// @param agentId ERC-8004 agent id.
    /// @return score      0-100, higher = more trustworthy (passed polarity).
    /// @return lastUpdate Timestamp of the underlying assessment (for freshness checks).
    function verificationScore(uint256 agentId)
        external
        view
        returns (uint8 score, uint256 lastUpdate);
}
