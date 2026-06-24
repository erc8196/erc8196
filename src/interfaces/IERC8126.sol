// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC8126 — AI Agent Verification (on-chain query surface)
/// @notice ERC-8196 states: "Implementations MUST perform a verification check using
///         ERC-8126 before executing any agent action. Actions MUST be rejected if the
///         agent's current ERC-8126 score exceeds the policy's `minVerificationScore`."
/// @dev    Spec: https://eips.ethereum.org/EIPS/eip-8126 (Final).
///         ERC-8126 is primarily an OFF-CHAIN specification; its optional on-chain
///         component exposes the latest risk score. This interface mirrors that
///         component verbatim — ERC-8196 depends on nothing more.
///
///         POLARITY (ERC-8126, Final): the score is a RISK score in [0,100] where
///         0 = lowest risk and 100 = highest risk (HIGHER = WORSE). ERC-8196 REJECTS
///         when this score EXCEEDS `minVerificationScore`, so that field is the maximum
///         tolerated risk. There is NO `100 - risk` inversion — the wallet consumes the
///         risk score directly. Per ERC-8126, the returned value MUST be the mean of the
///         agent's applicable verification scores.
interface IERC8126 {
    /// @notice Latest overall risk score for an agent (mean of applicable verifications).
    /// @param agentId   ERC-8004 agent id.
    /// @return riskScore 0-100, higher = MORE risky.
    function getLatestRiskScore(uint256 agentId) external view returns (uint8 riskScore);
}
