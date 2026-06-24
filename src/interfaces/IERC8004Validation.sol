// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC8004Validation — ERC-8004 Validation Registry (consumed subset)
/// @notice Signatures reproduced verbatim from ERC-8004 (Trustless Agents).
///         ERC-8196 references this registry for: (a) the verification score that
///         ERC-8126 providers write here, and (b) optional periodic posting of
///         hash-chained audit Merkle roots.
/// @dev    Spec: https://eips.ethereum.org/EIPS/eip-8004
///         POLARITY: ERC-8004 `response` follows "0 = failed, 100 = passed" (high = good).
///         This is the OPPOSITE of the risk polarity ERC-8196 uses for its score gate:
///         the wallet reads ERC-8126's risk score directly via `getLatestRiskScore`
///         (high = bad) and does NOT route scoring through this registry. A bridge that
///         did post 8126 results here would write `response = 100 - riskScore` to match
///         ERC-8004's passed polarity. This registry is used only for audit-root
///         anchoring in the wallet. See NOTES.md.
interface IERC8004Validation {
    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external;

    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external;

    function getValidationStatus(bytes32 requestHash)
        external
        view
        returns (
            address validatorAddress,
            uint256 agentId,
            uint8 response,
            bytes32 responseHash,
            string memory tag,
            uint256 lastUpdate
        );

    function getSummary(uint256 agentId, address[] calldata validatorAddresses, string calldata tag)
        external
        view
        returns (uint64 count, uint8 averageResponse);
}
