// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC8004Validation — ERC-8004 Validation Registry (consumed subset)
/// @notice Signatures reproduced verbatim from ERC-8004 (Trustless Agents).
///         ERC-8196 references this registry for: (a) the verification score that
///         ERC-8126 providers write here, and (b) optional periodic posting of
///         hash-chained audit Merkle roots.
/// @dev    Spec: https://eips.ethereum.org/EIPS/eip-8004
///         POLARITY: ERC-8004 `response` follows "0 = failed, 100 = passed"
///         (high = good). ERC-8126 emits a *risk* score (high = bad), so an
///         ERC-8126 provider MUST write `response = 100 - riskScore` for
///         ERC-8196's `minVerificationScore >=` check to be correct. See NOTES.md.
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
