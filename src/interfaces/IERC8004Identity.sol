// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC8004Identity — ERC-8004 Identity Registry (consumed subset)
/// @notice ERC-8196 requires agents to be registered in ERC-8004 before a policy
///         may be registered for them. The Identity Registry is ERC-721 based
///         (portable agent NFTs keyed by `agentId`).
/// @dev    Spec: https://eips.ethereum.org/EIPS/eip-8004
///         MINIMAL SURFACE: ERC-8004's canonical Identity Registry resolves agents
///         via tokenURI/ownerOf on `agentId`. ERC-8196 needs an address -> agentId
///         resolution to (a) confirm registration and (b) key the ERC-8126/8004
///         validation lookups. The exact reverse-lookup accessor below should be
///         confirmed against the canonical ERC-8004 interface; see NOTES.md.
interface IERC8004Identity {
    /// @return agentId The ERC-8004 agent id bound to `agent`, or 0 if unregistered.
    function agentIdOf(address agent) external view returns (uint256 agentId);

    /// @return owner The owner of the agent NFT (ERC-721 semantics).
    function ownerOf(uint256 agentId) external view returns (address owner);
}
