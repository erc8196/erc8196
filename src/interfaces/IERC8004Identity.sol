// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC8004Identity — ERC-8004 Identity Registry (consumed subset)
/// @notice ERC-8196 requires agents to be registered in ERC-8004 before a policy may be
///         registered for them. ERC-8004 identifies an agent by `agentId` (a uint256
///         ERC-721 tokenId) and exposes a FORWARD lookup `getAgentWallet(agentId)`.
/// @dev    Spec: https://eips.ethereum.org/EIPS/eip-8004 — function shapes below verified
///         against the canonical interface (2026-06).
///
///         RECONCILIATION / SPEC GAP: canonical ERC-8004 provides NO reverse lookup
///         (`address -> agentId`). Yet ERC-8196 references agents by ADDRESS while ERC-8126
///         keys risk scores by AGENT ID, so an execution layer must bridge the two. Two
///         resolutions, both documented in KNOWN-LIMITATIONS.md:
///           (a) ERC-8196 registers policies by `agentId`, resolving the signing address
///               via the canonical `getAgentWallet` — the clean fix (a Draft change), or
///           (b) back the `agentIdOf` EXTENSION below with an off-chain indexer / wrapper.
///         This reference impl currently consumes `agentIdOf` (option b).
interface IERC8004Identity {
    /// @notice CANONICAL: the agent's operational wallet — the address that signs actions.
    /// @return wallet Signing wallet bound to `agentId`, or address(0) if unset.
    function getAgentWallet(uint256 agentId) external view returns (address wallet);

    /// @notice CANONICAL (ERC-721): owner of the agent NFT.
    function ownerOf(uint256 agentId) external view returns (address owner);

    /// @notice EXTENSION (NOT in canonical ERC-8004): reverse lookup `address -> agentId`.
    ///         Required by ERC-8196's address-keyed model; see the spec-gap note above.
    /// @return agentId ERC-8004 agent id bound to `agent`, or 0 if unregistered.
    function agentIdOf(address agent) external view returns (uint256 agentId);
}
