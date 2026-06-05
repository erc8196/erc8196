// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title PolicyTypes — storage types for the ERC-8196 policy structure.
/// @notice Fields mirror the Policy table in the ERC-8196 specification exactly.
///         Set-membership (allowedActions / allowedContracts / blockedContracts) is
///         kept in mappings alongside this struct for O(1) lookup; see ERC8196Wallet.
library PolicyTypes {
    struct Policy {
        // --- spec fields ---
        address agentAddress;        // authorized agent
        address ownerAddress;        // asset owner
        uint256 maxValuePerTx;       // per-transaction limit (required)
        uint256 maxValuePerDay;      // daily spending cap (optional; 0 == unset/unlimited)
        uint256 validAfter;          // activation timestamp (required)
        uint256 validUntil;          // expiration timestamp (required)
        uint8 minVerificationScore;  // ERC-8126 threshold (required)
        bool isActive;               // false once revoked or never registered
    }

    /// @dev Per-policy daily spend accounting. `day` is a UTC calendar-day bucket
    ///      (block.timestamp / 1 days). NOTE: the spec mandates `maxValuePerDay` but
    ///      does not define the windowing method; calendar-day bucketing is the
    ///      implementation choice here (cheap; resets at the UTC boundary). A rolling
    ///      24h window is the alternative — flagged in NOTES.md.
    struct DailySpend {
        uint64 day;
        uint192 spent;
    }
}
