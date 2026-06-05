# ERC-8196 Contracts — AI Agent Authenticated Wallet

Solidity for **[ERC-8196](https://eips.ethereum.org/EIPS/eip-8196)** — the execution
layer of the three-tier agent trust stack (**Register** ERC-8004 → **Verify**
ERC-8126 → **Execute** ERC-8196).

> **Status: Draft, interface-first.** ERC-8196 is an Ethereum proposal currently in
> Draft. The **citable artifact is the `IERC8196` interface** — it carries no
> contested design decisions. The full wallet here is a **non-normative reference
> implementation** and may change as the Draft evolves.
>
> Website: [erc8196.ai](https://erc8196.ai) · Authored by Leigh Cronian (@cybercentry)

## The interface (stable artifact)

[`src/interfaces/IERC8196.sol`](src/interfaces/IERC8196.sol) — the functions, events,
errors, and EIP-712 type hashes other implementations and integrators (ERC-8004,
ERC-8126, ERC-4337) should align against:

```solidity
function registerPolicy(
    address agent, string[] calldata allowedActions,
    address[] calldata allowedContracts, address[] calldata blockedContracts,
    uint256 maxValuePerTx, uint256 maxValuePerDay,
    uint256 validAfter, uint256 validUntil, uint8 minVerificationScore
) external returns (bytes32 policyHash);

function executeAction(
    bytes32 policyHash, address target, uint256 value, bytes calldata data,
    uint256 nonce, bytes32 entropyCommitment, bytes calldata signature
) external returns (bool success, bytes32 auditEntryId);

function revokePolicy(bytes32 policyHash, string calldata reason) external;
function getPolicy(bytes32 policyHash) external view returns (
    address agent, address owner, uint256 maxValuePerTx, uint256 validUntil, bool isActive
);
```

## Reference implementation (non-normative)

| Path | Purpose |
|---|---|
| `src/interfaces/IERC8196.sol` | **The interface** — stable, citable |
| `src/ERC8196Wallet.sol` | Reference wallet: policy enforcement, EIP-712 auth, value/temporal/allowlist checks, nonce replay protection, ERC-8126 score gating, hash-chained audit |
| `src/interfaces/IERC8004Identity.sol` | Consumed subset of the ERC-8004 Identity Registry |
| `src/interfaces/IERC8004Validation.sol` | Consumed subset of the ERC-8004 Validation Registry |
| `src/interfaces/IERC8126.sol` | On-chain query surface for the ERC-8126 verifier |
| `src/libraries/PolicyTypes.sol` | Policy and daily-spend storage types |
| [`NOTES.md`](NOTES.md) | Cross-spec polarity convention + documented resolutions of points the Draft leaves open |

## Build

```bash
forge install OpenZeppelin/openzeppelin-contracts
forge build
forge test
```

See [`NOTES.md`](NOTES.md) for dependency wiring and the **polarity convention**
(ERC-8126 providers MUST write `100 − riskScore` so the score gate is not inverted).
