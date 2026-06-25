# ERC-8196 Contracts — AI Agent Authenticated Wallet

Solidity for **[ERC-8196](https://eips.ethereum.org/EIPS/eip-8196)** — the execution
layer of the three-tier agent trust stack (**Register** ERC-8004 → **Verify**
ERC-8126 → **Execute** ERC-8196).

> **Status: Draft, interface-first.** ERC-8196 is an Ethereum proposal currently in
> Draft. The **citable artifact is the `IERC8196` interface** — it carries no
> contested design decisions. The full wallet here is a **non-normative reference
> implementation** and may change as the Draft evolves.
>
> Website: [erc8196.ai](https://erc8196.ai) · Authored by Leigh Cronian (@cybercentry) <leigh.cronian@cybercentry.co.uk>, Chris Johnson <chris@virtuals.io>

## Architecture

```mermaid
sequenceDiagram
    participant Owner
    participant Agent
    participant ID as ERC-8004 Identity
    participant Scan as ERC-8126 scan and relayer
    participant VR as ERC-8004 Validation
    participant Wallet as ERC-8196 Wallet
    participant Target
    Agent->>ID: register, get agentId
    Owner->>Wallet: registerPolicy
    Scan->>VR: publish risk score (unverified is 100)
    Agent->>Wallet: executeAction (signed)
    Wallet->>VR: read latest risk score
    alt risk above ceiling or unverified
        Wallet-->>Agent: revert, blocked
    else risk within ceiling and signature valid
        Wallet->>Target: call with value
        Wallet-->>Agent: success
    end
```

**Register** (ERC-8004 Identity) → **Verify** (ERC-8126: the scan scores the agent and a relayer
publishes it into the **ERC-8004 Validation Registry**, the canonical on-chain store; unverified
or stale ⇒ fail-closed at 100) → **Execute** (the ERC-8196 wallet reads that score — via the
`ValidationRegistryAdapter` — and enforces policy + signature + risk ceiling, then logs a
hash-chained audit entry).

## The interface (stable artifact)

[`src/interfaces/IERC8196.sol`](src/interfaces/IERC8196.sol) — the functions, events,
errors, and EIP-712 type hashes other implementations and integrators (ERC-8004,
ERC-8126, ERC-4337) should align against:

```solidity
function registerPolicy(
    address agent, uint256 agentId, string[] calldata allowedActions,
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
| `src/interfaces/IERC8004Validation.sol` | Consumed subset of the ERC-8004 Validation Registry (optional audit anchoring) |
| `src/interfaces/IERC8126.sol` | On-chain query surface for the ERC-8126 verifier |
| `src/libraries/PolicyTypes.sol` | Policy and daily-spend storage types |
| `src/ERC8126ScoreAnchor.sol` | On-chain risk-score store (the bridge's on-chain half): admin/oracle role split, fail-closed, 24h TTL |
| `src/ValidationRegistryAdapter.sol` | Drop-in verifier that reads scores from the canonical ERC-8004 Validation Registry once it is live (same `IERC8126` surface) |
| `script/Deploy.s.sol` · `script/Demo.s.sol` | Deploy script · runnable end-to-end demo |
| `relayer/relay.sh` | Reference off-chain relayer (publishes scores to the anchor) |
| [`SCSVS-compliance.md`](SCSVS-compliance.md) | OWASP SCSVS 0.0.1 verification report |
| [`KNOWN-LIMITATIONS.md`](KNOWN-LIMITATIONS.md) | Honest, up-front list of trade-offs and spec-feedback items |
| [`NOTES.md`](NOTES.md) | Cross-spec polarity convention + documented resolutions of points the Draft leaves open |

## Build & test

```bash
# dependencies live in lib/ (gitignored) — install via forge:
forge install OpenZeppelin/openzeppelin-contracts@v5.1.0
forge install foundry-rs/forge-std
forge build
forge test            # 52 tests across wallet, anchor, adapter, and end-to-end bridge
```

## Run the reference end-to-end

```bash
forge script script/Demo.s.sol -v
```
Prints the full lifecycle on a simulated chain: agent **blocked while unverified**
(risk 100, fail-closed) → relayer publishes risk 15 → agent **allowed**, value moves.

## Deploy + relay (live network)

The functioning path is self-contained — scores live in `ERC8126ScoreAnchor`, written by
an off-chain relayer. (The `ValidationRegistryAdapter` is a drop-in for when the ERC-8004
Validation Registry goes live — same `IERC8126` surface, wallet unchanged.)

```bash
# 1. deploy (anchor + wallet). The wallet takes no ERC-8004 identity registry — the
#    owner supplies the agentId at registerPolicy; the wallet only reads the verifier.
PRIVATE_KEY=0x… ANCHOR_ORACLE=0x… \
  forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast

# 2. relay a score on-chain (oracle/hot key; production fetches from erc8126scan,
#    treats unverified/NULL as 100, maps scan agent -> ERC-8004 agentId)
RPC_URL=… ANCHOR=0x… ORACLE_KEY=0x… AGENT_ID=1 RISK=15 ./relayer/relay.sh
```

## Live deployment (Ethereum Sepolia)

A reference deployment of the bridge is live and publicly verifiable on **Sepolia**
(chainId `11155111`):

| Contract | Address |
|---|---|
| `ERC8126ScoreAnchor` | [`0x9C27aBF011d5E1D97D5F8d8E58b59C8A182DAab1`](https://sepolia.etherscan.io/address/0x9C27aBF011d5E1D97D5F8d8E58b59C8A182DAab1) |
| `ERC8196Wallet` | [`0x0a510B545A1d43798450FEFd831C83C4a67501bE`](https://sepolia.etherscan.io/address/0x0a510B545A1d43798450FEFd831C83C4a67501bE) |

Verified flow: an unverified agent reads `100` (fail-closed); after a relayer
[`setScore` tx](https://sepolia.etherscan.io/tx/0xbcd316dad6b5307531ad9bca069a83ced628c03bb2f4b29be4e37c7fac43f550)
publishing risk `15`, `getLatestRiskScore(1)` returns `15`. The wallet's `verifier()` points
at the anchor.

**Full gate, live on-chain:** the owner
[`registerPolicy` tx](https://sepolia.etherscan.io/tx/0x673ee8a8d2b7acf5cf131889aa40c505d6ac3c737dd32edd7f76cf63585af3b4)
(agentId 1), then an agent-signed
[`executeAction` tx](https://sepolia.etherscan.io/tx/0x70faa9e5c7e12ad2b020ae92487cf2ef97fda6a37fab61afa915b85d49cd31a4)
that cleared every gate (risk 15 ≤ ceiling 50, valid EIP-712 signature, limits, nonce) and
transferred 0.001 ETH with a hash-chained audit entry.

> Demo only — deployed with a throwaway key; not audited; do not use in production.

See [`NOTES.md`](NOTES.md) for dependency wiring and the **polarity convention**
(ERC-8126 is Final: the wallet reads the risk score directly via `getLatestRiskScore`
and rejects when it **exceeds** `minVerificationScore` — that field is a max-risk ceiling,
no inversion).

## Copyright

Copyright and related rights waived via [CC0](LICENSE).
