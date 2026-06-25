# SCSVS Verification Report — ERC-8196 Reference Implementation

Mapping of the **OWASP Smart Contract Security Verification Standard (SCSVS) 0.0.1**
to this repository's contracts:

- [`src/ERC8196Wallet.sol`](src/ERC8196Wallet.sol) — the policy-enforcing wallet (normative ERC-8196 reference).
- [`src/ERC8126ScoreAnchor.sol`](src/ERC8126ScoreAnchor.sol) — the bridge's on-chain risk-score oracle (non-normative).

**Target assurance level: SCSVS Level 2 (Moderate)** — these contracts hold value and
gate financial actions, but are single-protocol and non-upgradeable. Level 3 items that
assume formal verification, multisig governance, or decentralized multi-oracle consensus
are listed as out-of-scope trade-offs.

Status legend: **PASS** (met) · **FIXED** (gap closed in this pass) · **N/A** (control
doesn't apply) · **OPEN** (accepted trade-off or flagged for a spec/design decision).

---

## S1. Architecture, Design, Threat Modeling

| Ref | Control | Status | Notes |
|---|---|---|---|
| S1.1.A (modularity) | Modular components, clear boundaries | PASS | Interfaces + `PolicyTypes` library; wallet/anchor/registries cleanly separated. |
| S1.1.A5 | **Critical privilege transfers are two-step** | **FIXED** | Anchor `transferAdmin` → `acceptAdmin` (nominee must accept). A typo'd admin can no longer brick the contract. |
| S1.1.B (separation) | Single responsibility per module | PASS | Wallet = enforcement; anchor = score custody; identity/validation = external. |
| S1.2 (proxy patterns) | Upgrade/proxy safety | N/A | No proxies — both contracts are non-upgradeable by design. |
| S1.3 (threat modeling) | Threats documented | PASS | Trust model + gate sequence documented in `NOTES.md` and contract NatSpec. |

## S2. Policies, Procedures, Code Management

| Ref | Control | Status | Notes |
|---|---|---|---|
| S2.2.A | Readability & documentation | PASS | Full NatSpec on every external function and the gate sequence. |
| S2.2.B | Linting / formatting | PASS | `forge fmt` applied; solc build warning-free. Remaining `forge lint` advisories (`block-timestamp`, `unsafe-typecast`) reviewed & accepted: time-windowed policy logic inherently compares `block.timestamp` (sub-second manipulation is irrelevant to 24h TTL / daily buckets / validity windows), and timestamp casts to `uint64` cannot overflow in any realistic horizon. |
| S2.3.A | Unit + integration tests | PASS | 32 tests across 3 suites, incl. wallet⇄anchor integration. |
| S2.3.B | **Security-specific tests** | PASS | Reentrancy, nonce replay, access control, bad/forged signature, fail-closed-on-unverified, pause kill-switch, verifier migration — all have dedicated tests; plus **fuzz** tests over the per-tx limit and the risk ceiling. |

## S3. Business Logic & Economic Security

| Ref | Control | Status | Notes |
|---|---|---|---|
| S3.3.A3 | `nonReentrant` applied before other modifiers | PASS | It is the only/first modifier on `executeAction`. |
| S3.3.A4 | Checks-Effects-Interactions | PASS | Nonce marked used + score read **before** the external `target.call`. |
| S3.3.B1 | Unique-per-params calls not repeatable | PASS | Per-policy nonce replay protection. |
| S3.1/S3.2 | Tokenomics / staking / rebasing | N/A | No native token, staking, or rebase logic. |

## S4. Access Control & Authentication

| Ref | Control | Status | Notes |
|---|---|---|---|
| S4.1.A1 | Appropriate function visibility | PASS | Helpers `internal`; state mappings `private`. |
| S4.1.B2 | `ecrecover` handles null/unexpected addresses | PASS | OZ `ECDSA.tryRecover`; result checked `err == NoError && recovered == agent` (agent ≠ 0). |
| S4.1.C1 / S4.2.A1 | `msg.sender` not `tx.origin` | PASS | All authorization uses `msg.sender`. |
| S4.1.C / least privilege | Minimal privilege per role | PASS | Anchor role split: `admin` (cold, rotate-only) vs `oracle` (hot, write-only). Tested. |
| S4.2.A2 | Access control on state-changing fns | PASS | `onlyAdmin` / `onlyOracle` on anchor writes; wallet `revokePolicy` is owner-only. |

## S5. Secure Interactions (Oracle — most relevant)

| Ref | Control | Status | Notes |
|---|---|---|---|
| S5.1.B | Minimal trusted surface | PASS | Wallet depends on **immutable** registry/verifier addresses set at construction. |
| S5.2.A1 | Tamper-proof feed | PASS | Anchor writes gated by `onlyOracle`; random addresses cannot publish (tested). |
| S5.2.A2 | Validate oracle data | PASS | Anchor caps `risk ≤ 100` on write (`InvalidRisk`). |
| S5.2.A3 | **Fallback on oracle failure** | PASS | If the verifier reverts or returns no attestation, the agent is **blocked** (fail-closed), never allowed. |
| S5.2 (canonical store) | Use canonical infra where available | PASS | Two `IERC8126` verifier implementations: `ERC8126ScoreAnchor` (self-stored, test/standalone) and **`ValidationRegistryAdapter`** (reads scores from the canonical **ERC-8004 Validation Registry** — no duplicate store; the ERC-8126-blessed path). Both inherit fail-closed + TTL. |
| S5.2.A2 (range) | Validate oracle data range | PASS | Adapter rejects 8004 `response > 100` (fail-closed); anchor rejects `risk > 100` on write. |
| S5.2.B | Decentralized / multi-oracle consensus | **OPEN** | Single oracle by design — erc8126scan is the *named verification authority*. Accepted L2 trade-off; mitigated by key rotation + fail-closed. Multi-oracle is a future L3 option. |
| S5.2 (staleness) | Handle data latency/staleness | **FIXED** | Anchor enforces a `maxScoreAge` TTL (admin-settable, default 24h): past it `getLatestRiskScore` returns 100 (fail-closed), trustlessly, behind the bare ERC-8126 surface — no wallet/interface change. |
| S5.3 / S5.4 | Cross-chain / bridges | N/A | "Bridge" here is off-chain→on-chain score relay, not a cross-chain token bridge. |

## S6. Cryptographic Practices

| Ref | Control | Status | Notes |
|---|---|---|---|
| S6.1.A2 | Resistant to malleability & replay (nonces) | PASS | EIP-712 typed data + per-policy nonce; OZ ECDSA rejects high-`s` malleable sigs. |
| S6.2.B1 | `ECDSA.recover/tryRecover` manage sig formats | PASS | OZ `tryRecover` handles 64/65-byte + EIP-2098 and rejects malleable forms. |
| S6.2.B (EIP-712) | Standard-compliant typed data | PASS | OZ `EIP712` domain separator; typehash matches the ERC-8196 spec verbatim. |
| S6.3 (randomness) | Secure RNG | N/A | No on-chain randomness; `entropyCommitment` is only bound into the signed digest/audit. |

## S7. Arithmetic & Logic

| Ref | Control | Status | Notes |
|---|---|---|---|
| S7.1.A | Overflow/underflow safety | PASS | Solidity 0.8 checked math throughout; **no `unchecked` blocks**. |
| S7.1.A1 | Explicit casts don't overflow | **FIXED** | `registerPolicy` now rejects `maxValuePerDay > type(uint192).max` — a one-time guard, so the per-tx `uint192(spent)` cast can never truncate. No recurring gas cost (kept the packed `uint192`). |
| S7.2.A9 | Correct comparison operators | PASS | Gate uses `riskScore > minVerificationScore` (reject-on-exceed), matching ERC-8126 risk polarity. Tested at the boundary. |

## S8. Denial of Service

| Ref | Control | Status | Notes |
|---|---|---|---|
| S8.1.A | Bounded loops / gas | **FIXED** | `registerPolicy` caps each policy list at `MAX_POLICY_ENTRIES` (100), bounding both the registration loops and the execution-time `_authenticate` auth loop. |
| S8.2.A4 | Check external-call return values | PASS | `(success,) = target.call{value}(data)` checked; reverts `"call failed"` on `false`. |

## S9. Data & State Management

| Ref | Control | Status | Notes |
|---|---|---|---|
| S9.1.A1 | **Payable funds withdrawable (no locked ETH)** | **FIXED** | Single-tenant `owner` (deployer) + `withdraw(to, amount)` (`nonReentrant`, owner-only). Funds can't be locked if the agent key is lost. Not a gating bypass — gates constrain the agent, not the owner. |
| S9.3.A | Events for critical changes | PASS | Wallet: `PolicyRegistered/ActionExecuted/PolicyRevoked/AuditEntryLogged`. Anchor: `OracleUpdated/AdminTransferStarted/AdminTransferred/ScoreUpdated/ScoreRevoked`. |
| S9.2 (privacy/ZK) | Confidential data | N/A | No on-chain secrets; all state is intentionally public/auditable. |

## S10 / S11

| Ref | Status | Notes |
|---|---|---|
| S10 (gas) | PASS | `via_ir` + optimizer enabled; O(1) lookups via mappings. |
| S11 (tokens/NFT/vault/AMM/staking/Uniswap hook) | N/A | None of these component types are present. |

---

## Open items (prioritized)

1. **S5.2.B — multi-oracle** (L3; accepted single-authority trade-off). Only adds trust with *independent* providers; with one real ERC-8126 provider (erc8126scan) it would be N self-held keys = no decentralization. Revisit when independent providers exist. Mitigated today by key rotation + fail-closed.

## Fixed in this pass
- **S9.1.A1** single-tenant `owner` + `withdraw` (no locked ETH) (+ tests).
- **S5.2** anchor `maxScoreAge` TTL — stale scores fail-closed (+ tests).
- **S1.1.A5** two-step admin transfer on `ERC8126ScoreAnchor` (+ tests).
- **S8.1.A** `MAX_POLICY_ENTRIES` cap on policy lists (+ test).
- **S7.1.A1** one-time `maxValuePerDay ≤ uint192.max` guard (+ test).
- **S2.2.B** `forge fmt` applied repo-wide.
