# ERC-8196 Reference Implementation — Build Notes

This implementation is **faithful to the ERC-8196 specification** as published
(https://eips.ethereum.org/EIPS/eip-8196, Draft). The public surface — interface,
events, errors, EIP-712 type hashes — is reproduced verbatim. No features, parameters,
or policy fields have been added beyond the spec.

## Dependencies wired in (all mandated by ERC-8196 itself)

| Dependency | Used for | Where |
|---|---|---|
| **ERC-8126 Verifier** (`IERC8126`) | "MUST perform a verification check using ERC-8126 … `minVerificationScore` MUST be enforced". Keyed by the `agentId` the owner supplies at `registerPolicy` — the wallet makes **no ERC-8004 identity call**. | `executeAction` |
| **ERC-8004 Validation Registry** (`IERC8004Validation`) | audit-root anchoring ("periodic on-chain Merkle roots posted to ERC-8004's Validation Registry"); also where ERC-8126 providers write scores | held as immutable; see Open Items |
| **EIP-712** | typed-data agent signatures | OZ `EIP712` base |
| **ERC-4337** | "Compatible with ERC-4337 wallets" — `executeAction` is signature-authorized and caller-agnostic, so a bundler/relayer or a 4337 account can drive it. No native `validateUserOp` is added (would diverge). | n/a |

## Spec silences resolved using ONLY spec-defined data

ERC-8196 contains **no Reference Implementation** and is silent on three mechanisms
that `executeAction` requires. Each is resolved below without adding parameters,
fields, or features — but each is also a **candidate spec correction** you may prefer
to make explicit.

### 1. `action` is in the typehash but not an `executeAction` parameter
`AGENT_ACTION_TYPEHASH` includes `string action`, yet `executeAction` has no `action`
argument, so the digest cannot be rebuilt directly. **Resolution:** recover `action`
by trying each entry of the policy's `allowedActions` and checking which one makes the
agent's signature verify. This uses only existing spec data and *simultaneously*
enforces `action ∈ allowedActions`. Cost is O(allowedActions) ECDSA recoveries
(lists are small). **Suggested spec fix:** either add `string action` as an
`executeAction` parameter, or state this recovery rule normatively.

### 2. `validUntil` is in the typehash but not an `executeAction` parameter
**Resolution:** sourced from `policy.validUntil`. **Suggested spec fix:** state this
explicitly (or add the parameter).

### 3. ERC-8126 check mechanism is read on-chain via the Final interface
ERC-8126 is primarily off-chain but its **Final** spec defines an optional on-chain
component: `getLatestRiskScore(uint256 agentId) returns (uint8)`. The wallet calls that
verbatim through `IERC8126`. The value is a **risk** score (higher = worse) and ERC-8196
rejects when it **exceeds** `minVerificationScore` — no inversion (see Polarity below).

### 4. Entropy commit-reveal has no reveal step
`executeAction` takes `entropyCommitment` only; there is no reveal parameter and no
commit function, yet `EntropyVerificationFailed(commitment, revealed)` is defined.
**Resolution:** the commitment is bound into the signed digest and the audit entry;
no reveal is invented. `EntropyVerificationFailed` is therefore currently unreachable.
**Suggested spec fix:** either add a reveal step (new parameter / second call) or
remove the reveal-based error.

## Polarity convention (cross-spec, important)

ERC-8126 is **Final**, so the implementation conforms to it rather than the reverse:

- ERC-8126 score is a **risk** score, `0` = lowest risk .. `100` = highest risk → **high = bad**.
- Per ERC-8126 it MUST be the **mean** of the agent's applicable verification scores.
- ERC-8196 rejects when the score **exceeds** `minVerificationScore`, so that field is a
  **maximum tolerated risk ceiling**. The wallet consumes the risk score **directly**
  via `getLatestRiskScore` — there is **no `100 − risk` inversion**.

Naming caveat (ERC-8196 — still adjustable): the field is called `minVerificationScore`
but functions as a *max risk*. A value of `20` admits only `risk ≤ 20` (Low Risk) agents.
Consider renaming to `maxRiskScore` in ERC-8196 to remove the min/max ambiguity.

> NB — the ERC-8126 reference scanner (`erc-xxxx-scan`, `lib/risk.ts`) currently
> aggregates with `Math.max`, not the spec-mandated **mean**. That is a scanner bug to
> fix against Final ERC-8126; it does not affect this wallet, which reads whatever single
> risk value the on-chain verifier returns.

## Other documented implementation choices (spec-permitted latitude)

- **Daily cap windowing:** UTC calendar-day buckets (`timestamp / 1 days`). Cheap;
  resets at the UTC boundary (gameable across the boundary). Alternative: rolling 24h.
- **`maxValuePerDay == 0`** ⇒ unset/unlimited (it is the one optional Policy field).
- **Whitelist semantics:** deny-by-default — empty `allowedContracts` allows nothing.
- **`policyHash`:** commitment over all policy params + owner + a per-owner salt, so
  identical re-registrations hash distinctly.
- **`sessionId`** for the audit chain = `policyHash`.
- **agentId** is cached at registration because ERC-8126/8004 lookups key by `agentId`,
  not address (ERC-8196's Policy struct stores only the address).

## Open items / not yet built

- **Audit-root anchoring** to the Validation Registry is referenced but not auto-called
  (spec says MAY / periodic). The on-chain `previousHash` chain satisfies the MUST.
- **`DELEGATION_TYPEHASH`** is declared (verbatim) but no delegation flow is specified
  by ERC-8196 beyond it; left unused pending spec detail.
- **agentId resolution**: the owner supplies the `agentId` at `registerPolicy` (the score
  is keyed by it). The wallet makes **no ERC-8004 identity-registry call** — this avoids the
  non-existent canonical `address -> agentId` reverse lookup, and handles one address backing
  many agents (each policy names one `agentId`).
- **ERC-4337 module** (optional wrapper) — deferred.
