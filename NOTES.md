# ERC-8196 Reference Implementation — Build Notes

This implementation is **faithful to the ERC-8196 specification** as published
(https://eips.ethereum.org/EIPS/eip-8196, Draft). The public surface — interface,
events, errors, EIP-712 type hashes — is reproduced verbatim. No features, parameters,
or policy fields have been added beyond the spec.

## Dependencies wired in (all mandated by ERC-8196 itself)

| Dependency | Used for | Where |
|---|---|---|
| **ERC-8004 Identity Registry** (`IERC8004Identity`) | "must verify agents via ERC-8004 before policy registration" | `registerPolicy` |
| **ERC-8126 Verifier** (`IERC8126`) | "MUST perform a verification check using ERC-8126 … `minVerificationScore` MUST be enforced" | `executeAction` |
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

### 3. ERC-8126 check mechanism is undefined on-chain
ERC-8126 is primarily off-chain; the score is read here via an `IERC8126` verifier
(which a deployment MAY back with the ERC-8004 Validation Registry, where 8126
providers write). **Suggested spec fix:** name the on-chain query surface normatively.

### 4. Entropy commit-reveal has no reveal step
`executeAction` takes `entropyCommitment` only; there is no reveal parameter and no
commit function, yet `EntropyVerificationFailed(commitment, revealed)` is defined.
**Resolution:** the commitment is bound into the signed digest and the audit entry;
no reveal is invented. `EntropyVerificationFailed` is therefore currently unreachable.
**Suggested spec fix:** either add a reveal step (new parameter / second call) or
remove the reveal-based error.

## Polarity convention (cross-spec, important)

- ERC-8004 `response`: **0 = failed, 100 = passed** → high = good.
- ERC-8126 raw output is a **risk** score → high = bad.
- ERC-8196 compares `score >= minVerificationScore` → expects high = good.

Therefore an **ERC-8126 provider MUST write `response = 100 − riskScore`** to ERC-8004,
so that the value ERC-8196 reads carries "passed" polarity. If 8126 ever writes raw
risk, this gate silently inverts (a critical-risk agent passes). The fix belongs in
**ERC-8126** (the writer), and/or via a tag convention agreed with the ERC-8004 team.

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
- **`IERC8004Identity.agentIdOf`** is a minimal assumed reverse-lookup; confirm against
  canonical ERC-8004.
- **ERC-4337 module** (optional wrapper) — deferred.
- **Tests** — to be added (`test/`).
