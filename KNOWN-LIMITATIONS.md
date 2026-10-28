# Known Limitations

This is a **non-normative, unaudited reference implementation** of [ERC-8196](https://eips.ethereum.org/EIPS/eip-8196)
(Final). It is written to be correct and legible, not production-hardened. The limitations
below are deliberate and disclosed up front. Several are really *spec feedback* for
ERC-8196 / ERC-8126 / ERC-8004 rather than implementation bugs.

## Integration & conformance

- **Interfaces reconciled against the canonical specs (2026-06):**
  - **ERC-8126** `getLatestRiskScore(uint256) → uint8` — **exact match.**
  - **ERC-8004 Validation Registry** — `validationRequest`, `validationResponse`,
    `getValidationStatus`, `getSummary` **match canonical exactly**, so `ValidationRegistryAdapter`
    is built to the real ABI.
  - **ERC-8004 Identity Registry** — **not used.** Canonical ERC-8004 has no `address → agentId`
    reverse lookup, and ERC-8126 keys scores by `agentId`. Rather than invent a non-canonical
    reverse lookup, `registerPolicy` takes the **`agentId` directly** (owner-supplied) and the
    score is keyed by it. So the wallet makes **no identity-registry call at all** — and one
    address backing many agents is handled (each policy names one `agentId`).
- **Still mock-only at runtime.** Signatures now match canonical, but **all tests use in-repo
  mocks** — there is no fork test against a deployed ERC-8004/8126 system yet.

- **The `agentId`↔`agent` binding is owner-trusted.** `registerPolicy` takes both the agent
  address (signs actions) and the `agentId` (scored); the wallet does not verify on-chain that
  they correspond (e.g. via `getAgentWallet`). In the single-tenant model the owner only risks
  their own funds, so a mismatched pair is not an external threat. Implementations MAY add a
  `getAgentWallet(agentId) == agent` check if they want the binding enforced on-chain.

- **Signatures are not portable across ERC-8196 implementations.** The `AgentAction`
  EIP-712 type includes `action`, but `executeAction` omits it; this wallet recovers it by
  trying each `allowedActions` entry. That is non-normative — another conforming wallet
  won't reproduce it, so an agent signature only validates against *this* wallet. The fix
  belongs in ERC-8196 (add `action` as a parameter, or specify recovery normatively).

## Trust model

- **A single verification provider is the core trust assumption.** The wallet acts on
  whatever risk score the configured verifier returns. A compromised relayer/oracle key can
  mark a malicious agent low-risk and let it spend (within policy limits) to allow-listed
  targets. Mitigated by: fail-closed defaults, a staleness TTL on the anchor/adapter, hot-key
  rotation, and `setVerifier` migration — but it is **not trustless**. Multi-oracle/quorum is
  out of scope until independent ERC-8126 providers exist.

- **The owner is fully trusted.** `withdraw` lets the owner reclaim all native funds at any
  time, and `setVerifier` / `setPaused` are owner powers. This is a **single-tenant** wallet:
  the owner already owns the funds, so these add no trust beyond ownership. Do not fund one
  wallet from multiple parties.

## Mechanism gaps (spec-level)

- **`entropyCommitment` provides no security property as implemented.** It is bound into the
  signed digest and the audit entry but never revealed/verified, so `EntropyVerificationFailed`
  is unreachable. ERC-8196 defines no reveal step. Either add a real reveal/verification, or
  remove the field from the spec.

- **`minVerificationScore` is misnamed.** Per ERC-8126's risk polarity it functions as a
  *maximum tolerated risk* ceiling (reject if risk exceeds it), not a minimum. Kept verbatim
  to match the published interface. The standard is Final, so a rename would
  need an erratum rather than a Draft edit.

## Implementation choices

- **Daily-cap windowing is UTC calendar-day bucketing**, which is gameable across the
  midnight boundary (spend the cap at 23:59 and again at 00:01). A rolling 24h window is the
  stricter alternative. See `PolicyTypes` / `NOTES.md`.

- **Verifier migration requires owner trust at the moment of `setVerifier`.** Updating the
  verifier is how a deployment moves from the self-stored `ScoreAnchor` to the ERC-8004
  `ValidationRegistryAdapter`; there is no timelock on it.

- **No policy enumeration / cleanup.** Re-registration creates new policies; old ones remain
  active until individually revoked (or the wallet is paused).

## Assurance

- **Not audited.** The [`SCSVS-compliance.md`](SCSVS-compliance.md) report is a *self-assessment*
  against OWASP SCSVS 0.0.1, not an independent audit. Tests are example-based plus light fuzz;
  there is no formal verification.
