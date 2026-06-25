# Known Limitations

This is a **non-normative, unaudited reference implementation** of [ERC-8196](https://eips.ethereum.org/EIPS/eip-8196)
(Draft). It is written to be correct and legible, not production-hardened. The limitations
below are deliberate and disclosed up front. Several are really *spec feedback* for
ERC-8196 / ERC-8126 / ERC-8004 rather than implementation bugs.

## Integration & conformance

- **External interfaces are this repo's interpretation, not verified against canonical
  deployments.** `IERC8004Identity` (`agentIdOf`), `IERC8004Validation`, and `IERC8126`
  (`getLatestRiskScore`) are modelled from the specs as understood here. The real ERC-8004
  registries may expose different signatures (e.g. the address→agentId reverse lookup).
  **All tests use in-repo mocks** — there is no test against a live ERC-8004/8126 system.
  Reconcile against the canonical ABIs (and fork-test) before relying on the integration.

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
  to match the published interface; consider renaming in the Draft.

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
