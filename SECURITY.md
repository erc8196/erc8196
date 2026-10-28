# Security Policy

## Status

This repository is a **non-normative reference implementation** of [ERC-8196](https://eips.ethereum.org/EIPS/eip-8196)
(Final). It is **not audited** and is **not intended for production use** as-is. The
citable artifact is the `IERC8196` interface; the wallet and bridge contracts are
non-normative and may change, while the standard itself will not.

A self-assessment against the **OWASP Smart Contract Security Verification Standard
(SCSVS) 0.0.1** is recorded in [`SCSVS-compliance.md`](SCSVS-compliance.md). A
self-assessment is not an audit.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue for
anything exploitable.

- Use **GitHub Security Advisories** (the repository's *Security → Report a vulnerability*
  tab), or
- email the maintainer (see the `author` field in
  [`src/interfaces/IERC8196.sol`](src/interfaces/IERC8196.sol)).

Please include: affected contract/commit, a description, and a proof-of-concept or failing
test if possible. We aim to acknowledge within a few business days.

## Scope

In scope: the Solidity contracts under [`src/`](src/) and the reference relayer under
[`relayer/`](relayer/).

Out of scope: third-party dependencies (OpenZeppelin, forge-std), the external ERC-8004
and ERC-8126 systems, and the off-chain erc8126scan service.
