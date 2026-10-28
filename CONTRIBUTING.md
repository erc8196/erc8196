# Contributing

Thanks for your interest in the ERC-8196 reference implementation.

## Ground rules

- The **`IERC8196` interface is the stable, citable artifact.** Changes to it are spec
  decisions — open an issue (and ideally raise it on the
  [Ethereum Magicians ERC-8196 thread](https://ethereum-magicians.org/)) before a PR.
- The wallet and bridge contracts are **non-normative** and may change. The standard is Final and will not.
- Conform to **OWASP SCSVS** where applicable; if a change touches a control listed in
  [`SCSVS-compliance.md`](SCSVS-compliance.md), update that file.

## Dev setup

```bash
# deps live in lib/ (gitignored); install via forge:
forge install OpenZeppelin/openzeppelin-contracts@v5.1.0
forge install foundry-rs/forge-std
forge build
forge test
```

## Before opening a PR

- `forge fmt` (CI runs `forge fmt --check`).
- `forge test` — all tests pass.
- Add tests for new behaviour, including the **revert/negative paths** (every gate in the
  wallet has a dedicated test; match that bar).
- Keep NatSpec on external functions.

## Commit / PR

- Small, focused PRs with a clear description of *what* and *why*.
- Reference the relevant ERC (8196 / 8126 / 8004 / 8183) where applicable.
