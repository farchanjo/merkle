# Runbook — Deploy Merkle on macOS (dev machine)

## Purpose

Build, codesign, install, and restart the LaunchAgent so CLI, agent, and MCP
binaries match the workspace release build.

## Trigger or When

* After merging release-ready changes to `main`
* After `cargo build --workspace --release` validation
* When `merkle status` reports a binary/version mismatch with the workspace
* When rotating the LaunchAgent after config or binary upgrades

## Preconditions

* Repo checkout with Rust toolchain from `rust-toolchain.toml`
* Codesigning identity present (dev: Apple Development)
* Launchd wrapper and passphrase keychain entry configured for production-like
  runs
* Recovery recipient available when the wrapper requires it

## Steps

1. Build release binaries: `cargo build --workspace --release` (or `make build-release`).
2. Codesign each of `merkle`, `merkle-agent`, `merkle-mcp` under `target/release/` with the Apple Development identity and verify with `codesign --verify --deep --strict --verbose=2`.
3. Install with `sudo install -m 755` into `/usr/local/bin` (never `cp`).
4. Kickstart the LaunchAgent: `launchctl kickstart -k gui/$UID/dev.fapp.merkle.agent`.
5. Wait ~2s and run `/usr/local/bin/merkle status` (and optionally `merkle doctor`).

Fast path equivalent: `make deploy` then `merkle status`.

## Verification

| Check | Expect |
|---|---|
| `codesign --verify --deep --strict --verbose=2` | exit 0 |
| `spctl --assess` | may print rejected on Apple Development — non-blocking |
| `launchctl print gui/$UID/dev.fapp.merkle.agent` | pid / running |
| `merkle status` | reachable |
| `merkle doctor` | structured checks |

## Rollback

1. Re-install previous release binaries from backup or prior git tag build.
2. `launchctl kickstart -k gui/$UID/dev.fapp.merkle.agent`
3. Do not delete `~/.local/share/merkle/vault.db` unless disaster recovery is
   intentional.

## Forbidden

* `cp` into `/usr/local/bin` — use `install`
* Signing a staged copy instead of `target/release/`
* Passphrase in the LaunchAgent plist
* Running `merkle-agent` directly instead of the launchd wrapper in production

## Related

* `docs/arch/operations/deployment.md`
* `docs/arch/operations/runbook.md`
* `deploy/launchd/`
* Makefile: `deploy`, `sign`, `install`, `kickstart`, `logs`
