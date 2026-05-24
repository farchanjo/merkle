# Merkle — Project Instructions

Local-first MCP secret vault. Hexagonal architecture per ADR-0002 + ADR-0024:
Vault Agent daemon hosts the Companion Socket (HTTP/1.1 over Unix domain
socket); the CLI (`merkle`) and MCP Adapter (`merkle-mcp`) are external
clients that consume it.

## Binaries

| Binary | Role |
|---|---|
| `merkle` | Operator CLI — talks to the daemon via Companion Socket. |
| `merkle-agent` | Long-running daemon — hosts SQLite, keystore, audit chain, background workers. |
| `merkle-mcp` | Thin stdio MCP server — one process per Claude Code window; proxies to daemon. |

## Workspace layout

```
bin/           merkle-cli, merkle-agent, merkle-mcp (binary crates)
crates/        merkle-types, merkle-ports, merkle-domain-*, merkle-adapter-*, merkle-application, merkle-companion-client, merkle-adapter-mcp, merkle-bdd, merkle-e2e
docs/arch/     spec source-of-truth (CUE, MADR, Rego, Gherkin, Structurizr, OpenAPI)
```

Edition 2024, MSRV 1.85. Workspace lints `clippy::all=deny + clippy::pedantic=deny` baseline (forbidden to modify per `~/.claude/CLAUDE.md`).

## Build + test

```bash
cargo fmt --all
cargo build --workspace --release
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
spec validate                                   # docs/arch/ source-of-truth lint
```

## Deployment — HARD RULES (NON-NEGOTIABLE)

- Target install location: **`/usr/local/bin`** (system-wide, requires `sudo`).
- **Deploy is ALWAYS release profile** — `cargo build --release`. Never deploy
  `target/debug/` binaries. Every step below operates exclusively on
  `target/release/`.
- **Codesign is mandatory on every deploy** — no unsigned binary ever reaches
  `/usr/local/bin`. macOS Gatekeeper + hardened runtime + Developer ID.

### Canonical deploy sequence

```bash
# 1. Build RELEASE binaries (mandatory — debug profile is NEVER deployed)
cargo build --workspace --release

# 2. CODESIGN DIRECTLY in target/ — NEVER copy to staging dir first
#    Signature MUST live on the exact bytes produced by cargo.
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: <CN>" \
  target/release/merkle \
  target/release/merkle-agent \
  target/release/merkle-mcp

# 3. Verify signatures at target/ BEFORE install
codesign --verify --deep --strict --verbose=2 target/release/merkle
codesign --verify --deep --strict --verbose=2 target/release/merkle-agent
codesign --verify --deep --strict --verbose=2 target/release/merkle-mcp

# 4. Install to /usr/local/bin with sudo — use `install` (NOT `cp`).
#    `install` sets mode + ownership atomically; cp loses xattrs on some
#    filesystems and breaks the signature.
sudo install -m 755 -o root -g wheel target/release/merkle      /usr/local/bin/merkle
sudo install -m 755 -o root -g wheel target/release/merkle-agent /usr/local/bin/merkle-agent
sudo install -m 755 -o root -g wheel target/release/merkle-mcp  /usr/local/bin/merkle-mcp

# 5. Re-codesign at /usr/local/bin (defensive — guarantees signature
#    survived the install regardless of filesystem semantics)
sudo codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: <CN>" \
  /usr/local/bin/merkle \
  /usr/local/bin/merkle-agent \
  /usr/local/bin/merkle-mcp

# 6. Verify final state
codesign --verify --deep --strict --verbose=2 /usr/local/bin/merkle
codesign --verify --deep --strict --verbose=2 /usr/local/bin/merkle-agent
codesign --verify --deep --strict --verbose=2 /usr/local/bin/merkle-mcp
spctl --assess --type execute --verbose /usr/local/bin/merkle
```

### One-shot deploy (recommended)

Set `DEVELOPER_ID` env var once, then run as a single command. Bash exits on
first failure thanks to `set -euo pipefail`, so any signature mismatch or
install error halts the deploy.

```bash
export DEVELOPER_ID="Developer ID Application: <CN>"

set -euo pipefail
cargo build --workspace --release
for bin in merkle merkle-agent merkle-mcp; do
  codesign --force --options runtime --timestamp \
    --sign "$DEVELOPER_ID" "target/release/$bin"
  codesign --verify --deep --strict --verbose=2 "target/release/$bin"
  sudo install -m 755 -o root -g wheel "target/release/$bin" "/usr/local/bin/$bin"
  sudo codesign --force --options runtime --timestamp \
    --sign "$DEVELOPER_ID" "/usr/local/bin/$bin"
  codesign --verify --deep --strict --verbose=2 "/usr/local/bin/$bin"
done
spctl --assess --type execute --verbose /usr/local/bin/merkle-agent
```

Output of `spctl --assess` must end with `accepted` and the source `Developer ID`.
Any other status = block the deploy and investigate.

### Forbidden patterns

- **NEVER** `cp target/release/X /usr/local/bin/X`. `cp` loses extended
  attributes on cross-filesystem moves and can silently corrupt the code
  signature. Always use `install` (or `ditto` on macOS for trees with
  resources).
- **NEVER** stage to an intermediate directory and codesign there.
  Sign on the **exact build artifact in `target/release/`**, then install.
- **NEVER** skip the post-install re-codesign at `/usr/local/bin`. The
  filesystem layer (APFS → APFS, APFS → external) can change attribute
  preservation; the re-sign guarantees the deployed binary is signed by
  the active Developer ID.
- **NEVER** run any of these steps without `sudo` once writing to
  `/usr/local/bin`. The directory is system-owned.

### When to re-deploy

After every `cargo build --release` change to any of the three binaries.
Stop the launchd-managed daemon, redeploy, restart:

```bash
launchctl kickstart -k gui/$UID/dev.fapp.merkle.agent  # respawn after binary swap
# or full cycle:
launchctl bootout gui/$UID/dev.fapp.merkle.agent
# … run deploy sequence above …
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/dev.fapp.merkle.agent.plist
```

## LaunchAgent (macOS) — production runtime

`merkle-agent` runs as a per-user `LaunchAgent` for hands-off
auto-start at login + crash-restart. Assets live in
`deploy/launchd/`:

- `dev.fapp.merkle.agent.plist` — LaunchAgent template (Label
  `dev.fapp.merkle.agent`, KeepAlive on crash, throttle 10 s).
- `merkle-agent-launchd` — wrapper that fetches
  `MERKLE_KEYSTORE_PASSPHRASE` from macOS login Keychain
  (`security find-generic-password -s dev.fapp.merkle.launchd -a passphrase`).
- `README.md` — install + lifecycle commands.

The plist must NEVER carry the passphrase in plain text. The wrapper
+ keychain pattern keeps it inside the user's encrypted login keychain;
launchd inherits a clean env, so the wrapper is required for any
file-keystore deployment.

`gui/$UID` scope (NOT `system`) because vault state lives under
`$HOME/.local/share/merkle/` and OS keychain access is session-bound
(Touch ID).

### Notarization (release builds only)

For published releases, notarize after step 6 using `xcrun notarytool` + staple
with `xcrun stapler`. Track per release; not part of the dev loop.

## Architecture

See `docs/arch/` — source-of-truth. Highlights:

- `docs/arch/adr/` — MADR 4.0 ADRs (25 records). Latest: ADR-0024 (MCP consumes
  Companion Socket Client), ADR-0025 (post-Phase-2 cosmetic cleanup).
- `docs/arch/integrations/openapi/companion-socket.yaml` — 34 endpoints
  (19 original + 15 added per ADR-0024).
- `docs/arch/schemas/` — CUE domain types.
- `docs/arch/policies/` — Conftest/Rego.
- `docs/arch/specs/features/` — Gherkin scenarios.
- `docs/arch/architecture/workspace.dsl` — Structurizr C4.

`spec validate` runs all linters; must stay 9/9 green on every PR.

## Conventions

- Commit format: `<type>(<scope>): <subject>` (Angular). Never commit all files
  at once — split by contextual scope.
- Tests-first per BUG impl-guard tier (write reproducing test, then fix, in
  same edit).
- PMD/Clippy rulesets are LOCKED — fix code to comply, never alter the rule.
- `~/.claude/CLAUDE.md` global rules apply (Rust skill, ssh skill, arithma skill,
  spec-mode workflow, model routing, concurrency guard).

## Quick smoke

```bash
# Live integration test against running daemon
sudo /usr/local/bin/merkle-agent &      # or via launchd plist in prod
/usr/local/bin/merkle unseal
/usr/local/bin/merkle bind <label>
/usr/local/bin/merkle list <label>
```

MCP smoke: configure `~/.claude.json` `mcpServers.merkle.command =
/usr/local/bin/merkle-mcp` and reconnect via `/mcp` in Claude Code.
