# Deployment

Installation, service registration, and upgrade procedures for Merkle.

## 1. Distribution Channels

Merkle is distributed as a single pre-compiled binary. Choose the channel
appropriate for the target OS.

### macOS — Homebrew tap

```sh
brew tap fapp/merkle
brew install merkle
```

The tap formula downloads the signed universal binary, verifies the
SHA-256 digest, and places `merkle` in `$(brew --prefix)/bin/merkle`.

### Windows — Scoop bucket

```powershell
scoop bucket add fapp https://github.com/fapp/scoop-merkle
scoop install merkle
```

The manifest downloads the signed `.exe`, verifies SHA-256, and places
the binary in `%USERPROFILE%\scoop\shims\merkle.exe`.

### Arch Linux — AUR

```sh
yay -S merkle-bin
# or
paru -S merkle-bin
```

`merkle-bin` installs the pre-built ELF binary. A source variant
(`merkle`) compiles from crates.io via `cargo build --release` during
PKGBUILD execution (requires stable Rust toolchain).

### Debian / Ubuntu — .deb package

```sh
curl -fsSL https://pkg.fapp.dev/gpg.key | sudo gpg --dearmor \
    -o /usr/share/keyrings/fapp.gpg
echo "deb [signed-by=/usr/share/keyrings/fapp.gpg] \
    https://pkg.fapp.dev/deb stable main" \
    | sudo tee /etc/apt/sources.list.d/fapp.list
sudo apt update && sudo apt install merkle
```

The `.deb` package places the binary at `/usr/local/bin/merkle` and a
man page at `/usr/share/man/man1/merkle.1.gz`. It does not register a
system-wide service; service registration is always per-user (see
section 4).

### Cargo install fallback

```sh
cargo install merkle --locked
```

Builds and installs from crates.io into `~/.cargo/bin/merkle`. Requires
a Rust stable toolchain (MSRV declared in `Cargo.toml`). Suitable for
CI environments or architectures not covered by pre-built binaries.

---

## 2. Single Binary Layout

All functionality ships in one binary. Subcommands determine the runtime
role:

| Subcommand | Role |
|---|---|
| `merkle init` | Interactive setup wizard; generates keys and configuration |
| `merkle agent` | Start the Vault Agent daemon (foreground or daemonized) |
| `merkle mcp` | Start the MCP Adapter over stdio (spawned by Claude Code) |
| `merkle put` | Store or update a Secret from the CLI |
| `merkle backup` | Trigger an immediate backup to the configured target |
| `merkle restore` | Restore a backup; modes: overwrite, merge, newest-wins |
| `merkle rotate` | Rotate Master Key or Recovery Key |
| `merkle audit` | Query, export, and verify the audit log |
| `merkle doctor` | Run diagnostic checks; auto-fix stale backups |
| `merkle migrate` | Apply pending database migrations (run automatically on upgrade) |

The binary detects whether it is running as a login item, launchd agent,
or systemd unit and adjusts log destination accordingly (stderr when
attached to a TTY; file otherwise).

---

## 3. Initial Setup

Run `merkle init` after installation. The wizard walks through seven
steps:

| Step | Action |
|---|---|
| 1 | Choose database location (default: `~/.local/share/merkle/vault.db`) |
| 2 | Choose configuration location (default: `~/.config/merkle/config.toml`) |
| 3 | Select Security Profile: `relaxed`, `balanced`, or `paranoid` |
| 4 | Generate Master Key and store it in the OS keychain (`dev.fapp.merkle`, account `master-v1`) |
| 5 | Generate Recovery Key (X25519 age identity); display it once; prompt operator to record it offline |
| 6 | Confirm Recovery Key receipt; store Recovery Public Key in `config.toml` |
| 7 | Optionally register the service with the OS service manager (calls the logic in section 4) |

After `merkle init` completes, the agent can be started manually with
`merkle agent` or automatically via the registered service.

For a description of the onboarding flow from a client window perspective,
see `integrations/onboarding.md`.

---

## 4. Service Registration

The service manager integration runs the Vault Agent as the current user
(not root). Each platform uses its standard per-user mechanism.

### macOS — launchd Launch Agent

Place the plist at `~/Library/LaunchAgents/com.fapp.vault-agent.plist`
and load it:

```sh
launchctl load -w ~/Library/LaunchAgents/com.fapp.vault-agent.plist
```

To unload:

```sh
launchctl unload -w ~/Library/LaunchAgents/com.fapp.vault-agent.plist
```

### Linux — systemd user unit

Place the unit file at `~/.config/systemd/user/vault-agent.service` and
enable it:

```sh
systemctl --user daemon-reload
systemctl --user enable --now vault-agent.service
```

To disable:

```sh
systemctl --user disable --now vault-agent.service
```

### Windows — Service Control Manager

Register and manage the service with `sc.exe` as shown in section 5.

---

## 5. Service Templates

### macOS — com.fapp.vault-agent.plist

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fapp.vault-agent</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/merkle</string>
        <string>agent</string>
    </array>

    <!-- Restart on crash. -->
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
    </dict>

    <!-- Write stdout/stderr to the state log. -->
    <key>StandardOutPath</key>
    <string>/Users/USER/.local/state/merkle/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/USER/.local/state/merkle/agent.log</string>

    <!-- Run only when the user is logged in. -->
    <key>SessionCreate</key>
    <true/>

    <key>RunAtLoad</key>
    <true/>

    <!-- Throttle restart after repeated crashes. -->
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
```

Replace `USER` with the actual username, or use
`$HOME` in a shell-expanded copy generated by `merkle init`.

### Linux — vault-agent.service

```ini
[Unit]
Description=Merkle Vault Agent
Documentation=https://github.com/fapp/merkle
After=default.target

[Service]
Type=notify
ExecStart=%h/.cargo/bin/merkle agent
# Adjust ExecStart to the correct binary path if installed via package manager.

Restart=on-failure
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=60

StandardOutput=append:%h/.local/state/merkle/agent.log
StandardError=append:%h/.local/state/merkle/agent.log

# Notify readiness via sd_notify(3) when the Companion Socket is bound.
NotifyAccess=main

[Install]
WantedBy=default.target
```

The `Type=notify` directive requires the agent to call `sd_notify(3)`
with `READY=1` once the Companion Socket is bound and the agent is
accepting connections. The `merkle agent` subcommand handles this
automatically when running under systemd.

### Windows — Service Control Manager

```powershell
# Create the service (run once, elevated PowerShell not required for
# user services in modern Windows; adjust path as needed).
$merkle = "$env:USERPROFILE\.cargo\bin\merkle.exe"

sc.exe create MerkleVaultAgent `
    binPath= "$merkle agent" `
    DisplayName= "Merkle Vault Agent" `
    start= auto `
    obj= "$env:USERDOMAIN\$env:USERNAME"

# Set a description.
sc.exe description MerkleVaultAgent "Local-first secret vault agent for Merkle."

# Configure restart behavior (restart after 5 s, up to 3 times).
sc.exe failure MerkleVaultAgent reset= 60 actions= restart/5000/restart/5000/restart/5000

# Start the service.
sc.exe start MerkleVaultAgent

# Stop the service.
sc.exe stop MerkleVaultAgent

# Remove the service.
sc.exe delete MerkleVaultAgent
```

On Windows, the agent writes logs to
`%LOCALAPPDATA%\merkle\logs\agent.log` when running as a service.

---

## 6. Upgrade Procedure

Follow these steps in order when upgrading to a new version of Merkle.

1. **Pause the agent.** Send SIGTERM on macOS/Linux; on Windows, use
   `sc.exe stop MerkleVaultAgent`. The agent drains in-flight MCP
   requests, flushes the audit log, triggers a backup if pending changes
   exist, and exits zero. Allow up to 30 seconds.

2. **Replace the binary.** Install the new version via the same
   channel used for the original installation (Homebrew, Scoop, apt,
   or `cargo install --locked`). The binary path does not change.

3. **Run migrations.** Execute `merkle migrate` as the vault user
   before restarting the service. The command applies any pending
   schema migrations and is idempotent; it exits zero if no migrations
   are pending.

4. **Restart the service.**

   - macOS: `launchctl kickstart -k gui/$(id -u)/com.fapp.vault-agent`
   - Linux: `systemctl --user restart vault-agent.service`
   - Windows: `sc.exe start MerkleVaultAgent`

5. **Verify.** Run `merkle doctor` to confirm the agent is running, the
   database is accessible, the keychain is reachable, and the audit
   chain is intact.

Rollback: stop the new agent, restore the previous binary, and restart.
Downgrade migrations are not supported; restore from backup if a schema
migration must be reverted.

---

## 7. Uninstall

### Stop the service

```sh
# macOS
launchctl unload -w ~/Library/LaunchAgents/com.fapp.vault-agent.plist
rm ~/Library/LaunchAgents/com.fapp.vault-agent.plist

# Linux
systemctl --user disable --now vault-agent.service
rm ~/.config/systemd/user/vault-agent.service
systemctl --user daemon-reload

# Windows
sc.exe stop MerkleVaultAgent
sc.exe delete MerkleVaultAgent
```

### Remove the binary

```sh
# macOS (Homebrew)
brew uninstall merkle

# Linux (apt)
sudo apt remove merkle

# Cargo
cargo uninstall merkle

# Windows (Scoop)
scoop uninstall merkle
```

### Remove vault data (optional, destructive)

Before removing vault data, create a backup:

```sh
merkle backup --target ~/merkle-final-backup.merkle.age
```

Then remove data directories:

```sh
rm -rf ~/.local/share/merkle      # database
rm -rf ~/.local/state/merkle      # logs
rm -rf ~/.config/merkle           # configuration
```

Remove keychain entries:

```sh
# macOS — using the security CLI
security delete-generic-password -s dev.fapp.merkle

# Linux — using secret-tool
secret-tool clear service dev.fapp.merkle

# Windows — using cmdkey
cmdkey /delete:dev.fapp.merkle
```

Removing keychain entries without a backup makes the vault data
permanently irrecoverable unless the Recovery Key was preserved.

---

## 8. References

- ADR-0002: agent + MCP adapter topology — `adr/0002-adopt-agent-plus-mcp-adapter-topology.md`
- Onboarding flow — `integrations/onboarding.md`
- Backup format — ADR-0006 (`adr/0006-age-encryption-for-backups-and-recovery.md`)
- Keychain adapter — ADR-0015 (when authored)
- Lifecycle states — `operations/lifecycle.md`
