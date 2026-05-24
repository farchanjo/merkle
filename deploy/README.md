# Merkle Agent — Deployment Guide

This directory contains OS-specific service descriptors for running
`merkle-agent` as a supervised background service.

```
deploy/
  systemd/
    merkle-agent.service       Linux systemd unit (Type=notify, hardened)
  launchd/
    dev.fapp.merkle.plist      macOS launchd agent plist
  windows/
    merkle-agent-service.xml   WinSW service wrapper configuration
  etc/merkle/
    config.toml.example        Sample configuration with annotated defaults
  README.md                    This file
```

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Rust toolchain | 1.95 | `rustup show` to verify |
| `merkle-agent` binary | any | `cargo build --release -p merkle-agent` |
| SQLite | 3.35+ | Required for WAL mode |
| OpenSSH client | 7.6+ | Required for port-forward (`ssh -L`) |
| systemd (Linux) | 240+ | For `Type=notify` and `RuntimeDirectory` |
| macOS | 12 Monterey+ | For launchd plist |
| Windows | 10 / Server 2016+ | For WinSW service wrapper |

---

## Linux (systemd)

### 1. Build and install the binary

```bash
cargo build --release --package merkle-agent
sudo install -m 0755 target/release/merkle-agent /usr/local/bin/merkle-agent
```

### 2. Create the service user and directories

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin merkle
sudo mkdir -p /var/lib/merkle /run/merkle /etc/merkle
sudo chown -R merkle:merkle /var/lib/merkle /run/merkle
sudo chmod 0750 /var/lib/merkle /run/merkle
```

### 3. Install the configuration

```bash
sudo cp deploy/etc/merkle/config.toml.example /etc/merkle/config.toml
sudo chown root:merkle /etc/merkle/config.toml
sudo chmod 0640 /etc/merkle/config.toml
# Edit the file and adjust paths, security profile, and log settings.
sudo nano /etc/merkle/config.toml
```

### 4. Install and start the service unit

```bash
sudo cp deploy/systemd/merkle-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now merkle-agent
sudo systemctl status merkle-agent
```

### 5. Verify

```bash
# Service health
sudo systemctl status merkle-agent

# Structured logs
sudo journalctl -u merkle-agent -f

# Agent socket (companion socket for Claude Code)
ls -la /run/merkle/companion.sock
```

### Troubleshooting — Linux

| Symptom | Likely cause | Fix |
|---|---|---|
| `active: failed (code=exited)` | Binary not found or wrong path | Check `ExecStart=` in the unit |
| `Failed to open database` | `/var/lib/merkle` not writable by `merkle` | `chown merkle:merkle /var/lib/merkle` |
| `VaultSealed` on every request | Agent started but vault not unsealed | Run `merkle-cli unseal` or configure auto-unseal |
| Port-forward fails (ssh not found) | `ssh` not on PATH for the `merkle` user | Set `ssh.ssh_binary` in `config.toml` |

---

## macOS (launchd)

### 1. Build and install the binary

```bash
cargo build --release --package merkle-agent
sudo install -m 0755 target/release/merkle-agent /usr/local/bin/merkle-agent
```

### 2. Create log and data directories

```bash
mkdir -p /usr/local/var/merkle /usr/local/var/log/merkle /usr/local/etc/merkle
```

### 3. Install the configuration

```bash
cp deploy/etc/merkle/config.toml.example /usr/local/etc/merkle/config.toml
# Edit paths — change /var/lib/merkle to /usr/local/var/merkle throughout.
nano /usr/local/etc/merkle/config.toml
```

### 4. Install and load the plist

User-level agent (runs in your login session — recommended for development):

```bash
cp deploy/launchd/dev.fapp.merkle.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/dev.fapp.merkle.plist
launchctl start dev.fapp.merkle
```

System-level daemon (runs at boot, all users — recommended for servers):

```bash
sudo cp deploy/launchd/dev.fapp.merkle.plist /Library/LaunchDaemons/
# Add <key>UserName</key><string>merkle</string> to the plist for isolation.
sudo launchctl load -w /Library/LaunchDaemons/dev.fapp.merkle.plist
```

### 5. Verify

```bash
launchctl list | grep merkle
tail -f /usr/local/var/log/merkle/agent.stderr.log
```

### Troubleshooting — macOS

| Symptom | Likely cause | Fix |
|---|---|---|
| `Load failed: 5` | Plist has a syntax error | `plutil -lint deploy/launchd/dev.fapp.merkle.plist` |
| Agent exits immediately | Binary panics on startup | Check `agent.stderr.log` for `RUST_BACKTRACE=1` output |
| Keychain access denied | Sandbox or TCC restriction | Grant Full Disk Access in System Settings if needed |
| Port-forward subprocess killed | macOS App Sandbox blocks child processes | Not applicable for non-sandboxed installs |

---

## Windows (WinSW)

### 1. Build the binary

```powershell
cargo build --release --package merkle-agent
```

### 2. Install WinSW

Download the latest `WinSW-x64.exe` from
https://github.com/winsw/winsw/releases and rename it to
`merkle-agent-service.exe`. Place it in the same directory as
`merkle-agent.exe`.

### 3. Create the installation directory

```powershell
New-Item -ItemType Directory -Path "C:\Program Files\merkle"
Copy-Item target\release\merkle-agent.exe "C:\Program Files\merkle\"
Copy-Item deploy\windows\merkle-agent-service.xml "C:\Program Files\merkle\"
Copy-Item deploy\windows\merkle-agent-service.exe "C:\Program Files\merkle\"
```

### 4. Install the configuration

```powershell
New-Item -ItemType Directory -Path "C:\ProgramData\merkle"
Copy-Item deploy\etc\merkle\config.toml.example "C:\Program Files\merkle\config.toml"
# Edit paths in config.toml to use Windows paths.
notepad "C:\Program Files\merkle\config.toml"
```

### 5. Register and start the service

Run PowerShell as Administrator:

```powershell
Set-Location "C:\Program Files\merkle"
.\merkle-agent-service.exe install
.\merkle-agent-service.exe start
.\merkle-agent-service.exe status
```

### 6. Verify

```powershell
Get-Service MerkleAgent
Get-Content "C:\Program Files\merkle\logs\merkle-agent.out.log" -Tail 20
```

### Troubleshooting — Windows

| Symptom | Likely cause | Fix |
|---|---|---|
| Service fails to start (error 1053) | Binary path wrong in XML | Check `<executable>` in the XML |
| Access denied on database file | Service account lacks write access | Grant write access to `C:\ProgramData\merkle` |
| SSH bridge not working | `ssh.exe` not on PATH | Install OpenSSH via Windows Optional Features |
| WinSW install error | Not running as Administrator | Restart PowerShell as Administrator |

---

## Configuration reference

See `deploy/etc/merkle/config.toml.example` for the full annotated reference.

Key sections:

| Section | Purpose |
|---|---|
| `[database]` | SQLite path and WAL settings |
| `[agent]` | Companion Socket path, HTTP debug bind |
| `[security]` | Security profile, session token TTL |
| `[ssh]` | SSH binary path, known-hosts policy |
| `[log]` | Log level and format (pretty or JSON) |
| `[backup]` | Backup interval, retain count, destination |

---

## Note on spec validation

The `deploy/` directory is **not** under `docs/arch/` and is **not** validated
by `spec validate --lane full`. It is a release artifact, not an architectural
specification. See ADR-0018 Amendment (2026-05-23) for the rationale.
