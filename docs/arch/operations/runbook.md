# Runbook

Operational runbook for Merkle. Each scenario follows the structure:
Symptom / Diagnostic / Root Cause / Remediation / Prevention.

---

## 1. Agent Won't Start — Invalid Configuration

**Symptom.** `merkle agent` exits immediately with a non-zero code.
The service manager marks the unit as failed. The Companion Socket is
absent (`~/.local/run/merkle/agent.sock` does not exist). The log
contains a line such as `ERROR failed to load config: ...`.

**Diagnostic.**

```sh
# Run in foreground to see the error directly
merkle agent 2>&1 | head -20

# Check the log if the service started briefly
tail -50 ~/.local/state/merkle/agent.log

# Validate the config file syntax
merkle doctor --config-only
```

**Root Cause.** `config.toml` has a parse error, a missing required
field, or references a database path the agent cannot create (permission
denied, parent directory absent).

**Remediation.**

1. Open `~/.config/merkle/config.toml` and correct the reported field.
2. Ensure the database directory exists and is writable:
   `mkdir -p ~/.local/share/merkle && chmod 700 ~/.local/share/merkle`.
3. Restart the service: `systemctl --user restart vault-agent` (Linux)
   or `launchctl kickstart -k gui/$(id -u)/com.fapp.vault-agent` (macOS).

**Prevention.** Use `merkle init` to generate the initial configuration.
Validate configuration changes with `merkle doctor --config-only` before
applying them to a running system.

---

## 2. Unseal Fails — Keychain Access Denied

**Symptom.** The agent starts and enters `sealed` state. When an MCP
tool call is received, the agent attempts to unseal but fails. MCP
callers receive `ErrUnsealFailed`. The log shows
`ERROR keychain access denied: service=dev.fapp.merkle account=master-v1`.

**Diagnostic.**

```sh
# Probe keychain directly (macOS)
security find-generic-password -s dev.fapp.merkle -a master-v1 -w

# Probe secret-tool (Linux)
secret-tool lookup service dev.fapp.merkle account master-v1

# Check the agent log for the exact keychain error code
grep -i keychain ~/.local/state/merkle/agent.log | tail -20
```

**Root Cause.** The OS keychain has revoked access to the Merkle item.
Common causes on macOS: the binary path changed after an upgrade
(Keychain Access control list is path-bound); the entry was deleted by
another tool; the user's login keychain is locked. On Linux: Secret
Service daemon (gnome-keyring, KWallet) is not running in the user
session.

**Remediation.**

macOS:
1. Open Keychain Access; locate the `dev.fapp.merkle` item.
2. In the Access Control tab, add the new `merkle` binary path.
3. Alternatively, delete the item and run `merkle rotate --master-key`
   to generate a new Master Key (this re-seals existing data under the
   new key; ensure a backup exists first).

Linux:
1. Ensure the Secret Service daemon is running: `systemctl --user status gnome-keyring`.
2. If absent, install `gnome-keyring` or configure the passphrase
   fallback: set `keychain_backend = "passphrase"` in `config.toml`
   and run `merkle unseal --passphrase` to migrate.

**Prevention.** After upgrades, run `merkle doctor` to confirm keychain
access before relying on auto-unseal.

---

## 3. Companion Socket Connection Refused — Agent Down

**Symptom.** `merkle mcp` (or Claude Code) attempts to connect to the
Companion Socket and receives a connection error. All MCP tools fail
immediately with `ErrAgentUnreachable`. The socket file is absent or
stale.

**Diagnostic.**

```sh
# Check socket existence
ls -la ~/.local/run/merkle/agent.sock

# Check if the agent process is running
pgrep -a merkle

# Check service status
systemctl --user status vault-agent    # Linux
launchctl print gui/$(id -u)/com.fapp.vault-agent  # macOS
```

**Root Cause.** The Vault Agent process is not running. The socket file
may be present but stale (agent crashed without cleaning it up).

**Remediation.**

1. Remove a stale socket if present:
   `rm -f ~/.local/run/merkle/agent.sock`.
2. Start or restart the service:
   `systemctl --user restart vault-agent` (Linux) or
   `launchctl kickstart -k gui/$(id -u)/com.fapp.vault-agent` (macOS).
3. Verify: `merkle doctor`.

**Prevention.** Enable service supervision (section 9 of
`lifecycle.md`). The `KeepAlive` / `Restart=on-failure` directives
ensure the agent is restarted after a crash.

---

## 4. MCP Tool Returns "namespace not bound"

**Symptom.** A vault MCP tool (e.g., `vault.list`, `vault.put`) returns
an error indicating that no Namespace is bound to the current session.
The tool call completes but with an error payload.

**Diagnostic.**

```sh
# From the Claude Code session, call the binding tool
# vault.bind(label="my-project")

# Check the session's current binding via
# vault.describe() — should return the bound Namespace metadata
```

**Root Cause.** The MCP session started without a Namespace binding in
effect. Merkle binds a Namespace automatically based on the current
working directory hash only if `auto_bind = true` in `config.toml` and
a Namespace has been initialized for that directory. If auto-bind is
disabled, or the working directory has no associated Namespace, the
session is unbound.

**Remediation.**

1. Call `vault.bind(label="<namespace-label>")` from within the Claude
   Code session to explicitly bind.
2. Alternatively, place a `.merklerc` file in the project root declaring
   `namespace = "<label>"` — the agent auto-reads it when the MCP
   session starts with that directory as its root.
3. If the Namespace does not exist, create it:
   `merkle init --namespace <label> --path /path/to/project`.

**Prevention.** Add `.merklerc` to project roots as part of the project
initialization checklist.

---

## 5. Reveal Denied — No Slash Flag

**Symptom.** A `vault.reveal` call from the LLM returns `ErrDenied` with
the message `reveal requires operator confirmation via slash command`.
No plaintext is returned.

**Diagnostic.** The agent log shows
`WARN reveal denied: handle=vault://...; reason=no_slash_flag`.
The Namespace Policy requires `confirmation_via_slash = true`.

**Root Cause.** The `vault.reveal` tool was called without the operator
issuing `/merkle-reveal` in the Claude Code UI first. This is the
expected security behavior: reveals of high-sensitivity Secrets require
a verifiable human confirmation signal.

**Remediation.**

1. In the Claude Code window, type the slash command `/merkle-reveal`
   before repeating the reveal request.
2. If the Secret's sensitivity is `low` and a slash command should not
   be required, review the Namespace Policy:
   `merkle namespace policy edit <label>` and adjust
   `reveal_requires_slash = false` for that Namespace.

**Prevention.** This is a security control, not a bug. Operator
training: always issue `/merkle-reveal` when asking the LLM to reveal
a Secret. Do not attempt to work around it programmatically.

---

## 6. Backup Target Unreachable — Drive Offline

**Symptom.** `merkle backup` fails with an error such as
`ERROR backup target unreachable: path=/Volumes/BackupDrive/merkle`.
The `merkle_backup_age_seconds` metric climbs above the `max_interval`.

**Diagnostic.**

```sh
# Check whether the target path is mounted / accessible
ls -la /path/to/backup/target

# Check the agent log for backup attempt history
grep backup ~/.local/state/merkle/agent.log | tail -30

# Run doctor to see backup age
merkle doctor
```

**Root Cause.** The configured backup target (external drive, network
share, cloud-mounted path) is not accessible. The drive may be offline,
the mount may have dropped, or permissions may have changed.

**Remediation.**

1. Reconnect or mount the backup target.
2. Trigger an immediate backup: `merkle backup`.
3. If the primary target is permanently unavailable, update the target:
   `merkle config set backup.target /new/path` and run `merkle backup`.
4. For redundancy, configure a secondary backup target in `config.toml`:
   ```toml
   [[backup.targets]]
   path = "~/BackupDrive/merkle"
   [[backup.targets]]
   path = "~/iCloud Drive/merkle-backups"
   ```

**Prevention.** Configure at least two backup targets on different
storage media. Set a `backup_age` alert (see `observability.md`,
section 5) to catch stale backups before they become a recovery risk.

---

## 7. Audit Chain Verification Fails — Tampering or Disk Corruption

**Symptom.** `merkle doctor` or `merkle audit query --verify-chain`
reports `chain_broken` at a specific entry ID. The
`merkle_chain_verifications_total{outcome="broken"}` metric is non-zero.

**Diagnostic.**

```sh
# Identify the first broken entry
merkle audit query --verify-chain --format json 2>&1 | \
    grep -A5 chain_broken

# Inspect entries around the break
merkle audit query --since 2026-05-01T00:00:00Z --format json | \
    grep -B2 -A2 '"entry_id":"<broken_id>"'

# Check database file integrity
sqlite3 ~/.local/share/merkle/vault.db "PRAGMA integrity_check;"
```

**Root Cause.** Two possible causes: (a) disk corruption in the SQLite
database, possibly due to an unclean shutdown or storage hardware fault;
(b) deliberate tampering with the audit log. The Hash Chain design makes
it impossible to modify or remove an entry without breaking all
subsequent hashes.

**Remediation.**

1. Do not modify the database to "fix" the chain; this destroys forensic
   evidence.
2. If disk corruption is suspected: run filesystem checks (`fsck`,
   `diskutil verifyVolume`). Restore the database from the most recent
   backup: `merkle restore --backup <path.merkle.age>`.
3. If tampering is suspected: preserve the corrupted database file as
   evidence (copy it to a safe location). Report the incident per your
   security incident response policy. Restore from backup.
4. After restore, re-run `merkle audit query --verify-chain` to confirm
   the chain is intact in the restored database.

**Prevention.** Store backups on media physically separate from the
vault database. Enable filesystem checksumming (ZFS, APFS) where
available. Run `merkle doctor` on a daily schedule.

---

## 8. Disk Full

**Symptom.** Agent operations begin failing with `IOError: No space left
on device`. Backup fails. New Audit Entries cannot be written. The
`merkle doctor` disk space check reports `ERROR: < 10 MB free`.

**Diagnostic.**

```sh
# Check free space on vault filesystem
df -h ~/.local/share/merkle

# Find large files in the vault directory
du -sh ~/.local/share/merkle/*
du -sh ~/.local/state/merkle/*

# Check rotated log files
ls -lh ~/.local/state/merkle/*.log*
```

**Root Cause.** Most common causes: log files consuming excessive space
(log rotation not functioning); database grown large due to retained
Secret Versions; backup file accumulation in the same filesystem as the
vault.

**Remediation.**

1. Immediately free space: remove old log rotations
   (`rm ~/.local/state/merkle/agent.log.{2,3,4,5}`) or reduce Secret
   Version retention (`merkle namespace policy edit <label>
   --retain-count 1`).
2. Verify log rotation is configured correctly; the agent rotates at
   50 MB by default.
3. Move backup files to a separate filesystem: update `backup.target`
   in `config.toml` to point to a different mount point.
4. If the database itself is large, review and delete unused Secrets:
   `merkle audit query --op delete --dry-run`.

**Prevention.** Set an alert on `merkle doctor` disk space check output
or on a Prometheus rule for filesystem capacity. Configure backup targets
on filesystems separate from the vault database.

---

## 9. Master Key Rotation Needed — Compromise Suspected

**Symptom.** The operator suspects the OS keychain has been accessed by
an unauthorized party, or a keychain export has occurred. The Master Key
may be compromised.

**Diagnostic.** Review the audit log for unexpected reveals, uses, or
unseal events from unfamiliar session IDs or caller PIDs:

```sh
merkle audit query --since 30d --op unseal --format json
merkle audit query --since 30d --op reveal --sensitivity high --format json
```

**Root Cause.** Master Key compromise results in an attacker being able
to derive the Vault Root Key and decrypt all Namespace DEKs, effectively
exposing all Secret private blobs.

**Remediation.**

1. Ensure a current backup exists: `merkle backup`.
2. Stop all active MCP sessions that may be using the current Master Key.
3. Rotate the Master Key:
   ```sh
   merkle rotate --master-key
   ```
   This generates a new Master Key, re-wraps the Vault Root Key under the
   new key, stores the new Master Key in the keychain, and removes the old
   keychain entry.
4. Invalidate all existing Use Tokens by restarting the agent:
   `systemctl --user restart vault-agent`.
5. Review all Secrets that may have been exposed during the compromise
   window. Rotate any external credentials (API keys, passwords, SSH keys)
   that were stored in the vault.

**Prevention.** Restrict keychain access control lists to the `merkle`
binary path. Enable OS-level audit logging for keychain access events.
Rotate the Master Key periodically as part of a credential hygiene
schedule.

---

## 10. Recovery Key Rotation Needed — Compromise Suspected

**Symptom.** The operator suspects the Recovery Key (age X25519 secret)
has been exposed. The Recovery Key was stored insecurely, or the medium
holding it was accessed by an unauthorized party.

**Diagnostic.** The Recovery Key cannot be used to decrypt the vault
without the backup file; however, any backup file can be decrypted with
the Recovery Key alone. Assess whether any backup files were accessible
to the attacker.

**Root Cause.** The Recovery Key was displayed once at `merkle init` and
was the operator's responsibility to store securely (hardware token,
paper copy in a safe). A compromised Recovery Key combined with a leaked
backup file gives full plaintext access to all Secrets.

**Remediation.**

1. Ensure a current backup exists: `merkle backup`.
2. Rotate the Recovery Key:
   ```sh
   merkle rotate --recovery-key
   ```
   This generates a new age identity, displays the new Recovery Key once
   (record it immediately), updates the Recovery Public Key in
   `config.toml`, and re-wraps the Vault Root Key for the new recipient.
3. The old Recovery Key can no longer decrypt new backups; old backups
   remain decryptable by the old key. If old backup files are accessible
   to an attacker and the compromise window was significant, treat those
   Secrets as exposed and rotate them externally.

**Prevention.** Store the Recovery Key on a hardware security device
(YubiKey, paper in a fireproof safe) with no digital copy. Never store
the Recovery Key on the same machine as the vault.

---

## 11. SQLite Database Locked — Concurrent Access

**Symptom.** Agent operations fail intermittently with
`SQLITE_BUSY (5)` or `SQLITE_LOCKED (6)`. The log shows
`ERROR database is locked; retry timeout exceeded`.

**Diagnostic.**

```sh
# Check if another merkle process is running against the same database
pgrep -a merkle

# Check if any external tool has the database open
lsof ~/.local/share/merkle/vault.db   # macOS/Linux
```

**Root Cause.** A second instance of `merkle agent` is running against
the same database, or an external SQLite client (DB Browser, sqlite3
CLI) has the database open in write mode. The agent architecture
(ADR-0002) enforces a single writer; this error indicates that
constraint has been violated.

**Remediation.**

1. Identify and stop the duplicate agent:
   `pgrep -a merkle` → `kill <duplicate_pid>`.
2. Close any external SQLite client.
3. If the lock is stale (no other process holds it), run:
   `sqlite3 ~/.local/share/merkle/vault.db "PRAGMA wal_checkpoint(TRUNCATE);"`.
4. Restart the agent: `systemctl --user restart vault-agent`.

**Prevention.** Never open the vault database with external tools while
the agent is running. Use `merkle doctor` and `merkle audit` for all
inspection. Service manager configuration ensures only one agent starts
per user.

---

## 12. Stuck Use Token Reaper — Tempfiles Not Cleaned

**Symptom.** Tempfiles created by `vault.write_tempfile` accumulate at
`/tmp/merkle-*` and are not removed after sessions close. Disk space on
`/tmp` grows unexpectedly. The log may show
`WARN orphan tempfile found: path=/tmp/merkle-abc123`.

**Diagnostic.**

```sh
# Count orphaned tempfiles
ls /tmp/merkle-* 2>/dev/null | wc -l

# Check reaper log entries
grep reaper ~/.local/state/merkle/agent.log | tail -20

# Check if session_id in the tempfile registry matches any live session
merkle audit query --op use --since 1h --format json | grep tempfile
```

**Root Cause.** The session that created the tempfile closed without the
agent receiving a clean session close event (network drop, abrupt Claude
Code exit). The reaper runs at boot and on a periodic timer (default
every 5 minutes); if the timer task has stalled, tempfiles accumulate.

**Remediation.**

1. Trigger a manual reap: `merkle agent --reap-orphans` (or send
   `SIGUSR2` to a running agent to trigger an immediate reap cycle).
2. If tempfiles are older than the session TTL (default 1 hour), remove
   them manually: `find /tmp -name 'merkle-*' -mmin +60 -delete`.
3. Restart the agent to reset the reaper timer:
   `systemctl --user restart vault-agent`.

**Prevention.** Set `tempfile_max_age_secs` in `config.toml` to a value
shorter than the session TTL (e.g., 3600). The reaper enforces this
limit regardless of session close events.

---

## 13. Drive Sync Conflict — vault.db.conflict-copy Appearing

**Symptom.** Files named `vault.db.conflict-copy` or
`vault.db (conflicted copy YYYY-MM-DD)` appear in the vault data
directory. Syncing tools (Dropbox, iCloud Drive, Syncthing) have flagged
a conflict on the database file.

**Diagnostic.**

```sh
# Identify conflict files
ls ~/.local/share/merkle/vault.db*

# Check which sync tool is monitoring the directory
lsof ~/.local/share/merkle/ | grep -v merkle
```

**Root Cause.** The vault database directory is being managed by a
file-sync tool. SQLite WAL mode is incompatible with cloud sync agents
because WAL files (`-wal`, `-shm`) must be accessed atomically; sync
tools treat them as independent files and can produce split-brain
conflicts when the same vault is opened on two machines simultaneously.

**Remediation.**

1. Stop the agent on both machines.
2. Identify the authoritative copy (check the `merkle_audit_entries_total`
   count in each; the larger number is authoritative, or use timestamps).
3. Preserve the conflict copy in a safe location.
4. Restore the authoritative database: copy it to the canonical path.
5. Remove the conflict copy from the vault directory.
6. Restart the agent on one machine only.
7. Exclude the vault data directory from sync:
   - Dropbox: add `.dropboxignore` in `~/.local/share/merkle/`.
   - iCloud Drive: move the vault directory outside the iCloud container.
   - Syncthing: add the directory to `.stignore`.

**Prevention.** Never place the vault database inside a cloud-synced
folder. Use `merkle backup` with an age-encrypted backup file as the
portable format — backup files are conflict-safe (each is a snapshot).

---

## 14. Lost Laptop Scenario — Disaster Recovery on New Machine

**Symptom.** The original machine is lost, stolen, or destroyed. The
operator has the Recovery Key (X25519 age secret) and a backup file
(`merkle-bk-*.merkle.age`). No access to the original keychain.

**Diagnostic.** Confirm the Recovery Key is available (offline storage,
hardware token). Locate the most recent backup file from the backup
target (external drive, cloud storage, secondary target).

**Remediation.**

1. Install Merkle on the new machine via any distribution channel
   (section 1 of `deployment.md`).

2. Do not run `merkle init`. Instead, restore directly from backup using
   the Recovery Key path:

   ```sh
   merkle restore \
       --backup merkle-bk-2026-05-22T10-00-00Z.merkle.age \
       --recovery-key    # prompts for the age secret key
   ```

3. The restore command:
   a. Decrypts the backup using the Recovery Key (age X25519 recipient).
   b. Validates the backup integrity.
   c. Previews the restore (number of Namespaces, Secrets, Audit Entries).
   d. Prompts for confirmation before applying.
   e. Generates a new Master Key, stores it in the new machine's keychain.
   f. Re-wraps the Vault Root Key under the new Master Key.

4. Start the agent: `merkle agent`.

5. Register the service on the new machine (section 4 of `deployment.md`).

6. Run `merkle doctor` to verify full health.

7. Rotate the Recovery Key as a precaution (the old key is unaffected by
   the restore, but if the old device is not wiped it could still hold
   keychain access):
   ```sh
   merkle rotate --recovery-key
   ```

**Prevention.** Test disaster recovery annually on a non-production
machine. Store the Recovery Key in at least two physically distinct
offline locations. Maintain at least one backup target on storage
independent of the primary machine.

---

## 15. Suspected Prompt-Injection Exfil Attempt

**Symptom.** The audit log shows an unusual pattern of `reveal`
operations: many high-sensitivity Secrets revealed in a short window
(seconds to minutes), possibly from a single MCP session, targeting
multiple namespaces. The operator did not issue the corresponding
`/merkle-reveal` slash commands. The `merkle_reveals_total` metric
spikes. Rate-limit denials begin firing.

**Diagnostic.**

```sh
# Identify rapid reveals in the last hour
merkle audit query \
    --since 1h \
    --op reveal \
    --format json | \
    jq '.[] | {ts, session_id, handle, outcome, caller_pid}'

# Identify the session responsible
merkle audit query --since 1h --op reveal --format json | \
    jq 'group_by(.session_id) | map({session: .[0].session_id, count: length})'

# Check whether slash-command confirmation flags were set
# (outcome "allowed" without operator intervention = policy misconfiguration)
merkle audit query --since 1h --op reveal --format json | \
    jq '.[] | select(.outcome == "allowed") | .purpose'
```

**Root Cause.** A prompt-injection payload embedded in external content
(web page, file, API response) instructed the LLM to call `vault.reveal`
repeatedly. If the Reveal Policy is misconfigured to allow reveals
without slash-command confirmation, or if the attacker found a way to
simulate the confirmation flag, secrets may have been exfiltrated via
the LLM transcript.

**Remediation.**

1. Immediately terminate the compromised MCP session: `merkle session kill
   <session_id>` or restart the agent to drop all sessions.

2. Assess exposure: for every handle that shows `outcome=allowed` in the
   suspicious window, treat the corresponding Secret as compromised.

3. Rotate all compromised Secrets externally (API keys, passwords, SSH
   keys, tokens) before doing anything else.

4. Revoke them in the vault: `merkle rotate --handle vault://...` for
   each compromised Secret.

5. Review Reveal Policy. Confirm `reveal_requires_slash = true` and
   `confirmation_via_slash = true` for all high-sensitivity Namespaces:
   ```sh
   merkle namespace policy show <label>
   ```

6. If policy was misconfigured, correct it immediately:
   ```sh
   merkle namespace policy edit <label> \
       --reveal-requires-slash true \
       --oob-confirmation-threshold medium
   ```

7. Review rate limit settings. Lower `reveals` rate-limit class to a
   tighter bound for the affected Namespace.

8. Preserve the audit log for forensic analysis: export it before any
   database changes:
   ```sh
   merkle audit query --since 24h --format ndjson > incident-audit.ndjson
   ```

9. Conduct a blameless post-incident review. Determine how the
   confirmation flag was bypassed (or whether the policy gap permitted
   unrestricted reveals). Update the threat model accordingly.

**Prevention.** Set `reveal_requires_slash = true` for every Namespace
that contains any `sensitivity = high` Secret. Enable OOB Confirmation
for high-sensitivity reveals as a second channel. Configure rate limits
for the `reveals` class tightly (e.g., 3 per 5 minutes). Monitor the
`merkle_reveals_total` metric and alert on any burst. Treat the audit log
chain as the authoritative forensic record — its integrity guarantee is
the primary detection mechanism for this attack class.

---

## 16. OOB Notifier Unavailable

**Severity.** P2 (P1 if the affected Namespace uses `sensitivity = high`
and OOB Confirmation cannot be bypassed by policy).

**Alert file.** No dedicated alert condition file. Detect via the
`merkle_oob_notifier_available` gauge dropping to `0`; add a local
Prometheus rule if automated paging is required.

**Symptom.** `merkle doctor` reports `"oob_notifier": "unavailable"` in
its JSON output. For Namespaces with `oob_confirmation_threshold = high`,
all Reveal and Use operations that require OOB Confirmation are blocked.
`merkle_oob_notifier_available` reads `0`. The agent log contains entries
such as:

```
WARN oob_notifier probe failed: channel=desktop-notif reason=notifier_unavailable
```

**Diagnostic.**

```sh
# Check the notifier gauge
curl -s http://localhost:9117/metrics | grep merkle_oob_notifier_available

# Run doctor for structured output
merkle doctor --json | jq '.oob_notifier'

# Per-channel checks:

# desktop-notif — Linux: verify libnotify / notify-send
which notify-send && notify-send --version

# desktop-notif — macOS: verify osascript
osascript -e 'display notification "test" with title "merkle"'

# desktop-notif — Windows: check Toast availability
# (no CLI probe; check Windows version >= 10 build 10586)

# terminal-prompt — check TTY ownership
ls -la /proc/$MERKLE_PID/fd/0    # Linux (stdin of the agent process)
# If running under systemd without a user session, stdin is /dev/null

# localhost-confirm — check port binding
ss -tlnp | grep 39842            # Linux
lsof -iTCP:39842                 # macOS
```

**Root Cause.** Four common root causes depending on the configured OOB
channel:

- `desktop-notif`: the notification daemon (`libnotify`, `gnome-shell`,
  Windows Toast) is absent, the `$DISPLAY` or `$DBUS_SESSION_BUS_ADDRESS`
  environment variable is unset (headless environment, CI runner,
  systemd service without a user session).
- `terminal-prompt`: the agent's stdin is not a TTY (`/dev/null` under
  systemd, piped input in a script, SSH session without a pseudo-terminal).
- `localhost-confirm`: port `39842` is already bound by another process,
  or a firewall rule blocks loopback connections on that port.
- Any channel: the agent process lacks the OS permission needed to reach
  the notification subsystem (SELinux/AppArmor policy, container seccomp
  filter).

**Remediation.**

1. Identify the active OOB channel:
   ```sh
   merkle namespace policy show <label> | grep oob_channel
   ```

2. For `desktop-notif` on a systemd service: inject the display and bus
   variables into the unit:
   ```ini
   [Service]
   Environment=DISPLAY=:0
   Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
   ```
   Then reload and restart: `systemctl --user daemon-reload &&
   systemctl --user restart vault-agent`.

3. For `terminal-prompt` in a headless environment: switch the Namespace
   OOB channel to `desktop-notif` or `localhost-confirm`:
   ```sh
   merkle policy update --namespace <ns> --oob-channel desktop-notif
   ```

4. For `localhost-confirm` port collision: identify the conflicting
   process (`lsof -iTCP:39842`) and either stop it or reconfigure the
   Merkle listen port in `config.toml`:
   ```toml
   [oob_notifier]
   localhost_confirm_port = 39843
   ```

5. If the notifier cannot be restored promptly and the Namespace
   sensitivity does not require the full confirmation gate, lower the OOB
   confirmation threshold temporarily per the signed config flag described
   in ADR-0011 amendment. **This reduces security posture and must be
   treated as a temporary measure.** Record the change in the audit log
   and revert as soon as the notifier is restored.

6. If unavailability cannot be tolerated within 30 minutes, page the
   on-call operator to assess whether the affected Namespace must be
   locked until the notifier recovers.

**Prevention.** Run `merkle doctor` in CI and on service-start hooks to
detect notifier availability before load arrives. For automation
Namespaces, pre-select an OOB channel compatible with the deployment
environment. Avoid `terminal-prompt` for any workload that runs under a
service manager.

---

## 17. MCP Adapter Latency Regression

**Severity.** P2.

**Alert files.**
`docs/arch/slo/alerting/alert-condition-vault-use-latency-fast-burn.yaml`;
related conditions for `vault.list`, `vault.reveal`, and
`vault.ssh_exec` are referenced by
`docs/arch/slo/alerting/alert-policy-mcp-adapter-latency.yaml`.

**Symptom.** One or more of the following fast-burn alert conditions fire:
`vault-list-latency-fast-burn`, `vault-reveal-latency-fast-burn`,
`vault-use-latency-fast-burn`, or `vault-ssh-exec-overhead-fast-burn`.
The p95 latency for the affected operation climbs above its SLO target
(50 ms for `vault.list`, 150 ms for `vault.reveal`, 100 ms for
`vault.use`, 20 ms overhead for `vault.ssh_exec`). The error budget
burns faster than 2x the baseline rate.

**Diagnostic.**

```sh
# Query p95 latency for vault.list (substitute op for other operations)
histogram_quantile(0.95,
  sum by(le)(
    rate(merkle_rpc_duration_seconds_bucket{op="vault.list"}[5m])
  )
)

# Check RPC error rate alongside latency
rate(merkle_rpc_errors_total{op="vault.list"}[5m])

# Check Companion Socket queue depth
curl -s http://localhost:9117/metrics | grep merkle_companion_socket_queue_depth

# Identify slow queries at the SQLite layer
merkle doctor --explain-slow

# Check FTS5 index health
merkle doctor --fts5

# Check OS-level resource pressure
iostat -x 1 5      # disk I/O saturation
vmstat 1 5         # memory / swap usage
free -m            # confirm no swap engagement (mlock integrity)
```

**Root Cause.** Common causes in order of likelihood:

- SQLite WAL checkpoint stall: the WAL file has grown large and a
  checkpoint is blocking writes. Symptom: `iostat` shows elevated disk
  writes; `PRAGMA wal_checkpoint` times out.
- FTS5 index bloat: after many put/delete cycles the FTS5 index grows
  fragmented. `vault.list` queries degrade quadratically.
- Companion Socket back-pressure: queue depth is high, indicating that
  the agent is processing Use Token resolves faster than clients consume
  responses.
- System memory pressure / swap engagement: the agent's locked memory
  pages (`mlock`) are being paged out, causing crypto operations to stall
  on swap I/O.
- SQLite `SQLITE_BUSY` spin on WAL readers holding a read lock during a
  checkpoint attempt.

**Remediation.**

1. Run a full vacuum and FTS5 index rebuild:
   ```sh
   merkle doctor --vacuum
   ```
2. Force a WAL checkpoint:
   ```sh
   merkle doctor --wal-checkpoint
   ```
3. If memory pressure is confirmed (swap in use), free memory on the
   host before restarting the agent. After restart, verify `mlock` is
   active in the log (`INFO mlock: pages locked`).
4. Perform a controlled agent restart (Sealed → Unsealed cycle) to reset
   in-memory state and clear any queue backlog:
   ```sh
   systemctl --user restart vault-agent
   ```
5. For persistent regressions, capture a CPU and allocation profile:
   ```sh
   merkle agent --profile cpu --profile-duration 30s
   ```
   Share the profile output with the development team.

**Prevention.** Schedule `merkle doctor --vacuum` weekly via the system
cron or a systemd timer. Alert on `merkle_companion_socket_queue_depth`
exceeding a threshold of 100 pending items. Ensure the host running the
agent has sufficient free RAM to avoid swap engagement.

---

## 18. Companion Socket Connect Rate Drop

**Severity.** P2.

**Alert file.**
`docs/arch/slo/indicators/companion-socket-connect-rate.yaml` (SLI
source). No dedicated fast-burn alert condition file exists; add a local
Prometheus rule targeting
`merkle_companion_socket_connects_total{outcome="rejected"}` if
automated alerting is needed.

**Symptom.** The `companion-socket-connect-rate` SLI degrades below the
99.9% target. Authorized MCP clients fail to connect to the Companion
Socket. The agent log records entries such as:

```
WARN companion_socket: peer credential check failed: pid=<n> reason=not_in_allowlist
ERROR companion_socket: accept error: Too many open files
```

The `merkle_companion_socket_connects_total{outcome="rejected"}` counter
rate spikes. Clients receive `ErrAgentUnreachable` on every connection
attempt.

**Diagnostic.**

```sh
# Check rejection rate
curl -s http://localhost:9117/metrics | \
    grep 'merkle_companion_socket_connects_total'

# Inspect socket file permissions
stat /run/merkle/companion.sock         # Linux service path
stat ~/.local/run/merkle/agent.sock     # user-session path

# Check peer-credential rejections in the journal
journalctl -u merkle-agent | grep "peer cred" | tail -30

# Confirm the connecting process is in the allowed consumers list
merkle config show | grep allowed_consumers

# Check file descriptor limits (for "too many open files" errors)
cat /proc/$(pgrep merkle)/limits | grep "open files"
ulimit -n
```

**Root Cause.** Three common root causes:

- Socket file permission drift: a previous agent crash left the socket
  with incorrect permissions (`0600` instead of `0660`), or the parent
  directory changed ownership.
- Allowed-consumers allowlist drift: the PID or binary path of the
  connecting client changed (upgrade, path change, new Claude Code
  version) and no longer matches the allowlist entry.
- Agent restart in-flight: a client connected during an agent restart
  window; the socket was unlinked before the connection completed.
- File descriptor exhaustion: the agent hit the OS `RLIMIT_NOFILE` limit
  under high session concurrency.

**Remediation.**

1. Verify the socket file exists and has correct permissions:
   ```sh
   ls -la ~/.local/run/merkle/agent.sock
   # Expected: srwxr-x--- merkle merkle
   ```
   If the socket has wrong permissions or is absent, restart the agent —
   it recreates the socket with correct mode on startup.

2. If peer-credential rejections appear, update the allowed-consumers
   allowlist:
   ```sh
   merkle config set companion_socket.allowed_consumers \
       "/path/to/updated/merkle-mcp"
   ```
   Then reload: `systemctl --user restart vault-agent`.

3. For file descriptor exhaustion, raise the limit in the systemd unit:
   ```ini
   [Service]
   LimitNOFILE=65536
   ```
   Reload: `systemctl --user daemon-reload && systemctl --user restart vault-agent`.

4. Perform a coordinated agent restart to clear stale connection state:
   ```sh
   systemctl --user restart vault-agent
   ```
   Verify recovery: `merkle doctor`.

**Prevention.** Pin allowed-consumers entries to binary hashes rather
than paths where possible. Set `LimitNOFILE` to at least `65536` in the
systemd unit from initial deployment. Include a socket-permission check
in the `merkle doctor` suite.

---

## 19. Unseal Failure — Second in Calendar Month

**Severity.** P2 (escalate to P1 if an attack attempt is suspected).

**Alert file.**
`docs/arch/slo/alerting/alert-condition-unseal-failure.yaml`
(`unseal-failure-second-in-month`).

**Symptom.** The `unseal-failure-second-in-month` alert condition fires.
The `merkle_unseal_total{outcome="failure"}` counter has incremented at
least twice within the current calendar month. The agent entered or
remained in `sealed` state. The log contains:

```
ERROR unseal failed: reason=keychain_access_denied
```

or a similar unseal-failure reason.

**Diagnostic.**

```sh
# Count unseal failures in the last 30 days
merkle audit query --op unseal --outcome error --since 30d --format json | \
    jq 'length'

# Review the failure entries for reason and caller context
merkle audit query --op unseal --outcome error --since 30d --format json | \
    jq '.[] | {ts, reason: .purpose, session_id, caller_pid}'

# Check Argon2id parameters stored in the vault header
merkle doctor --json | jq '.argon2id_params'

# Check OS keychain reachability directly
security find-generic-password -s dev.fapp.merkle -a master-v1 -w  # macOS
secret-tool lookup service dev.fapp.merkle account master-v1         # Linux

# Check for locked-out state (too many failures)
curl -s http://localhost:9117/metrics | grep 'merkle_unseal_total'
```

**Root Cause.** Two categories of root cause:

- **Configuration / environment**: the OS keychain entry for the Master
  Key was deleted, the binary ACL changed after an upgrade, the Secret
  Service daemon stopped (Linux), or the Argon2id memory cost parameter
  `m_cost` was reduced below the minimum enforced by the vault, causing
  a parameter-mismatch error on unseal.
- **Security event**: an unauthorized process attempted to unseal the
  vault (wrong passphrase, cloned binary without keychain ACL
  permissions, automated brute-force attempt).

**Remediation.**

1. Do not attempt to bypass the unseal failure. Investigate the audit
   entries first.

2. If the cause is a missing keychain entry (see scenario 2 for detailed
   keychain remediation steps):
   ```sh
   merkle unseal --passphrase   # fall back to passphrase if configured
   ```

3. If the cause is a parameter mismatch, do not lower `m_cost` to work
   around the check. Restore the correct parameter by re-running the
   unseal after verifying the vault was initialized with the expected
   parameters:
   ```sh
   merkle doctor --json | jq '.argon2id_params'
   ```

4. If an attack attempt is suspected (unfamiliar `caller_pid`, unusual
   time-of-day pattern, multiple rapid attempts), treat as an incident:
   - Stop the agent: `systemctl --user stop vault-agent`.
   - Preserve the audit log: `merkle audit query --since 30d
     --format ndjson > incident-$(date +%s)-unseal.ndjson`.
   - Follow the incident-response runbook. Rotate the Master Key
     (scenario 9) before restarting.

5. After remediation, confirm a clean unseal:
   ```sh
   merkle agent &
   merkle doctor
   ```

**Prevention.** Run `merkle doctor` after every OS upgrade or binary
replacement to confirm keychain access before the next unseal attempt
reaches the failure threshold. Enable the `unseal-failure-second-in-month`
alert condition (see alert file above) so that a second failure in a
month pages the operator automatically. Store the passphrase fallback
credential in a password manager as a break-glass for keychain-loss
scenarios.

---

## 20. Audit Chain Integrity Broken

**Severity.** P1. No error budget; treat as an incident immediately.

**Alert file.**
`docs/arch/slo/alerting/alert-condition-audit-chain-broken.yaml`
(`audit-chain-broken`).

**Symptom.** The `audit-chain-broken` alert fires. The
`merkle_chain_integrity_ok` gauge reads `0`. The
`merkle_chain_verifications_total{outcome="broken"}` counter increments.
`merkle doctor` reports `[ERROR] Audit chain broken at entry <id>`.
Secret writes are frozen (the agent refuses new Audit Entries when chain
integrity cannot be confirmed).

**Diagnostic.**

```sh
# Confirm the gauge reading
curl -s http://localhost:9117/metrics | grep merkle_chain_integrity_ok

# Identify the break point
merkle audit verify --range full --format json 2>&1 | \
    jq '.break_point'

# Inspect entries around the break
merkle audit query \
    --since 2026-01-01T00:00:00Z \
    --format json | \
    jq '.[] | select(.entry_id == "<broken_id>" or .prev_entry_id == "<broken_id>")'

# Check SQLite database integrity
sqlite3 ~/.local/share/merkle/vault.db "PRAGMA integrity_check;"

# Check filesystem for signs of hardware fault
dmesg | grep -iE "I/O error|EXT4-fs error|disk failure" | tail -20
```

**Root Cause.** The Hash Chain design makes it impossible to modify,
remove, or reorder an Audit Entry without invalidating every subsequent
`current_hash`. Two root causes are possible:

- **Disk corruption**: an unclean shutdown, storage hardware fault, or
  filesystem bug corrupted one or more SQLite pages covering the audit
  table. The SQLite `integrity_check` pragma will report errors in this
  case.
- **Deliberate tampering**: an attacker with write access to the database
  file modified or deleted an Audit Entry. The `integrity_check` pragma
  may pass (the page-level structure is intact) while the chain HMAC
  verification fails.

**Remediation.**

> **STOP.** Do not modify the database to repair the chain. Do not run
> `VACUUM` or `wal_checkpoint` on the broken database. Every action
> before the forensic snapshot destroys evidence.

1. Stop the agent immediately to preserve forensic state:
   ```sh
   systemctl --user stop vault-agent
   ```

2. Create a timestamped forensic snapshot before any other action:
   ```sh
   SNAP=/tmp/forensic-$(date +%s)
   mkdir -p "$SNAP"
   cp -p ~/.local/share/merkle/vault.db        "$SNAP/"
   cp -p ~/.local/share/merkle/vault.db-wal    "$SNAP/" 2>/dev/null || true
   cp -p ~/.local/share/merkle/audit_head.json "$SNAP/" 2>/dev/null || true
   cp -p ~/.local/state/merkle/agent.log       "$SNAP/"
   echo "Snapshot at $SNAP"
   ```

3. Compare the pinned chain head against the reconstructed head to
   narrow the break window:
   ```sh
   merkle audit verify --range full --format json > "$SNAP/verify.json"
   ```

4. Determine the cause using `PRAGMA integrity_check` output:
   - If `integrity_check` returns errors: disk corruption confirmed.
     Restore from the most recent verified backup:
     ```sh
     merkle restore \
         --backup <path/to/latest.merkle.age> \
         --recovery-key
     ```
   - If `integrity_check` returns `ok`: tampering suspected. Notify the
     security team. Do not restore until the incident scope is assessed.

5. After restore, verify the chain on the restored database:
   ```sh
   merkle audit verify --range full
   ```
   Confirm `merkle_chain_integrity_ok` returns to `1`:
   ```sh
   curl -s http://localhost:9117/metrics | grep merkle_chain_integrity_ok
   ```

6. Restart the agent and confirm full health:
   ```sh
   systemctl --user start vault-agent
   merkle doctor
   ```

**Escalation.** This is a P1 incident. Notify the security team
immediately when tampering cannot be ruled out. Preserve the forensic
snapshot for investigation. Do not resume normal operations until the
chain integrity source is confirmed and the restored database verifies
clean.

**Prevention.** Store backups on media physically separate from the vault
database (different drive, different host). Enable filesystem checksumming
(ZFS, APFS) on the volume hosting the database. Run `merkle doctor`
daily via a systemd timer or cron job. The `merkle_chain_integrity_ok`
gauge should be scraped by Prometheus and the `audit-chain-broken` alert
condition activated so that any breach pages the operator within 5
minutes.
