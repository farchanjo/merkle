# macOS LaunchAgent — Merkle Vault Agent

Per-user LaunchAgent that auto-starts `merkle-agent` at login and
restarts it on crash. Pairs with the deploy + codesign procedure
documented in the project `CLAUDE.md`.

## Files

| File | Role |
|---|---|
| `dev.fapp.merkle.agent.plist` | LaunchAgent template — Label `dev.fapp.merkle.agent`, KeepAlive on crash only, throttle 10s. |
| `merkle-agent-launchd` | Wrapper script: fetches `MERKLE_KEYSTORE_PASSPHRASE` from macOS login Keychain and exec's the agent. Keeps the passphrase out of the plist. |

## Install

Assumes `/usr/local/bin/merkle-agent` is already deployed + codesigned
per the project `CLAUDE.md` deploy sequence.

```bash
# 1. Install the wrapper (signed implicitly — sh script).
sudo install -m 755 -o root -g wheel \
  deploy/launchd/merkle-agent-launchd \
  /usr/local/bin/merkle-agent-launchd

# 2. Provision the file-keystore passphrase in the login Keychain.
#    Touch ID / login keychain unlock prompt may appear once.
security add-generic-password \
  -s 'dev.fapp.merkle.launchd' \
  -a 'passphrase' \
  -w '<your-keystore-passphrase>' \
  -U

# 3. Render the plist with your username (the template ships with
#    REPLACE_WITH_USER placeholders) and copy into ~/Library/LaunchAgents/.
mkdir -p ~/Library/LaunchAgents ~/Library/Logs
sed "s|REPLACE_WITH_USER|$USER|g" \
  deploy/launchd/dev.fapp.merkle.agent.plist \
  > ~/Library/LaunchAgents/dev.fapp.merkle.agent.plist

# 4. Bootstrap into the user GUI session.
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/dev.fapp.merkle.agent.plist

# 5. Verify.
launchctl print gui/$UID/dev.fapp.merkle.agent | head -25
/usr/local/bin/merkle status
```

## Lifecycle

```bash
# Status
launchctl print gui/$UID/dev.fapp.merkle.agent

# Restart (force kill + relaunch)
launchctl kickstart -k gui/$UID/dev.fapp.merkle.agent

# Stop until next login
launchctl bootout gui/$UID/dev.fapp.merkle.agent

# Logs
tail -f ~/Library/Logs/merkle-agent.err.log
tail -f ~/Library/Logs/merkle-agent.out.log

# Permanently uninstall
launchctl bootout gui/$UID/dev.fapp.merkle.agent
rm ~/Library/LaunchAgents/dev.fapp.merkle.agent.plist
security delete-generic-password -s 'dev.fapp.merkle.launchd' -a 'passphrase'
sudo rm /usr/local/bin/merkle-agent-launchd
```

## Auto-start at login

Files in `~/Library/LaunchAgents/` are auto-scanned by `launchd` at user
login. The plist runs at every login as long as it remains in that
directory; KeepAlive (Crashed=true, SuccessfulExit=false) restarts after
unexpected exits but respects intentional shutdown.

## System-wide variant

For a multi-user daemon (NOT recommended for a user-scoped vault — keychain
access is per-user, Touch ID is per-session):

1. Move plist to `/Library/LaunchDaemons/dev.fapp.merkle.agent.plist` (owner
   root:wheel, mode 644).
2. Add `<key>UserName</key><string>some-user</string>` so the daemon runs
   as a specific user (otherwise it runs as root — wrong for `$HOME`-rooted
   storage paths).
3. Adjust `StandardOutPath` / `StandardErrorPath` / `WorkingDirectory` to
   paths writable by that user.
4. `sudo launchctl bootstrap system /Library/LaunchDaemons/...`.

## Legacy plist

`dev.fapp.merkle.plist` (label `dev.fapp.merkle`) was the initial
single-process template before the keystore passphrase + wrapper landed.
Retained only for archival reference; new installs use the `.agent` plist
+ wrapper documented above.
