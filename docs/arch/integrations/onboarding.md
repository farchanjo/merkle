# Onboarding Flow

Client-perspective walkthrough of the first-run experience from
installation through a working MCP session. This document covers
what the operator sees and does; the corresponding server-side
procedure (service registration, binary installation) is documented
in `operations/deployment.md`.

## 1. Prerequisites

Before running `merkle init`:

- Merkle binary is installed and on `$PATH` (see `operations/deployment.md`
  Section 1 for distribution-channel instructions).
- An OS keychain backend is available:
  - macOS: login keychain unlocked.
  - Linux: Secret Service daemon running (GNOME Keyring or KWallet).
  - Windows: Credential Manager accessible.
  - Headless or CI: passphrase fallback is used automatically.
- Claude Code is installed with MCP support enabled.

## 2. First-Run Init

Run the interactive wizard:

```sh
merkle init
```

The wizard proceeds through seven steps. The operator is prompted at
each step; defaults are shown in brackets.

| Step | Prompt | Action |
|---|---|---|
| 1 | Database path | Accept default (`~/.local/share/merkle/vault.db`) or specify an alternative. |
| 2 | Config path | Accept default (`~/.config/merkle/config.toml`) or specify an alternative. |
| 3 | Security Profile | Choose `relaxed`, `balanced` (recommended), or `paranoid`. |
| 4 | Master Key generation | The wizard generates a 32-byte Master Key at random and stores it in the OS Keychain under service `dev.fapp.merkle`, account `master-v1`. No operator input required. |
| 5 | Recovery Key display | The wizard generates a Recovery Key (X25519 age identity). The key is displayed once in the terminal. **Record it offline immediately.** |
| 6 | Recovery Key confirmation | The wizard prompts the operator to re-enter the first four words of the Recovery Key. This confirms the key was recorded before the wizard proceeds. |
| 7 | Service registration | Optionally registers the Vault Agent with the OS service manager (launchd, systemd, SCM). Recommended for persistent background operation. |

After step 7 completes, `merkle init` prints a confirmation and
suggests running `merkle agent` if service registration was skipped.

## 3. Master Key and Recovery Key

The **Master Key** is a 32-byte symmetric key at the top of the key
hierarchy. It is generated once at init, stored in the OS Keychain,
and never displayed. It can be rotated later with `merkle rekey`.

The **Recovery Key** is an `age` X25519 secret key. It is generated
once at init, displayed exactly once, and never stored by the system.
It must be recorded offline — in a printed document, an offline
password manager, or a hardware security token. Without the Recovery
Key, disaster recovery is impossible if the OS Keychain is lost.

The corresponding **Recovery Public Key** is stored in plaintext in
`config.toml` and used to encrypt all Backups and to dual-wrap the
Vault Root Key.

**Warning**: if the Recovery Key display is dismissed without
recording it, there is no way to retrieve it. Re-run `merkle init`
on an empty installation to generate a new one, or use `merkle rotate`
to generate a new Recovery Key and re-encrypt the vault.

## 4. Recovery Key Verification Step

After the Vault Agent reaches Unsealed State for the first time, the operator
MUST verify the Recovery Key before creating any secrets. This confirms that
the recorded key matches the Recovery Public Key stored in `config.toml` while
the vault is still empty.

Run the verification command:

```sh
merkle verify-recovery-key
```

The command reads the Recovery Key interactively from the TTY (terminal echo
disabled via `rpassword`). Alternatively, supply an identity file:

```sh
merkle verify-recovery-key --identity-file /path/to/recovery-key.txt
```

Expected output on success:

```
ok: recovery key matches recovery_pubkey in config.toml
```

On mismatch, the command exits with code 1 and prints a `mismatch:` diagnostic.
It does not modify any vault state.

The `merkle doctor` command reports `WARN: recovery key not yet verified` until
at least one successful `verify-recovery-key` run is recorded in the audit log.

See [ADR-0006](../adr/0006-age-encryption-for-backups-and-recovery.md)
Amendment 2 for the full command specification.

## 5. Initial Namespace Seed

After the agent starts, create at least one Namespace before issuing
MCP tool calls. The simplest path is via the CLI:

```sh
merkle put --namespace personal --category password --name example \
    --value '{"password":"change-me"}' --sensitivity low
```

Alternatively, from a Claude Code session after the MCP server is
configured (see Section 7), direct Claude to create the initial
Namespace:

```
"Create a namespace called personal and add a low-sensitivity
password secret named example with value change-me."
```

Claude calls `vault_bind` (which creates the Namespace on first
use) followed by `vault_put`.

## 6. Companion Device Pairing (Optional)

A Companion Device is a pre-paired secondary device that authenticates
Reveal operations via Ed25519 signature on OOB Confirmation challenges.
Enrolling a Companion Device is optional and not required for normal
operation; it provides a cryptographically bound second factor for
`sensitivity=high` Reveals.

### Enrollment ceremony

The enrollment ceremony uses `merkle device pair` and establishes an
Ed25519 identity for the device:

1. On the primary device, run:

   ```sh
   merkle device pair
   ```

   The command generates an Ed25519 keypair using `OsRng`. The private
   key is stored in the OS keychain under service identifier
   `merkle-companion-<device-id>`, where `device-id` is a randomly
   generated URL-safe base64 identifier (16 bytes, 22 characters). The
   corresponding Ed25519 public key is written to the vault's sealed
   state alongside the `device-id`.

2. The command displays a QR code and a pairing code in the terminal.
   On the companion device, install the Merkle companion app and scan
   the QR code or enter the pairing code to complete the exchange.

3. After pairing, confirm enrollment with `merkle device list`, which
   prints enrolled devices and their enrollment timestamps (public keys
   are not printed by default).

Multiple devices may be enrolled; each has an independent Ed25519
identity entry.

### Revoking a device

```sh
merkle device revoke <device-id>
```

This removes the public key from the vault's sealed state and deletes
the keychain entry on the local machine.

### Challenge signing protocol

Once a Companion Device is enrolled, every OOB Confirmation challenge
includes a Request Nonce (32-byte random value, URL-safe base64). The
Companion Device signs the challenge fields together with the nonce
using its Ed25519 private key. The Vault Agent verifies the signature
against the stored public key before accepting the confirmation. A
missing or invalid signature is rejected with an `oob_signature_invalid`
audit entry and the reveal is denied.

See [ADR-0011](../adr/0011-slash-only-reveal-with-oob-for-high-sensitivity.md)
Amendment for the full enrollment ceremony and cryptographic binding
specification. See Glossary: Companion Device, Request Nonce.

## 7. Connecting Claude Code

Add the MCP server entry to `~/.claude.json`:

```json
{
  "mcpServers": {
    "merkle": {
      "command": "/usr/local/bin/merkle",
      "args": ["mcp"],
      "env": {
        "MERKLE_PROFILE": "balanced"
      }
    }
  }
}
```

Restart Claude Code or run `/mcp restart merkle`.

Verify the connection:

```
Ask Claude: "Call vault_doctor and show me the full result."
```

Expected response includes `"sealed": false` if the agent is running
and Unsealed. If `"sealed": true`, run `merkle unseal` in a terminal.

For full slash command configuration (Operator Confirmation flows),
see `integrations/claude-code-wiring.md`.

## 8. References

- `operations/deployment.md` — installation and service registration.
- `integrations/claude-code-wiring.md` — slash commands and Operator
  Confirmation flows.
- Glossary: `../glossary.md` (Master Key, Recovery Key, Namespace,
  OOB Confirmation, Sealed State, Unsealed State, Companion Socket,
  Companion Device, Request Nonce).
- ADR-0006: age encryption for Backups and Recovery Key.
- ADR-0011: Slash-only Reveal with OOB for high sensitivity.
