# Glossary

Canonical vocabulary for the Merkle project. Every artifact under
`docs/arch/` MUST use these terms with the exact meaning defined here.
Translations in chat are allowed; written artifacts stay en-US.

Terms are grouped by bounded context. Cross-context references are
explicit (link or qualified name). When a term has a well-known
external definition (RFC, IETF spec), the source is cited.

## Identity and Sealing

**Master Key** — 32-byte symmetric key used as the top of the key
hierarchy. Generated once at `merkle init`. Wrapped by the OS
keychain (macOS Security framework, Linux Secret Service, Windows
Credential Manager) or, when no keychain is available, by a key
derived from the user passphrase via Argon2id (RFC 9106). Never
persisted in plaintext.

**Recovery Key** — `age` identity (X25519 secret key) generated at
init, displayed exactly once to the operator, and never stored by
the system. Used to unwrap the Vault Root Key when the Master Key
is unavailable (keychain wiped, OS reinstalled, hardware lost).

**Recovery Public Key** — `age` recipient corresponding to the
Recovery Key. Stored in plaintext in `config.toml`. Used to encrypt
backups and to dual-wrap the Vault Root Key.

**Vault Root Key** — 32-byte symmetric key that protects all
Namespace DEKs. Stored in the database wrapped twice: once by the
Master Key and once for the Recovery Public Key.

**Namespace DEK** — Data Encryption Key, 32-byte symmetric key per
Namespace. Encrypts the `private_blob` field of every Secret in the
Namespace. Wrapped by the Vault Root Key. Allows revocation at
Namespace granularity by destroying a single DEK.

**Sealed State** — Vault Root Key is not loaded in agent memory.
All read and write operations rejected. Default state on agent
boot until unseal succeeds.

**Unsealed State** — Vault Root Key is loaded in agent memory
(mlocked when supported). Read and write operations permitted.

**Unseal Protocol** — Procedure that transitions the agent from
Sealed to Unsealed: fetch Master Key from keychain (or derive from
passphrase), decrypt Vault Root Key, hold in protected memory.

## Secret Storage

**Namespace** — Top-level container for related Secrets. Identified
by a UUIDv7 and a stable label. Bound by default to the current
working directory hash; overridable by `.merklerc` in the project
root or by `vault.bind(label)` in the MCP session.

**Secret** — Aggregate root storing a credential, key, token, note,
or any structured artifact under a Category. Has public metadata
(visible in the transcript) and a private blob (encrypted, never in
the transcript).

**Secret Version** — Historical revision of a Secret. Created on
every `vault.rotate`. Retention governed by the Namespace Policy
(default `retain_count = 3`).

**Handle** — Opaque URI identifying a Secret without exposing its
material. Format: `vault://<namespace-label>/<category>/<name>`.
Sufficient to invoke any proxy tool; insufficient to reveal
plaintext.

**Category** — Closed enum classifying the shape and semantics of
a Secret. Built-in: `ssh`, `password`, `token`, `env`, `cert`,
`key`, `database`, `note`, `otp`, `cloud`, `gpg`. Custom categories
allowed but require a declared CUE schema.

**Sensitivity** — Closed enum: `low`, `medium`, `high`. Determines
whether OOB Confirmation is required for reveal, and the default
rate-limit class.

**Tag** — Structured discriminator of the form `key:value`. Used
as informal cohesion between Secrets in absence of foreign keys.
Examples: `env:prod`, `project:acme`, `role:bastion`.

**Public Metadata** — Set of fields in the Secret whose values are
returned by `vault.list` and `vault.describe`. Designed to let the
LLM reason about the Secret without ever seeing the private blob.

**Private Blob** — Encrypted serialization of the Secret's sensitive
material. Decrypted only inside the agent process, never returned
verbatim through the MCP transport (only via explicit `vault.reveal`
with operator confirmation).

**Schema** — Per-category CUE definition declaring which fields are
public and which are private, with type constraints and validation
rules.

## Access Mediation

**Proxy Tool** — MCP tool that operates a Secret without exposing
plaintext. Examples: `vault.ssh.exec`, `vault.http.request`,
`vault.spawn`, `vault.write_tempfile`. Implementation lives inside
the agent; only the result (filtered stdout, response body, exit
code) crosses the MCP transport.

**Use Token** — Short-lived opaque token (default TTL 60 seconds)
issued by `vault.use(handle, purpose)`. Permits a single consumer
process to dereference the Secret via the Companion Socket. Never
returned to the LLM transport for cross-process use.

**Proxy Executor** — Domain service that resolves a Handle to its
private material inside the agent and invokes the appropriate
external operation (SSH session, HTTP request, process spawn,
tempfile write).

**Tempfile** — Filesystem path materializing a Secret on disk with
mode `0600`. Cleaned up on session close, idle timeout, or explicit
revoke. Tracked by `session_id` for orphan reaping at agent boot.

**FIFO** — Named pipe variant of Tempfile that delivers the Secret
exactly once on the first read, then is removed. Suitable for tools
that consume credentials by path but never re-read.

**Companion Device** — Pre-paired secondary device that authenticates
Reveal operations via Ed25519 signature on OOB Confirmation challenges.
Enrolled via `merkle device pair`. The Ed25519 identity key is persisted
in the OS keychain under service identifier `merkle-companion-<device-id>`.
Multiple devices may be enrolled; each has an independent entry. See
ADR-0011 Amendment.

**Companion Socket** — Unix domain socket (or Windows named pipe)
exposed by the agent to local processes. Resolves Use Tokens to
plaintext. Authenticates callers by PID and process name against
`allowed_consumers`.

**Request Nonce** — 32-byte random value generated by `OsRng` and
embedded in every OOB Confirmation challenge (`OobChallenge.nonce`,
encoded as URL-safe base64). The Companion Device MUST include the
nonce in the signed message before returning a challenge response.
Prevents replay attacks between challenge issuance and reveal execution.
See ADR-0011 Amendment.

**Reveal** — Explicit return of a Secret's plaintext to the MCP
transport. Always requires Operator Confirmation. Default-denied
for `sensitivity = high` unless the Namespace Policy grants it.

## Audit and Compliance

**Audit Entry** — Append-only record of every Secret operation:
category_create, cross_env_warning, delete, disaster_recovery,
get, namespace_create, put, restore, reveal, rotate, unseal, use,
use_token_resolved. Includes timestamp, session id, namespace id,
op, handle, purpose, outcome, caller pid, and chain hashes.

**Audit Outcome** — Closed enum recorded on every Audit Entry:
`allow | deny | error`. The coarse outcome is always present.
Fine-grained rejection codes are carried in the separate
`denial_reason` field: `rejected_policy`, `rejected_no_confirmation`,
`rejected_oob_timeout`, `rejected_rate_limit`. This two-field model
keeps outcome queries simple while preserving forensic detail.

**Hash Chain** — Sequence of Audit Entries where each entry stores
a `prev_hash` (the `current_hash` of the immediately preceding
entry) and a `current_hash` computed as
`BLAKE3(canonical_content || prev_hash)`. Tampering with any entry
invalidates all following entries. The genesis entry uses the
64-hex-zero sentinel `blake3:0000...0000` for `prev_hash`. See ADR-0009.

**Chain Verifier** — Domain service that validates the Hash Chain
end-to-end. Detects entry mutation, reordering, or removal.

**HMAC Signature** — Detached integrity tag computed over the
Audit Entry payload using a per-vault HMAC key. Used by the remote
sync worker to authenticate events to an external receiver.

**Pinned Head** — The audit chain head hash written synchronously to
`audit_head.json` on every entry append. Compared against the tail
entry's `current_hash` during chain verification to detect truncation
attacks (an attacker who removes trailing entries would cause the stored
head to diverge from the last hash actually present in the log). See
ADR-0009.

**Append-Only** — Storage discipline: entries can only be added.
Updates and deletes are forbidden at the data layer (enforced by
SQLite triggers and write-only file handles).

## Backup and Recovery

**Backup** — Encrypted single-file export of the entire vault
state. Format: `age`-encrypted with two recipients (Master public
key + Recovery Public Key). Filename:
`merkle-bk-<utc-iso8601>.merkle.age`.

**Restore** — Procedure that reads a Backup, validates integrity,
previews changes, and applies them. Modes: `overwrite`, `merge`,
`newest-wins`.

**Disaster Recovery** — Restore path when the Master Key is
unavailable. Operator supplies the Recovery Key, agent re-wraps
the Vault Root Key with a freshly generated Master Key, and stores
the new Master Key in the keychain.

**Anacron Trigger** — Boot-time check that compares the current
time against the last successful Backup timestamp and the
configured `max_interval`. Triggers a Backup if the interval has
elapsed and there are pending changes.

**Change-Triggered Backup** — Backup initiated when a configurable
count of mutations has accumulated since the last successful
Backup.

**Idle-Triggered Backup** — Backup initiated after a configurable
idle period with pending changes.

**Sleep Hook** — Platform-specific notification of imminent system
sleep (macOS IOKit, Linux logind, Windows PowerBroadcast). Best-effort
trigger of a Backup before sleep.

**Vault HMAC Key** — Key distinct from the Master Key, Vault Root Key,
and all Namespace DEKs. Used to compute the HMAC tag appended to Backup
files and to sign Audit Entry payloads for remote sync. Derived from the
Vault Root Key via BLAKE3 in keyed-derivation mode:
`vault_hmac_key = BLAKE3(key=vault_root_key, data="merkle:vault-hmac-key:v1")`.
Derived at unseal time and held in the agent's `mlocked` key store;
never written to disk in plaintext. See ADR-0006 Amendment 1.

## Policy and Permissions

**Namespace Policy** — Set of rules applied to all Secrets in a
Namespace: default sensitivity, rate limits, OOB threshold,
allowed consumers, tag validation, cross-namespace access,
retention policy.

**Rate Limit** — Maximum number of operations of a given class per
unit time. Default classes: `plaintext_reads`, `use_token_resolves`,
`reveals`.

**Reveal Policy** — Configuration controlling when and how a
Reveal can be authorized: whether allowed at all, the sensitivity
threshold above which OOB Confirmation is required, and whether
only slash commands can pass the confirmation flag.

**Cross-Namespace Access** — Whether a session bound to namespace
A may read Secrets from namespace B. Default: forbidden. Positive
allowlist of imports permitted by configuration.

**Allowed Consumers** — Glob list of process names (resolved from
peer PID on the Companion Socket) authorized to dereference Use
Tokens for this Namespace.

**Operator Confirmation** — Verifiable signal that the human
operator authorized a sensitive action. Sources: slash command in
the client (carries a verified flag), OOB Confirmation, signed
config flag for automation.

**OOB Confirmation** — Out-of-band acknowledgment delivered through
a channel distinct from the MCP transport: desktop notification,
terminal prompt in the agent's TTY, or local browser confirmation
on a localhost-only port.

**Operator Attestation** — Ed25519-signed JWT issued by the vault
operator to declare that a non-Claude Code MCP client's turn-boundary
enforcement is trusted. Presented as a `signed_config_flag` in reveal
requests; treated as equivalent to `slash_command=true` if the
signature, `exp`, and `vault_id` fields are valid. Does not satisfy the
OOB Confirmation requirement for `sensitivity=high`; OOB remains
mandatory. See ADR-0011 Amendment.

**Security Profile** — Bundle of policy defaults applied at init.
Built-in profiles: `relaxed`, `balanced`, `paranoid`. Operator
selects one; per-namespace policies may override.

**Signed Config Flag** — Operator Attestation JWT presented by a
non-Claude Code MCP client as proof of slash-command-equivalent intent.
Stored in the `signed_config_flag` field of the reveal request. The
Vault Agent verifies the JWT signature against the operator attestation
public key held in the sealed state. Acts as the `slash_command=true`
fallback for clients that do not support native slash commands. See
ADR-0011 Amendment.

**Value Format** — Encoding declaration for the `value` field in a
`PutSecretRequest`. Two values: `utf8` (the value string is raw UTF-8 text;
stored as-is after AEAD encryption) and `base64` (the value string is
standard-base64-encoded binary or text bytes; decoded before AEAD encryption
and storage). The `value_format` field is required on every put and rotate
request. Binary payloads MUST use `value_format=base64`. Decision basis:
ADR-0021 Amendment 2026-05-23 — structured JSON envelope over raw binary
stream or base64-only, for explicit type signaling and schema validation
compatibility.

**Unseal Guard** — RAII Rust struct that transitions the vault state machine
to `Unsealing` on construction and reverts to `Sealed` via `Drop` if
`commit()` was not called before the guard is dropped. Implements the error
rollback contract defined in ADR-0015 Amendment 3. Ensures that any
mid-protocol failure leaves the vault in `Sealed` state, allowing the caller
to retry immediately without a process restart.

## MCP Adapter

**MCP Tool** — Function exposed over the MCP stdio transport.
Implemented by the MCP Adapter as a thin call into the application
service of the agent.

**MCP Session** — Connection between a client (Claude Code window)
and the MCP server process. Identified by a `session_id` issued at
handshake. Used for orphan tempfile reaping and idle backup
triggers.

## Storage Adapter

**SQLite** — Embedded relational database used as the persistence
backend. Configured in WAL mode for concurrent reads. Located at
the path declared in `config.toml`.

**Per-Blob Encryption** — Encryption applied to specific columns
(notably `private_blob`) rather than to the entire database file.
Algorithm: XChaCha20-Poly1305 (AEAD) with per-secret nonces.

**FTS5 Index** — SQLite full-text search virtual table built over
public metadata fields. Tokenizer: `porter unicode61
remove_diacritics 2`. Indexed columns chosen per category; private
material is never indexed.

## Keychain Adapter

**OS Keychain** — Operating-system-managed credential store
abstracted by the Rust `keyring` crate. Concrete backends: macOS
Security framework (Keychain), Linux Secret Service or KWallet,
Windows Credential Manager.

**Service Identifier** — Logical name used to look up an entry in
the OS Keychain. For Merkle: `dev.fapp.merkle` with accounts
`master-v1`, `master-v2`, etc., as the Master Key is rotated.

## Crypto Adapter

**BLAKE3** — Cryptographic hash function (BLAKE3 family) used for
content addressing and Audit Entry hash chain computation. Each
`current_hash` field in an Audit Entry is computed as
`BLAKE3(canonical_content || prev_hash)`. Chosen for its speed
(3-5x faster than SHA-256 on modern hardware), pure-Rust
availability, and XOF mode for per-vault key derivation. See ADR-0009.

**XChaCha20-Poly1305** — AEAD cipher (RFC 8439, extended-nonce
variant) used for per-blob encryption. 24-byte nonces eliminate
collision risk under heavy use.

**Argon2id** — Password hashing function (RFC 9106), winner of the
Password Hashing Competition. Used to derive the Master Key from a
user passphrase in the keychain-absent fallback path.

**age** — File-encryption format (filippo.io/age). Used for
Backups and for the Recovery Key. Two recipients on every backup:
Master public key and Recovery Public Key.

**Minimum Hardness Floor** — Compile-time constants enforced by the
agent at unseal time to prevent KDF downgrade attacks. Values: Argon2id
`m_cost` ≥ 65536 KiB (64 MiB), `t_cost` ≥ 3 iterations, `p_cost` ≥ 1
lane. If any stored parameter falls below its floor the unseal is
rejected with a fatal `UNSEAL_ERROR`. The floor cannot be overridden by
`config.toml` or any runtime flag. See ADR-0005 Amendment.

**Nonce** — Number used once. Per-blob random 24-byte value
prefixed to the ciphertext.

## External Service Adapter

**SSH Bridge** — Component that performs SSH connections inside
the agent, injecting key material and passphrases without exposing
them to the LLM transport. Backed by `russh` or by an isolated
ssh-mcp subprocess.

**HTTP Bridge** — Component that performs HTTP requests inside the
agent, injecting auth headers, cookies, or body fields without
exposing them.

**Process Spawn** — Operation that starts an arbitrary child
process with selected environment variables drawn from a Secret.
Captures filtered stdout and stderr.

## LLM-as-Composer

**Composition** — LLM-driven chain of two or more Proxy Tool
invocations that together accomplish a task using multiple
Secrets. Not modeled persistently by the vault; reconstructed by
the LLM in every session.

**Tag-Based Cohesion** — Informal grouping mechanism: Secrets that
share semantic tags (`env:prod`, `project:acme`, `role:bastion`)
are likely to be composed together. The LLM uses tags to discover
related Secrets without foreign keys.

**Cross-Env Warning** — Audit-level signal emitted when Secrets
tagged with different `env:*` values are accessed in the same
session. Not a block; a forensic marker for later review.

## Common Operational Terms

**Vault Agent** — Long-running background daemon hosting the
domain core. One per user. Communicates with MCP Adapter instances
through the Companion Socket. Owns lifecycle of keys, audit log,
backup scheduler, and tempfile reaper.

**MCP Server** — Short-lived process spawned per client window,
acting as the MCP Adapter. Translates MCP tool calls into JSON-RPC
to the Vault Agent.

**Slash Command** — Client-side trigger (Claude Code) that carries
a verifiable Operator Confirmation flag. Used for sensitive
operations: `/merkle-reveal`, `/merkle-rollback`, `/merkle-show`.

**Doctor** — Diagnostic command that reports agent status, key
availability, audit chain integrity, backup freshness, expiring
secrets, and disk space.
