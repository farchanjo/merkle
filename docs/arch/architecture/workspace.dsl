# DDD role taxonomy (canonical per docs/arch/glossary.md):
#   AggregateRoot, Entity, ValueObject, DomainService, ReadModel,
#   DrivingPort, DrivingAdapter, DrivenAdapter.
# Every component MUST carry `properties { "ddd-role" "<role>" }`.

workspace "Merkle Architecture Model" "Local-first MCP vault that mediates between LLM context and secret storage. Issues opaque handles by default; LLM operates secrets via proxy tools without seeing plaintext. Audit log uses a Merkle-style hash chain inspired by Ralph Merkle's tree construction." {

    !identifiers hierarchical

    model {

        # ─── People ───────────────────────────────────────────────────────────

        operator = person "Operator" "The human who owns the vault, performs initial setup, authorizes sensitive operations via slash commands and OOB Confirmation, and holds the Recovery Key."

        # ─── External software systems ────────────────────────────────────────

        llmClient = softwareSystem "LLM Client" "MCP-aware host that submits tool calls to the Merkle MCP Server. Examples: Claude Code, Cursor, any MCP-capable IDE or agent runtime. Never receives plaintext of protected Secrets." {
            tags "External", "Layer:Infrastructure"
        }

        osKeychain = softwareSystem "OS Keychain" "Operating-system-managed credential store abstracted by the Rust keyring crate. Concrete backends: macOS Security framework (Keychain), Linux Secret Service or KWallet, Windows Credential Manager. Stores the Master Key under service identifier dev.fapp.merkle." {
            tags "External", "Layer:Infrastructure"
        }

        sshTarget = softwareSystem "SSH Target" "Remote host that accepts SSH connections proxied by the SSH Bridge inside the Vault Agent. Credentials are never exposed to the LLM transport." {
            tags "External", "Layer:Infrastructure"
        }

        httpService = softwareSystem "HTTP Service" "Remote HTTP API that accepts requests proxied by the HTTP Bridge inside the Vault Agent. Auth headers, cookies, and body secrets are injected inside the agent." {
            tags "External", "Layer:Infrastructure"
        }

        cloudProviderApi = softwareSystem "Cloud Provider API" "External cloud control-plane API (AWS, GCP, Azure, etc.) accessed via cloud-category Secrets through the External Service Adapter." {
            tags "External", "Layer:Infrastructure"
        }

        processSpawnTarget = softwareSystem "Process Spawn Target" "Arbitrary child process launched with environment variables drawn from Secrets via vault.spawn. Captures filtered stdout and stderr." {
            tags "External", "Layer:Infrastructure"
        }

        driveSyncTarget = softwareSystem "Drive Sync Target" "Cloud or local sync destination for vault Backups: Google Drive, iCloud, Dropbox, or Syncthing. Receives age-encrypted .merkle.age files." {
            tags "External", "Layer:Infrastructure"
        }

        remoteAuditWebhook = softwareSystem "Remote Audit Webhook" "Optional external receiver for HMAC-signed Audit Entry streams. Receives events authenticated with the per-vault HMAC key when remote sync is enabled." {
            tags "External", "Layer:Infrastructure"
        }

        companionDevice = softwareSystem "Companion Device" "Pre-paired secondary device that authenticates OOB Confirmation challenges via Ed25519 signature. Enrolled via merkle device pair. The Ed25519 identity key is persisted in the OS Keychain under service identifier merkle-companion-<device-id>. Multiple devices may be enrolled. Operates off-box or as a separate process. See ADR-0011 Amendment." {
            tags "External", "Layer:Infrastructure"
        }

        # ─── Merkle Vault — system in focus ───────────────────────────────────

        merkleVault = softwareSystem "Merkle Vault" "Local-first secret vault that mediates between LLM context and credential storage. Issues opaque Handles by default, enforces the Reveal policy, maintains an append-only Hash Chain audit log, and delegates secret operations through Proxy Tools." {

            # ── Vault Agent (daemon) ─────────────────────────────────────────

            vaultAgent = container "Vault Agent" "Long-running background daemon. One per user. Hosts the domain core across all six bounded contexts. Communicates with MCP Server instances through the Companion Socket. Owns lifecycle of keys, audit log, backup scheduler, and tempfile reaper." "Rust 2024 edition (1.85+), Tokio async runtime" {

                # ── Driving-port adapters ────────────────────────────────────

                companionSocketPort = component "Companion Socket Port" "Driving-port adapter. The SINGLE inbound driving port for the Vault Agent domain. Exposes a Unix domain socket (or Windows named pipe) that resolves Use Tokens to plaintext. Authenticates callers by PID and process name against the Allowed Consumers list. MCP Adapter and CLI Adapter are external clients that consume this port; they do not bypass it." "Rust / tokio::net::UnixListener" {
                    tags "Adapter", "Layer:Adapter"
                    properties {
                        "ddd-role" "DrivingPort"
                    }
                }

                mcpPortAdapter = component "MCP Port Adapter" "Adapter component bridging MCP Server external Container calls to the Companion Socket Port driving port. Translates MCP tool calls received over stdio into JSON-RPC messages and forwards them to the Companion Socket Port inside the Vault Agent. External to the domain core but wired through companionSocketPort as its sole entry." "Rust / rmcp SDK, JSON-RPC over Unix socket" {
                    tags "Adapter", "Layer:Adapter"
                    properties {
                        "ddd-role" "DrivingAdapter"
                    }
                }

                cliPortAdapter = component "CLI Port Adapter" "Adapter component bridging Merkle CLI external Container calls to the Companion Socket Port driving port. Translates CLI subcommands into JSON-RPC messages and forwards them to the Companion Socket Port inside the Vault Agent. External to the domain core but wired through companionSocketPort as its sole entry." "Rust / clap, JSON-RPC over Unix socket" {
                    tags "Adapter", "Layer:Adapter"
                    properties {
                        "ddd-role" "DrivingAdapter"
                    }
                }

                # ── Identity and Sealing bounded context ─────────────────────

                identityAndSealingDomain = component "Identity And Sealing Domain" "Bounded context owning the unseal protocol and key hierarchy. Manages Master Key, Vault Root Key, Namespace DEK, and the Recovery Key lifecycle. Transitions the agent between Sealed State and Unsealed State. Implements the Unseal Protocol: fetch Master Key from OS Keychain, decrypt Vault Root Key, hold in mlocked protected memory." "Rust / Domain core (AggregateRoot: VaultIdentity, DomainService: UnsealService)" {
                    tags "Domain", "Layer:Domain"
                    properties {
                        "ddd-role" "AggregateRoot"
                    }
                }

                # ── Secret Storage bounded context ────────────────────────────

                secretStorageDomain = component "Secret Storage Domain" "Bounded context owning the Secret aggregate lifecycle: create, read, rotate, delete, and version management. Manages Namespaces (UUIDv7, Namespace binding by cwd hash or .merklerc override), Categories, Sensitivity levels, Tags, Public Metadata, Private Blob encryption, and the FTS5 Index over public metadata. Full-text search is ranked by weighted BM25 (ADR-0027 weight vector: name=10.0, tags=5.0, description=3.0, category=2.0, namespace_label=1.0); results expose score, bm25_rank, and highlight snippets. Enforces retain_count from the Namespace Policy." "Rust / Domain core (AggregateRoot: Secret, Entity: SecretVersion, ValueObject: Handle, DomainService: NamespaceBindingService)" {
                    tags "Domain", "Layer:Domain"
                    properties {
                        "ddd-role" "AggregateRoot"
                    }
                }

                # ── Access Mediation bounded context ──────────────────────────

                accessMediationDomain = component "Access Mediation Domain" "Bounded context owning Proxy Tool execution, Use Token issuance (TTL 60s), and the Reveal workflow. Implements vault.ssh.*, vault.http.*, vault.spawn, and vault.write_tempfile. Resolves Handles to Private Blobs inside the agent, executes the external operation, and returns only filtered results. Manages Tempfile and FIFO lifecycle. Requires Operator Confirmation and OOB Confirmation for high-sensitivity Reveals." "Rust / Domain core (DomainService: ProxyExecutor, DomainService: UseTokenRegistry, DomainService: RevealService)" {
                    tags "Domain", "Layer:Domain"
                    properties {
                        "ddd-role" "DomainService"
                    }
                }

                # ── Audit and Compliance bounded context ──────────────────────
                # Option 1 applied: split into three discrete components per W4.C finding A.

                auditWriter = component "Audit Writer" "DomainService within the Audit and Compliance bounded context. Emits Audit Entries for every Secret operation: unseal, put, get, use, reveal, rotate, delete, restore. Computes BLAKE3 content hash, chains to previous entry hash (Merkle-style Hash Chain), and optionally appends HMAC Signature for remote sync. Emits Cross-Env Warning when Secrets tagged with different env:* values are accessed in the same session." "Rust / Domain core (DomainService: AuditWriter)" {
                    tags "Domain", "Layer:Domain" "DomainService"
                    properties {
                        "ddd-role" "DomainService"
                    }
                }

                chainVerifier = component "Chain Verifier" "DomainService within the Audit and Compliance bounded context. Recomputes the Hash Chain end-to-end: reads all Audit Entries in insertion order, recomputes BLAKE3 content hashes, and validates each previous_hash link. Reports any mutation, reordering, gap, or removal as a ChainIntegrityViolation. Invoked by the Doctor command and on Restore. See ADR-0015." "Rust / Domain core (DomainService: ChainVerifier)" {
                    tags "Domain", "Layer:Domain" "DomainService"
                    properties {
                        "ddd-role" "DomainService"
                    }
                }

                auditQueryModel = component "Audit Query Model" "ReadModel within the Audit and Compliance bounded context. Provides read-only projections over the Audit Entry ledger: list by session, filter by op / namespace / time range, fetch single entry by id, and stream entries for remote sync webhook delivery. Never mutates the ledger. Public surface consumed by CLI Adapter (merkle doctor) and the Remote Audit Webhook sync path." "Rust / Domain core (ReadModel: AuditQueryModel)" {
                    tags "Domain", "Layer:Domain"
                    properties {
                        "ddd-role" "ReadModel"
                    }
                }

                # ── Backup and Recovery bounded context ───────────────────────

                backupRecoveryDomain = component "Backup And Recovery Domain" "Bounded context owning Backup creation, scheduling, and Restore. Encrypts backups with age using two recipients (Master public key + Recovery Public Key). Filename: merkle-bk-<utc-iso8601>.merkle.age. Triggers: Anacron Trigger (1h/24h), Change-Triggered Backup (10 mutations), Idle-Triggered Backup (10 min idle), Sleep Hook, and on-shutdown. Implements Restore modes: overwrite, merge, newest-wins. Implements Disaster Recovery when Master Key is unavailable." "Rust / Domain core (DomainService: BackupScheduler, DomainService: RestoreService, AggregateRoot: BackupManifest)" {
                    tags "Domain", "Layer:Domain"
                    properties {
                        "ddd-role" "AggregateRoot"
                    }
                }

                # ── Policy and Permissions bounded context ────────────────────

                policyPermissionsDomain = component "Policy And Permissions Domain" "Bounded context owning Namespace Policy evaluation, Rate Limit enforcement, Reveal Policy decisions, Cross-Namespace Access control, Allowed Consumers validation, and Security Profile application. Governs all operations in Secret Storage and Access Mediation. Built-in Security Profiles: relaxed, balanced, paranoid." "Rust / Domain core (AggregateRoot: NamespacePolicy, ValueObject: RateLimit, ValueObject: RevealPolicy, DomainService: PolicyEvaluator)" {
                    tags "Domain", "Layer:Domain"
                    properties {
                        "ddd-role" "AggregateRoot"
                    }
                }

                # ── Driven-port adapters ─────────────────────────────────────

                storageAdapter = component "Storage Adapter" "Driven-port adapter. Wraps SQLite in WAL mode. Implements per-blob XChaCha20-Poly1305 AEAD encryption on the private_blob column with per-secret 24-byte Nonces. Maintains FTS5 virtual table secrets_fts over public metadata columns (name, tags, description, category, namespace_label) with weighted BM25 ranking (ADR-0027); INSERT, UPDATE, and DELETE triggers keep the index in strong consistency with the secrets table. Ranked queries use bm25(secrets_fts, 10.0, 5.0, 3.0, 2.0, 1.0) and expose score, bm25_rank, and highlight() / snippet() results. Enforces append-only discipline on audit tables via SQLite triggers. Stores Vault Root Key wrapped twice: by Master Key and by Recovery Public Key." "Rust / rusqlite, SQLite WAL, FTS5 with porter unicode61 tokenizer" {
                    tags "Adapter", "Layer:Adapter"
                    properties {
                        "ddd-role" "DrivenAdapter"
                    }
                }

                keychainAdapter = component "Keychain Adapter" "Driven-port adapter. Abstracts the OS Keychain via the Rust keyring crate. Stores and retrieves the Master Key using Service Identifier dev.fapp.merkle. Falls back to Argon2id key derivation when no OS Keychain is available." "Rust / keyring crate, macOS Security framework / Linux Secret Service / Windows Credential Manager" {
                    tags "Adapter", "Layer:Adapter"
                    properties {
                        "ddd-role" "DrivenAdapter"
                    }
                }

                cryptoAdapter = component "Crypto Adapter" "Driven-port adapter. Implements XChaCha20-Poly1305 AEAD (RFC 8439 extended-nonce variant) for per-blob encryption. Implements Argon2id (RFC 9106) KDF for passphrase-derived keys. Implements age encryption for Backups and Recovery Key. Implements BLAKE3 for Hash Chain content hashing. Manages Nonce generation." "Rust / chacha20poly1305, argon2, age, blake3 crates" {
                    tags "Adapter", "Layer:Adapter"
                    properties {
                        "ddd-role" "DrivenAdapter"
                    }
                }

                oobNotifierAdapter = component "OOB Notifier Adapter" "Driven-port adapter. Delivers OOB Confirmation requests through channels distinct from the MCP transport: desktop notifications (macOS/Linux/Windows native), terminal prompt on the agent TTY, or localhost-only browser confirmation page. Subscribed to by enrolled Companion Devices via the OOB endpoint exposed on the Vault Agent host." "Rust / notify-rust, platform notification APIs" {
                    tags "Adapter", "Layer:Adapter"
                    properties {
                        "ddd-role" "DrivenAdapter"
                    }
                }

                externalServiceAdapter = component "External Service Adapter" "Driven-port adapter. Contains SSH Bridge (russh crate or isolated ssh-mcp subprocess), HTTP Bridge (reqwest), Process Spawn, and Cloud Provider API client. All inject credential material inside the agent and return only filtered results." "Rust / russh, reqwest, tokio::process" {
                    tags "Adapter", "Layer:Adapter"
                    properties {
                        "ddd-role" "DrivenAdapter"
                    }
                }

                backupScheduler = component "Backup Scheduler" "DomainService: BackupScheduler. Implements the anacron-style scheduling loop (1h/24h intervals), change counter, idle timer, Sleep Hook listener, and on-shutdown trigger. Delegates backup creation to Backup And Recovery Domain. Reads max_interval, change_threshold, and idle_timeout from Namespace Policy." "Rust / Tokio timers, platform sleep hooks (macOS IOKit, Linux logind, Windows PowerBroadcast)" {
                    tags "DomainService", "Layer:Domain"
                    properties {
                        "ddd-role" "DomainService"
                    }
                }

                auditChainVerifier = component "Audit Chain Verifier" "DomainService: AuditChainVerifier. Implements Chain Verifier: reads all Audit Entries in sequence, recomputes the Hash Chain end-to-end, and reports any mutation, reordering, or removal. Invoked by the Doctor command and on Restore." "Rust / Domain service wrapper" {
                    tags "DomainService", "Layer:Domain"
                    properties {
                        "ddd-role" "DomainService"
                    }
                }
            }

            # ── MCP Server ───────────────────────────────────────────────────

            mcpServer = container "MCP Server" "Short-lived process spawned per client window. Acts as the MCP Adapter: translates MCP tool calls received over stdio into JSON-RPC messages forwarded to the Vault Agent over the Companion Socket. Exposes vault.list, vault.describe, vault.use, vault.reveal, vault.put, vault.rotate, vault.delete, vault.bind, and all Proxy Tool entrypoints." "Rust 2024 edition, rmcp Rust MCP SDK" {
                tags "External", "Layer:Infrastructure"
            }

            # ── CLI ───────────────────────────────────────────────────────────

            merkleCli = container "Merkle CLI" "Command-line interface for vault administration. Implements: merkle init, merkle unseal, merkle seal, merkle put, merkle get, merkle rotate, merkle delete, merkle list, merkle backup, merkle restore, merkle doctor, and merkle verify-chain. Communicates with the Vault Agent over the Companion Socket." "Rust 2024 edition, clap" {
                tags "External", "Layer:Infrastructure"
            }

            # ── Data stores ───────────────────────────────────────────────────

            sqliteDatabase = container "SQLite Database" "File-backed embedded relational database. WAL mode for concurrent reads. Stores Secrets with per-blob XChaCha20-Poly1305 encryption on private_blob columns. Stores Namespace records, Secret Versions, Use Token registry, wrapped Vault Root Key (dual-wrapped: Master Key + Recovery Public Key), and Namespace Policies. FTS5 Index on public metadata. Audit Entry table is append-only (enforced by SQLite triggers)." "SQLite WAL, per-blob XChaCha20-Poly1305 AEAD" {
                tags "Database", "Layer:Domain"
            }

            auditLogFile = container "Audit Log File" "Append-only JSONL file on disk. Primary persistence for Audit Entries. Each entry stores timestamp, session id, namespace id, op, Handle, purpose, outcome, caller pid, content hash, and previous hash (Hash Chain). Write-only file handle enforced at the OS level." "JSONL, append-only, BLAKE3 Hash Chain"

            configStore = container "Config Store" "Configuration persistence layer. config.toml holds global settings: vault path, Security Profile, backup targets, HMAC sync endpoint, Companion Socket path, and Recovery Public Key (in plaintext). .merklerc files in project roots override the active Namespace binding for that directory tree." "TOML files, .merklerc convention"

            backupStore = container "Backup Store" "Filesystem path holding encrypted Backup files. Default: ~/.local/share/llm-vault/backups/. Each Backup is an age-encrypted archive with two recipients (Master public key + Recovery Public Key). Filename pattern: merkle-bk-<utc-iso8601>.merkle.age. May be mirrored to Drive Sync Target." "Filesystem, age-encrypted .merkle.age files"
        }

        # ─── Relationships: Operator ───────────────────────────────────────────

        operator -> merkleVault.merkleCli "Administers vault via" "CLI stdio (clap)"
        operator -> merkleVault.mcpServer "Issues slash commands (Operator Confirmation) via" "MCP stdio"
        operator -> llmClient "Uses LLM client to interact with vault through" "MCP tool calls"

        # ─── Relationships: LLM Client ────────────────────────────────────────

        llmClient -> merkleVault.mcpServer "Submits MCP tool calls to" "MCP stdio (JSON-RPC over stdio)"

        # ─── Relationships: MCP Server to Vault Agent ─────────────────────────

        merkleVault.mcpServer -> merkleVault.vaultAgent.companionSocketPort "Forwards tool calls to" "JSON-RPC over Unix socket / Windows named pipe"
        merkleVault.mcpServer -> merkleVault.vaultAgent.mcpPortAdapter "Routes MCP stdio calls through" "JSON-RPC over Unix socket / Windows named pipe"
        merkleVault.vaultAgent.mcpPortAdapter -> merkleVault.vaultAgent.companionSocketPort "Bridges MCP tool calls to" "In-process delegation to driving port"

        # ─── Relationships: CLI to Vault Agent ───────────────────────────────

        merkleVault.merkleCli -> merkleVault.vaultAgent.companionSocketPort "Sends admin commands to" "JSON-RPC over Unix socket / Windows named pipe"
        merkleVault.merkleCli -> merkleVault.vaultAgent.cliPortAdapter "Routes CLI subcommands through" "JSON-RPC over Unix socket / Windows named pipe"
        merkleVault.vaultAgent.cliPortAdapter -> merkleVault.vaultAgent.companionSocketPort "Bridges CLI commands to" "In-process delegation to driving port"

        # ─── Relationships: Companion Socket Port to domain components ─────────

        merkleVault.vaultAgent.companionSocketPort -> merkleVault.vaultAgent.identityAndSealingDomain "Delegates unseal and seal requests to" "In-process Rust trait call"
        merkleVault.vaultAgent.companionSocketPort -> merkleVault.vaultAgent.secretStorageDomain "Delegates Secret CRUD requests to" "In-process Rust trait call"
        merkleVault.vaultAgent.companionSocketPort -> merkleVault.vaultAgent.accessMediationDomain "Delegates Proxy Tool calls, Use Token requests, and Reveal requests to" "In-process Rust trait call"
        merkleVault.vaultAgent.companionSocketPort -> merkleVault.vaultAgent.policyPermissionsDomain "Delegates policy evaluation queries to" "In-process Rust trait call"

        # ─── Relationships: domain-to-domain (cross-context) ──────────────────
        # Relationship type tags follow context-map.md edge table.
        # C/S = Customer-Supplier; CF = Conformist; SK = Shared Kernel.
        # Format: tags "type,direction", "Layer:Domain" where upstream/downstream is from context-map.md.

        merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.secretStorageDomain "Provides unwrapped Namespace DEKs to" "In-process Rust trait call" {
            tags "C/S,upstream", "Layer:Domain"
        }
        merkleVault.vaultAgent.secretStorageDomain -> merkleVault.vaultAgent.accessMediationDomain "Provides resolved Private Blob to" "In-process Rust trait call" {
            tags "C/S,upstream", "Layer:Domain"
        }
        merkleVault.vaultAgent.accessMediationDomain -> merkleVault.vaultAgent.auditWriter "Emits Audit Entry on every operation to" "In-process Rust trait call" {
            tags "C/S,downstream", "Layer:Domain"
        }
        merkleVault.vaultAgent.secretStorageDomain -> merkleVault.vaultAgent.backupRecoveryDomain "Provides vault state snapshot to" "In-process Rust trait call" {
            tags "C/S,upstream", "Layer:Domain"
        }
        merkleVault.vaultAgent.policyPermissionsDomain -> merkleVault.vaultAgent.accessMediationDomain "Governs Proxy Tool execution and Reveal decisions via" "In-process Rust trait call" {
            tags "C/S,upstream", "Layer:Domain"
        }
        merkleVault.vaultAgent.policyPermissionsDomain -> merkleVault.vaultAgent.secretStorageDomain "Governs Namespace Policy and retention via" "In-process Rust trait call" {
            tags "C/S,upstream", "Layer:Domain"
        }
        merkleVault.vaultAgent.auditQueryModel -> merkleVault.vaultAgent.accessMediationDomain "References mediated access session context for cross-env warning projection (read-only; NOTE: context-map.md edge 7 — actual data flow is AccessMediation to AuditWriter; this arrow is a read-only read-model query)" "In-process Rust trait call" {
            tags "CF,chain-validation-readonly", "Layer:Domain"
        }
        merkleVault.vaultAgent.backupRecoveryDomain -> merkleVault.vaultAgent.backupScheduler "Receives trigger signals from" "In-process Rust trait call"
        merkleVault.vaultAgent.backupScheduler -> merkleVault.vaultAgent.policyPermissionsDomain "Reads max_interval, change_threshold, and idle_timeout from Namespace Policy via" "In-process Rust trait call"
        merkleVault.vaultAgent.auditWriter -> merkleVault.vaultAgent.chainVerifier "Delegates chain integrity validation to (on restore and doctor command)" "In-process Rust trait call"

        # ─── Relationships: domain to driven-port adapters ────────────────────

        merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.keychainAdapter "Loads and stores Master Key via" "Rust keyring crate trait"
        merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.cryptoAdapter "Derives Vault Root Key and Namespace DEKs via" "Argon2id / XChaCha20-Poly1305"
        merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.storageAdapter "Reads and atomically replaces dual-wrapped Vault Root Key copies via" "Rust rusqlite trait"
        merkleVault.vaultAgent.secretStorageDomain -> merkleVault.vaultAgent.storageAdapter "Persists and retrieves Secrets and Namespaces via" "Rust rusqlite trait"
        merkleVault.vaultAgent.secretStorageDomain -> merkleVault.vaultAgent.cryptoAdapter "Encrypts and decrypts Private Blob via" "XChaCha20-Poly1305 AEAD"
        merkleVault.vaultAgent.accessMediationDomain -> merkleVault.vaultAgent.externalServiceAdapter "Delegates SSH, HTTP, spawn, and tempfile operations to" "Rust async trait call"
        merkleVault.vaultAgent.accessMediationDomain -> merkleVault.vaultAgent.oobNotifierAdapter "Requests OOB Confirmation from operator via" "Platform notification API"
        merkleVault.vaultAgent.auditWriter -> merkleVault.vaultAgent.storageAdapter "Mirrors Audit Entries to SQLite audit table via" "Rust rusqlite trait"
        merkleVault.vaultAgent.auditWriter -> merkleVault.vaultAgent.cryptoAdapter "Computes BLAKE3 Hash Chain hashes and HMAC Signatures via" "blake3 / HMAC-BLAKE3"
        merkleVault.vaultAgent.chainVerifier -> merkleVault.vaultAgent.storageAdapter "Reads all Audit Entries in sequence for chain recomputation via" "Rust rusqlite trait"
        merkleVault.vaultAgent.chainVerifier -> merkleVault.vaultAgent.cryptoAdapter "Recomputes BLAKE3 content hashes for chain validation via" "blake3"
        merkleVault.vaultAgent.auditQueryModel -> merkleVault.vaultAgent.storageAdapter "Reads Audit Entry projections (filter, list, stream) via" "Rust rusqlite trait"
        merkleVault.vaultAgent.backupRecoveryDomain -> merkleVault.vaultAgent.cryptoAdapter "Encrypts Backups with age (two recipients) via" "age file-encryption format"
        merkleVault.vaultAgent.backupRecoveryDomain -> merkleVault.vaultAgent.storageAdapter "Reads vault state for Backup export via" "Rust rusqlite trait"

        # ─── Relationships: driven adapters to external systems / containers ───

        merkleVault.vaultAgent.keychainAdapter -> osKeychain "Stores and fetches Master Key in" "keyring crate / macOS Security framework / Linux Secret Service / Windows Credential Manager"
        merkleVault.vaultAgent.storageAdapter -> merkleVault.sqliteDatabase "Reads and writes Secret, Namespace, and Audit records to" "SQLite WAL (file I/O)"
        merkleVault.vaultAgent.auditWriter -> merkleVault.auditLogFile "Appends Audit Entries (JSONL, Hash Chain) to" "Append-only file write (JSONL)"
        merkleVault.vaultAgent.backupRecoveryDomain -> merkleVault.backupStore "Writes encrypted Backup files to" "Filesystem write (age .merkle.age)"
        merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.configStore "Reads Recovery Public Key and vault configuration from" "TOML file read"
        merkleVault.vaultAgent.secretStorageDomain -> merkleVault.configStore "Reads Namespace binding overrides from" "TOML / .merklerc file read"
        merkleVault.vaultAgent.externalServiceAdapter -> sshTarget "Proxies SSH sessions to" "SSH protocol (russh)"
        merkleVault.vaultAgent.externalServiceAdapter -> httpService "Proxies HTTP requests to" "HTTPS (reqwest)"
        merkleVault.vaultAgent.externalServiceAdapter -> cloudProviderApi "Invokes cloud API calls on behalf of operator via" "HTTPS / cloud SDK"
        merkleVault.vaultAgent.externalServiceAdapter -> processSpawnTarget "Spawns child processes with injected environment variables via" "OS process API (tokio::process)"
        merkleVault.vaultAgent.backupRecoveryDomain -> driveSyncTarget "Mirrors encrypted Backup files to" "Filesystem / cloud sync API"
        merkleVault.vaultAgent.auditQueryModel -> remoteAuditWebhook "Streams HMAC-signed Audit Entries to (opt-in) via" "HTTPS webhook (HMAC Signature)"
        merkleVault.vaultAgent.oobNotifierAdapter -> companionDevice "Delivers OOB Confirmation challenge to" "OOB channel (desktop notification, localhost, or direct companion protocol)"
        companionDevice -> merkleVault.vaultAgent.oobNotifierAdapter "Returns Ed25519-signed OobResolution to" "OOB channel (direct companion protocol)"

        # ─── Deployment Environment ────────────────────────────────────────────

        deploymentEnvironment "Production" {
            deploymentNode "macOS Workstation" "Apple macOS 14+ (Sonoma or later), arm64 or x86_64" "macOS" {
                deploymentNode "User Session (macOS)" "Single user login session. Vault Agent started as a launchd user agent." "macOS launchd" {
                    deploymentNode "Vault Agent Process (macOS)" "Long-running Tokio async runtime. mlock supported. Companion Socket at ~/Library/Application Support/merkle/agent.sock." "Rust binary" {
                        containerInstance merkleVault.vaultAgent
                    }
                    deploymentNode "MCP Server Process (macOS)" "One process per Claude Code / Cursor window. Short-lived. Communicates with Vault Agent over the Companion Socket." "Rust binary" {
                        containerInstance merkleVault.mcpServer
                    }
                    deploymentNode "Merkle CLI Process (macOS)" "Invoked on demand by the operator. Connects to the Vault Agent over the Companion Socket." "Rust binary" {
                        containerInstance merkleVault.merkleCli
                    }
                }
                deploymentNode "macOS File System" "APFS volume. WAL-mode SQLite, JSONL audit log, TOML config, and age-encrypted backups all reside here." "APFS" {
                    containerInstance merkleVault.sqliteDatabase
                    containerInstance merkleVault.auditLogFile
                    containerInstance merkleVault.configStore
                    containerInstance merkleVault.backupStore
                }
                deploymentNode "macOS Keychain" "macOS Security framework Keychain. Stores the Master Key under service identifier dev.fapp.merkle." "macOS Security.framework" {
                    softwareSystemInstance osKeychain
                }
            }

            deploymentNode "Linux Workstation" "GNU/Linux (Ubuntu 22.04+, Fedora 38+, or equivalent), x86_64 or arm64" "Linux" {
                deploymentNode "User Session (Linux)" "Single user login session. Vault Agent started as a systemd user service." "systemd --user" {
                    deploymentNode "Vault Agent Process (Linux)" "Long-running Tokio async runtime. mlock supported. Companion Socket at $XDG_RUNTIME_DIR/merkle/agent.sock." "Rust binary" {
                        containerInstance merkleVault.vaultAgent
                    }
                    deploymentNode "MCP Server Process (Linux)" "One process per client window. Short-lived." "Rust binary" {
                        containerInstance merkleVault.mcpServer
                    }
                    deploymentNode "Merkle CLI Process (Linux)" "Invoked on demand by the operator." "Rust binary" {
                        containerInstance merkleVault.merkleCli
                    }
                }
                deploymentNode "Linux File System" "ext4 or btrfs volume. WAL-mode SQLite, JSONL audit log, TOML config, and age-encrypted backups all reside here." "ext4 / btrfs" {
                    containerInstance merkleVault.sqliteDatabase
                    containerInstance merkleVault.auditLogFile
                    containerInstance merkleVault.configStore
                    containerInstance merkleVault.backupStore
                }
                deploymentNode "Linux Secret Service" "libsecret / KWallet D-Bus service. Stores the Master Key under service identifier dev.fapp.merkle." "Secret Service API / KWallet" {
                    softwareSystemInstance osKeychain
                }
            }

            deploymentNode "Windows Workstation" "Microsoft Windows 10 22H2+ or Windows 11, x86_64" "Windows" {
                deploymentNode "User Session (Windows)" "Single user login session. Vault Agent started as a Windows Service registered under the current user." "Windows Service" {
                    deploymentNode "Vault Agent Process (Windows)" "Long-running Tokio async runtime. Named pipe at \\.\pipe\merkle-agent. VirtualLock used in place of mlock." "Rust binary" {
                        containerInstance merkleVault.vaultAgent
                    }
                    deploymentNode "MCP Server Process (Windows)" "One process per client window. Short-lived." "Rust binary" {
                        containerInstance merkleVault.mcpServer
                    }
                    deploymentNode "Merkle CLI Process (Windows)" "Invoked on demand by the operator." "Rust binary" {
                        containerInstance merkleVault.merkleCli
                    }
                }
                deploymentNode "Windows File System" "NTFS volume. WAL-mode SQLite, JSONL audit log, TOML config, and age-encrypted backups all reside here." "NTFS" {
                    containerInstance merkleVault.sqliteDatabase
                    containerInstance merkleVault.auditLogFile
                    containerInstance merkleVault.configStore
                    containerInstance merkleVault.backupStore
                }
                deploymentNode "Windows Credential Manager" "Windows Credential Manager (DPAPI-backed). Stores the Master Key under service identifier dev.fapp.merkle." "Windows Credential Manager" {
                    softwareSystemInstance osKeychain
                }
            }
        }

        deploymentEnvironment "Local Workstation" {
            deploymentNode "Developer Workstation" "Single-user local machine. Vault Agent runs as a foreground process or user-level service. Companion Socket used for Companion Device pairing and Reveal OOB challenges. Cross-reference: integrations/onboarding.md section 5." "macOS / Linux" {
                deploymentNode "Vault Agent Process" "Long-running Tokio async runtime. Companion Socket at platform-default path. Hosts domain core across all six bounded contexts." "Rust binary" {
                    containerInstance merkleVault.vaultAgent
                }
                deploymentNode "MCP Server Process" "One process per client window (Claude Code, Cursor, or any MCP-capable IDE). Spawned on demand. Communicates with Vault Agent over the Companion Socket." "Rust binary" {
                    containerInstance merkleVault.mcpServer
                }
                deploymentNode "Merkle CLI Process" "Invoked on demand by the operator for vault administration (init, unseal, backup, doctor, device pair)." "Rust binary" {
                    containerInstance merkleVault.merkleCli
                }
                deploymentNode "Local File System" "Stores WAL-mode SQLite database, JSONL audit log, TOML config, and age-encrypted backup files." "Filesystem" {
                    containerInstance merkleVault.sqliteDatabase
                    containerInstance merkleVault.auditLogFile
                    containerInstance merkleVault.configStore
                    containerInstance merkleVault.backupStore
                }
                deploymentNode "OS Keychain (local)" "OS-managed credential store. Holds the Master Key and, for enrolled Companion Devices, the Ed25519 private key under merkle-companion-<device-id>." "macOS Keychain / Linux Secret Service" {
                    softwareSystemInstance osKeychain
                }
            }
            deploymentNode "Companion Device" "Pre-paired secondary device (mobile phone, hardware token, or secondary workstation) running off-box or as a separate process. Signs OOB Confirmation challenges with an Ed25519 identity key enrolled at pairing time via merkle device pair. The agent's Ed25519 paired key is persisted in the OS Keychain on the Vault Agent host under service identifier merkle-companion-<device-id>. Subscribes to the OOB Notifier endpoint exposed by the Vault Agent (desktop notification, localhost browser page, or direct companion protocol). Multiple devices may be enrolled simultaneously. Cross-reference: ADR-0011 Amendment, integrations/onboarding.md section 5." "External / Off-box" {
                softwareSystemInstance companionDevice
            }
            deploymentNode "OS Keychain — Companion Key Entry" "Logical entry within the Vault Agent host OS Keychain recording the paired device's Ed25519 public key. Service identifier: merkle-companion-<device-id>. Written during merkle device pair. Read by OOB Notifier Adapter when verifying OobResolution Ed25519 signature. One entry per enrolled device." "macOS Keychain / Linux Secret Service" {
                softwareSystemInstance osKeychain
            }
        }
    }

    views {

        # ── System Context ─────────────────────────────────────────────────────

        systemContext merkleVault "SystemContext" "System context view of Merkle Vault showing actors and external systems." {
            include *
            autoLayout
        }

        # ── Container ─────────────────────────────────────────────────────────

        container merkleVault "ContainerView" "Container view of Merkle Vault showing internal runtime components and data stores." {
            include *
            autoLayout
        }

        # ── Component views — one per bounded context ─────────────────────────

        component merkleVault.vaultAgent "IdentityAndSealingComponents" "Component view for the Identity and Sealing bounded context. Shows how the Unseal Protocol fetches the Master Key from the OS Keychain, derives the Vault Root Key, and unlocks Namespace DEKs for use by Secret Storage." {
            include merkleVault.vaultAgent.companionSocketPort
            include merkleVault.vaultAgent.identityAndSealingDomain
            include merkleVault.vaultAgent.keychainAdapter
            include merkleVault.vaultAgent.cryptoAdapter
            include merkleVault.vaultAgent.storageAdapter
            include merkleVault.vaultAgent.secretStorageDomain
            include merkleVault.configStore
            include osKeychain
            autoLayout
        }

        component merkleVault.vaultAgent "SecretStorageComponents" "Component view for the Secret Storage bounded context. Shows how Secrets are persisted, encrypted per-blob, and searched via the FTS5 Index, and how Namespace binding resolves the active Namespace from cwd hash or .merklerc." {
            include merkleVault.vaultAgent.companionSocketPort
            include merkleVault.vaultAgent.secretStorageDomain
            include merkleVault.vaultAgent.identityAndSealingDomain
            include merkleVault.vaultAgent.policyPermissionsDomain
            include merkleVault.vaultAgent.storageAdapter
            include merkleVault.vaultAgent.cryptoAdapter
            include merkleVault.sqliteDatabase
            include merkleVault.configStore
            autoLayout
        }

        component merkleVault.vaultAgent "AccessMediationComponents" "Component view for the Access Mediation bounded context. Shows how Proxy Tools execute SSH, HTTP, spawn, and tempfile operations with credential injection, how Use Tokens are issued and resolved via the Companion Socket Port, and how Reveal requests are gated by Operator Confirmation and OOB Confirmation." {
            include merkleVault.vaultAgent.companionSocketPort
            include merkleVault.vaultAgent.accessMediationDomain
            include merkleVault.vaultAgent.secretStorageDomain
            include merkleVault.vaultAgent.policyPermissionsDomain
            include merkleVault.vaultAgent.auditWriter
            include merkleVault.vaultAgent.externalServiceAdapter
            include merkleVault.vaultAgent.oobNotifierAdapter
            include sshTarget
            include httpService
            include processSpawnTarget
            include cloudProviderApi
            autoLayout
        }

        component merkleVault.vaultAgent "AuditAndComplianceComponents" "Component view for the Audit and Compliance bounded context. Shows how every Secret operation is recorded as an Audit Entry via Audit Writer, how the Merkle-style Hash Chain is maintained with BLAKE3 hashes, how the Chain Verifier validates integrity end-to-end, how the Audit Query Model exposes read-only projections, and how HMAC-signed entries are optionally streamed to the Remote Audit Webhook." {
            include merkleVault.vaultAgent.auditWriter
            include merkleVault.vaultAgent.chainVerifier
            include merkleVault.vaultAgent.auditQueryModel
            include merkleVault.vaultAgent.auditChainVerifier
            include merkleVault.vaultAgent.accessMediationDomain
            include merkleVault.vaultAgent.storageAdapter
            include merkleVault.vaultAgent.cryptoAdapter
            include merkleVault.auditLogFile
            include merkleVault.sqliteDatabase
            include remoteAuditWebhook
            autoLayout
        }

        component merkleVault.vaultAgent "BackupAndRecoveryComponents" "Component view for the Backup and Recovery bounded context. Shows how the Backup Scheduler triggers age-encrypted Backup creation (Anacron Trigger, Change-Triggered Backup, Idle-Triggered Backup, Sleep Hook, on-shutdown), how Backups are written to the Backup Store, how optional mirroring to the Drive Sync Target works, and how the Restore and Disaster Recovery flows operate." {
            include merkleVault.vaultAgent.backupRecoveryDomain
            include merkleVault.vaultAgent.backupScheduler
            include merkleVault.vaultAgent.storageAdapter
            include merkleVault.vaultAgent.cryptoAdapter
            include merkleVault.vaultAgent.chainVerifier
            include merkleVault.sqliteDatabase
            include merkleVault.backupStore
            include driveSyncTarget
            autoLayout
        }

        component merkleVault.vaultAgent "PolicyAndPermissionsComponents" "Component view for the Policy and Permissions bounded context. Shows how Namespace Policies are evaluated to govern Secret Storage and Access Mediation, how Rate Limits are enforced per operation class, how the Reveal Policy gates high-sensitivity disclosures, how Cross-Namespace Access is controlled, how Security Profiles (relaxed, balanced, paranoid) are applied at init, and how BackupScheduler reads scheduling parameters from Namespace Policy." {
            include merkleVault.vaultAgent.policyPermissionsDomain
            include merkleVault.vaultAgent.accessMediationDomain
            include merkleVault.vaultAgent.secretStorageDomain
            include merkleVault.vaultAgent.companionSocketPort
            include merkleVault.vaultAgent.backupScheduler
            include merkleVault.vaultAgent.storageAdapter
            include merkleVault.sqliteDatabase
            autoLayout
        }

        # ── Deployment views ──────────────────────────────────────────────────

        deployment merkleVault "Production" "DeploymentView" "Representative deployment topology for macOS, Linux, and Windows. Each platform runs one Vault Agent daemon per user, one or more MCP Server processes per client window, and one Merkle CLI binary. The OS Keychain backend differs per platform; all other components are identical." {
            include *
            autoLayout
        }

        deployment merkleVault "Local Workstation" "LocalWorkstationDeploymentView" "Single-workstation developer deployment. One Vault Agent process, one or more MCP Server processes per IDE window, and the Merkle CLI. OS Keychain holds the Master Key and optional Companion Device Ed25519 keys. Companion Device is an off-box or separate process enrolled via merkle device pair. Cross-reference: integrations/onboarding.md, integrations/claude-code-wiring.md." {
            include *
            autoLayout
        }

        # ── Dynamic views ─────────────────────────────────────────────────────

        dynamic merkleVault.vaultAgent "RevealWithOOB" "Reveal sequence for a high-sensitivity Secret requiring both Slash Command and OOB Confirmation from a pre-paired Companion Device. Cite: ADR-0011 Amendment." {
            merkleVault.mcpServer -> merkleVault.vaultAgent.companionSocketPort "1. vault.reveal(handle, slash_command=true) received from MCP Client"
            merkleVault.vaultAgent.companionSocketPort -> merkleVault.vaultAgent.accessMediationDomain "2. reveal_request dispatched: slash_command=true, oob_ack=false"
            merkleVault.vaultAgent.accessMediationDomain -> merkleVault.vaultAgent.policyPermissionsDomain "3. check_reveal_policy(namespace, sensitivity=high) — slash_command + oob_ack both required"
            merkleVault.vaultAgent.accessMediationDomain -> merkleVault.vaultAgent.oobNotifierAdapter "4. send_oob_challenge(challenge_id, handle, nonce) to OOB Notifier"
            merkleVault.vaultAgent.oobNotifierAdapter -> companionDevice "5. OOB Confirmation challenge delivered (desktop notification or companion protocol)"
            companionDevice -> merkleVault.vaultAgent.oobNotifierAdapter "6. OobResolution: {outcome=approved, device_signature=Ed25519Sign(canonical_challenge_bytes)}"
            merkleVault.vaultAgent.secretStorageDomain -> merkleVault.vaultAgent.accessMediationDomain "7. resolve_private_blob(handle) — oob_ack=true; signature verified; plaintext provided"
            merkleVault.vaultAgent.accessMediationDomain -> merkleVault.vaultAgent.auditWriter "8. emit AuditEntry(op=reveal, outcome=success, note=oob_confirmed); plaintext zeroed"
            autoLayout
        }

        dynamic merkleVault.vaultAgent "SealedToUnsealed" "Unseal protocol — Vault Agent transitions from Sealed State to Unsealed State by fetching the Master Key from the OS Keychain, unwrapping the Vault Root Key, and locking it in protected memory. Cite: ADR-0015, domain/identity-and-sealing.md." {
            merkleVault.vaultAgent.companionSocketPort -> merkleVault.vaultAgent.identityAndSealingDomain "1. unseal command dispatched (from CLI Adapter or MCP Adapter)"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.keychainAdapter "2. fetch Master Key (service=dev.fapp.merkle, account=master-vN)"
            merkleVault.vaultAgent.keychainAdapter -> osKeychain "3. OS Keychain read (keyring crate)"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.storageAdapter "4. read dual-wrapped Vault Root Key (master-wrapped copy) from SQLite"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.cryptoAdapter "5. unwrap Vault Root Key with Master Key (XChaCha20-Poly1305); mlock; Sealed -> Unsealed"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.secretStorageDomain "6. Namespace DEKs available to Secret Storage (unwrapped on demand)"
            autoLayout
        }

        dynamic merkleVault.vaultAgent "SealedToUnsealedFallback" "Passphrase/Argon2id fallback unseal path — used when the OS Keychain is unavailable (headless server, CI, keychain locked). Operator provides passphrase interactively via rpassword TTY prompt. Cite: ADR-0005 Amendment, ADR-0015, docs/arch/domain/identity-and-sealing.md." {
            merkleVault.vaultAgent.cliPortAdapter -> merkleVault.vaultAgent.companionSocketPort "1. merkle unseal --passphrase-mode dispatched via CLI Adapter"
            merkleVault.vaultAgent.companionSocketPort -> merkleVault.vaultAgent.identityAndSealingDomain "2. unseal_passphrase_mode command routed to Identity And Sealing Domain"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.keychainAdapter "3. attempt keychain fetch — keychain returns Unreachable"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.storageAdapter "4. read Argon2id parameters (m_cost, t_cost, p_cost, salt) from vault DB header"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.cryptoAdapter "5. validate Argon2id parameters against Minimum Hardness Floor (ADR-0005 Amendment: m>=65536, t>=3)"
            merkleVault.vaultAgent.cliPortAdapter -> merkleVault.vaultAgent.companionSocketPort "6. CLI Adapter prompts operator for passphrase via rpassword (TTY, no echo)"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.cryptoAdapter "7. derive Master Key: Argon2id(passphrase, salt, validated_params) — RFC 9106"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.storageAdapter "8. read dual-wrapped Vault Root Key (passphrase-derived master-wrapped copy) from SQLite"
            merkleVault.vaultAgent.identityAndSealingDomain -> merkleVault.vaultAgent.cryptoAdapter "9. unwrap Vault Root Key with derived Master Key (XChaCha20-Poly1305); mlock; Sealed -> Unsealed"
            autoLayout
        }

        # ── Styles ─────────────────────────────────────────────────────────────

        styles {

            element "Person" {
                shape Person
                background #08427b
                color #ffffff
                fontSize 16
            }

            element "Software System" {
                background #1168bd
                color #ffffff
                fontSize 14
            }

            element "External" {
                background #999999
                color #ffffff
                fontSize 14
            }

            element "Container" {
                background #438dd5
                color #ffffff
                fontSize 13
            }

            element "Component" {
                background #85bbf0
                color #000000
                fontSize 12
            }

            element "Database" {
                shape Cylinder
                background #438dd5
                color #ffffff
                fontSize 13
            }

            element "Domain" {
                background #2e7d32
                color #ffffff
                fontSize 12
            }

            element "Adapter" {
                background #6a1e72
                color #ffffff
                fontSize 12
            }

            element "DomainService" {
                background #1565c0
                color #ffffff
                fontSize 12
            }

            relationship "Relationship" {
                dashed false
                color #707070
                fontSize 11
                thickness 2
            }
        }

        themes default
    }
}
