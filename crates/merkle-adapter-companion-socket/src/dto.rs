//! Request and response Data Transfer Objects (DTOs).
//!
//! All DTOs mirror the OpenAPI 3.1 schemas in `companion-socket.yaml`.
//! They are used exclusively by the HTTP layer; the application layer
//! receives domain types, not DTOs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use merkle_types::{Handle, OobChannel, SecurityProfile, Sensitivity};

// ---------------------------------------------------------------------------
// Shared sub-types
// ---------------------------------------------------------------------------

/// Two-flag operator confirmation model (ADR-0011).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfirmation {
    /// Set by the MCP Adapter when a verified slash command triggered the op.
    pub slash_command: bool,
    /// Set by the OOB Notifier after operator physically acknowledged.
    #[serde(default)]
    pub oob_ack: bool,
    /// OOB channel through which confirmation was delivered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oob_channel: Option<OobChannel>,
}

/// Structured key-value tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagDto {
    /// Tag key — closed enum: env, project, role, provider, team.
    pub key: String,
    /// Tag value — slug pattern.
    pub value: String,
}

/// Public metadata fields safe to return through the MCP transport.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PublicMetadataDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes_public: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub expose: bool,
}

// ---------------------------------------------------------------------------
// Agent status
// ---------------------------------------------------------------------------

/// Response body for `GET /v1/agent/status`.
#[expect(
    clippy::struct_excessive_bools,
    reason = "Mirrors the AgentStatus OpenAPI schema verbatim; bools are \
              independent diagnostic flags, not a state machine."
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusResponse {
    pub agent_version: String,
    pub vault_state: VaultState,
    /// Deprecated: derive from `vault_state` instead.
    pub sealed: bool,
    pub keychain_reachable: bool,
    pub db_path: String,
    pub db_size_bytes: u64,
    pub audit_chain_valid: bool,
    pub backup_overdue: bool,
    pub disk_free_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_backup_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expiring_soon: Vec<ExpiringSoon>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Vault agent lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    Sealed,
    Unsealing,
    Unsealed,
    ShuttingDown,
}

/// A secret expiring within 7 days.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiringSoon {
    pub handle: Handle,
    pub expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Optional request body for `POST /v1/agent/init`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InitVaultRequest {
    /// Security profile applied to subsequent Namespace Policy defaults.
    /// Defaults to `balanced` when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_profile: Option<SecurityProfile>,
}

/// Response body for `POST /v1/agent/init` (201 Created).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitVaultResponse {
    /// UUIDv7 identifying this vault installation.
    pub vault_id: String,
    /// age X25519 recipient string (`age1<bech32>`).
    ///
    /// This is the ONLY time this value is transmitted.
    /// The operator MUST record it offline immediately.
    pub recovery_key: String,
    /// Canonical service + account reference where the Master Key was stored.
    /// Format: `dev.fapp.merkle/master-v1`.
    pub master_key_keychain_ref: String,
}

// ---------------------------------------------------------------------------
// Unseal / Seal
// ---------------------------------------------------------------------------

/// Optional request body for `POST /v1/agent/unseal`.
///
/// Currently no fields are accepted; the body is reserved for future extension.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnsealRequest {}

/// Response body for `POST /v1/agent/unseal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsealResponse {
    pub sealed: bool,
    pub already_unsealed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<UnsealMethod>,
}

/// Key-retrieval method used to unseal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsealMethod {
    Keychain,
    Argon2idPassphrase,
}

/// Response body for `POST /v1/agent/seal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealResponse {
    pub sealed: bool,
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

/// A single namespace in the list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceDto {
    pub id: Uuid,
    pub label: String,
    pub policy_profile: SecurityProfile,
    pub created_at: DateTime<Utc>,
    pub dek_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_count: Option<u32>,
}

/// Response body for `GET /v1/namespaces`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListNamespacesResponse {
    pub items: Vec<NamespaceDto>,
    pub total: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// Public metadata for a single Secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDto {
    pub handle: Handle,
    pub name: String,
    pub category: String,
    pub sensitivity: Sensitivity,
    pub tags: Vec<TagDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_meta: Option<PublicMetadataDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    pub expose: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_warning: Option<String>,
}

/// Response body for `GET /v1/namespaces/{namespace_id}/secrets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSecretsResponse {
    pub items: Vec<SecretDto>,
    pub total: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Present only when `fts_query` is active — ranked items with score +
    /// highlights. When present, `items` is empty (use `ranked_items`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranked_items: Option<Vec<RankedSecretDto>>,
    /// `true` when more ranked results exist beyond `offset + limit`.
    /// Only present in ranked mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
}

/// Per-field highlight snippet (ADR-0027 §Response Contract).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHighlightDto {
    /// FTS5 column that produced this highlight.
    pub field: String,
    /// Extracted text with matched terms wrapped in `<b>` tags.
    pub snippet: String,
}

/// A ranked secret result (ADR-0027 §Response Contract).
///
/// Extends [`SecretDto`] with BM25 ranking fields. The `score`, `bm25_rank`,
/// and `highlights` fields are absent in non-ranked (list) responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedSecretDto {
    #[serde(flatten)]
    pub secret: SecretDto,
    /// Raw BM25 score (negative; more negative = better match per SQLite FTS5).
    pub score: f64,
    /// 1-based rank within this page. Global rank = `offset + bm25_rank - 1`.
    pub bm25_rank: u32,
    /// Per-field highlight snippets.
    pub highlights: Vec<SearchHighlightDto>,
}

/// Encoding of the payload bytes in `value` / `new_value` fields.
///
/// Mirrors `merkle_application::ValueFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueFormatDto {
    /// UTF-8 text (default).
    #[default]
    Utf8,
    /// Standard base64-encoded binary blob.
    Base64,
}

impl From<ValueFormatDto> for merkle_application::ValueFormat {
    fn from(dto: ValueFormatDto) -> Self {
        match dto {
            ValueFormatDto::Utf8 => Self::Utf8,
            ValueFormatDto::Base64 => Self::Base64,
        }
    }
}

/// Request body for `POST /v1/namespaces/{namespace_id}/secrets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutSecretRequest {
    pub name: String,
    pub category: String,
    /// The sensitive material — write-only; never returned in responses.
    pub value: serde_json::Value,
    /// How `value` is encoded. Defaults to `utf8`.
    #[serde(default)]
    pub value_format: ValueFormatDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<TagDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<Sensitivity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub expose: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub force: bool,
}

/// Response body for `POST /v1/namespaces/{namespace_id}/secrets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutSecretResponse {
    pub handle: Handle,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate_fingerprint_warning: Option<String>,
}

/// Request body for `DELETE /v1/namespaces/{namespace_id}/secrets/{handle_encoded}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSecretRequest {
    pub purpose: String,
    pub operator_confirmation: OperatorConfirmationDeleteSecret,
}

/// Inline confirmation type for delete secret (requires both flags per OpenAPI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfirmationDeleteSecret {
    pub slash_command: bool,
    pub oob_ack: bool,
}

/// Response body for `DELETE /v1/namespaces/{namespace_id}/secrets/{handle_encoded}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSecretResponse {
    pub deleted: bool,
    pub versions_removed: u32,
}

// ---------------------------------------------------------------------------
// Secret versions
// ---------------------------------------------------------------------------

/// A single version entry in the version history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersionDto {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
    /// Size of the encrypted Private Blob in bytes.
    pub size_bytes: u64,
}

/// Response body for `GET /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/versions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSecretVersionsResponse {
    pub handle: Handle,
    pub versions: Vec<SecretVersionDto>,
}

// ---------------------------------------------------------------------------
// Rotate / Rollback
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rotate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateSecretRequest {
    pub new_value: serde_json::Value,
    /// How `new_value` is encoded. Defaults to `utf8`.
    #[serde(default)]
    pub value_format: ValueFormatDto,
    pub purpose: String,
}

/// Response body for `POST /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rotate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateSecretResponse {
    pub handle: Handle,
    pub version: u32,
    pub rotated_at: DateTime<Utc>,
    pub versions_retained: u32,
}

/// Request body for `POST /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rollback`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackSecretRequest {
    pub target_version: u32,
    pub operator_confirmation: OperatorConfirmation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// Response body for rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackSecretResponse {
    pub handle: Handle,
    pub active_version: u32,
    pub rolled_back_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub cwd_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_pid: Option<u32>,
}

impl CreateSessionRequest {
    /// Char-safe fallback namespace slug derived from the first 24 characters
    /// of `cwd_hash`.
    ///
    /// Uses `chars().take(24)` instead of a byte-index slice (`&cwd_hash[..24]`)
    /// so a non-ASCII / multibyte `cwd_hash` cannot panic on a non-char
    /// boundary (MERK-006). A well-formed `cwd_hash` is a 64-char lowercase hex
    /// SHA-256 digest, but the agent must never crash on malformed input.
    #[must_use]
    pub fn cwd_hash_slug(&self) -> String {
        self.cwd_hash.chars().take(24).collect()
    }
}

/// Response body for `POST /v1/sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: Uuid,
    pub namespace_id: Uuid,
    pub namespace_label: String,
    pub policy_profile: SecurityProfile,
}

/// Response body for `DELETE /v1/sessions/{session_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseSessionResponse {
    pub closed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_tokens_revoked: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tempfiles_scheduled_for_cleanup: Option<u32>,
}

// ---------------------------------------------------------------------------
// Reveal
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/reveal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealRequest {
    pub handle: Handle,
    /// Caller-supplied justification for the reveal.
    pub reason: String,
    pub session_id: Uuid,
    pub operator_confirmation: OperatorConfirmation,
}

/// Response body for `POST /v1/reveal` when plaintext is returned (200).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealAuthorizationResponse {
    pub handle: Handle,
    /// Decrypted Private Blob — shape varies by category.
    pub plaintext: serde_json::Value,
    pub revealed_at: DateTime<Utc>,
    pub warning: String,
}

/// Response body for `POST /v1/reveal` when OOB confirmation is pending (202).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobPendingResponse {
    pub oob_pending: bool,
    pub oob_channel: OobChannel,
    pub expires_at: DateTime<Utc>,
    /// 64-hex-char nonce for correlation and device-signature binding.
    pub request_nonce: String,
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Query parameters for `GET /v1/audit`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditQuery {
    pub handle: Option<String>,
    pub op: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub session_id: Option<Uuid>,
    pub outcome: Option<String>,
    #[serde(default)]
    pub verify_chain: bool,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    50
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntryDto {
    pub id: Uuid,
    pub ts: DateTime<Utc>,
    pub namespace_id: Uuid,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<Handle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    pub session_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub current_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

/// Response body for `GET /v1/audit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResponse {
    pub entries: Vec<AuditEntryDto>,
    pub total: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_valid: Option<bool>,
}

// ---------------------------------------------------------------------------
// Backup / Restore
// ---------------------------------------------------------------------------

/// Optional request body for `POST /v1/backup`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TriggerBackupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Backup snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSnapshotDto {
    pub filename: String,
    pub created_at: DateTime<Utc>,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<BackupTrigger>,
}

/// How a backup was triggered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupTrigger {
    Manual,
    PreRotate,
    ChangeTriggered,
    IdleTriggered,
    AnacronTriggered,
}

/// Response body for `GET /v1/backup/snapshots`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSnapshotsResponse {
    pub snapshots: Vec<BackupSnapshotDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Request body for `POST /v1/backup/restore-plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRestorePlanRequest {
    pub snapshot_filename: String,
    pub mode: RestoreMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_key_path: Option<String>,
}

/// Restore strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMode {
    Overwrite,
    Merge,
    NewestWins,
}

/// A conflict entry inside a restore plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreConflictDto {
    pub handle: Handle,
    pub resolution: String,
}

/// Response body for `POST /v1/backup/restore-plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePlanResponse {
    pub plan_id: String,
    pub mode: RestoreMode,
    pub snapshot_filename: String,
    pub namespaces_to_add: u32,
    pub namespaces_to_skip: u32,
    pub secrets_to_add: u32,
    pub secrets_to_overwrite: u32,
    pub secrets_to_skip: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<RestoreConflictDto>,
    pub expires_at: DateTime<Utc>,
}

/// Request body for `POST /v1/backup/restore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRestoreRequest {
    pub plan_id: String,
    pub operator_confirmation: OperatorConfirmationDeleteSecret,
}

/// Response body for `POST /v1/backup/restore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRestoreResponse {
    pub restored: bool,
    pub secrets_restored: u32,
    pub namespaces_restored: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restored_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Pagination helpers
// ---------------------------------------------------------------------------

/// Common pagination query parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Query parameters for listing secrets.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListSecretsParams {
    pub category: Option<String>,
    pub sensitivity: Option<Sensitivity>,
    pub tags: Option<String>,
    pub name_pattern: Option<String>,
    pub expires_before: Option<DateTime<Utc>>,
    pub fts_query: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: u32,
    pub cursor: Option<String>,
    /// Zero-based offset for ranked (fts_query) pagination (ADR-0027).
    #[serde(default)]
    pub offset: u32,
}

/// Query parameters for listing backup snapshots.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListSnapshotsParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
    pub cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// Use-token group
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/use-tokens`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseTokenRequest {
    pub namespace_id: Uuid,
    pub handle: Handle,
    pub session_id: Uuid,
}

/// Response body for `POST /v1/use-tokens`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseTokenResponse {
    /// Opaque 43-character URL-safe base64 token string.
    pub use_token: String,
    pub expires_at: DateTime<Utc>,
}

/// Request body for `POST /v1/use-tokens/tempfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteTempfileRequest {
    pub namespace_id: Uuid,
    pub handle: Handle,
    pub session_id: Uuid,
    /// Opaque single-use authorization token from `POST /v1/use-tokens`.
    ///
    /// Required: the agent validates and consumes it (rejecting expired,
    /// replayed, or unknown tokens) before materializing any plaintext.
    pub use_token: String,
}

/// Response body for `POST /v1/use-tokens/tempfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseTempfileResponse {
    /// Opaque token — the real path is never returned over the socket.
    pub opaque_token: String,
    pub expires_at: DateTime<Utc>,
}

/// Request body for `POST /v1/use-tokens/fifo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFifoRequest {
    pub namespace_id: Uuid,
    pub handle: Handle,
    pub session_id: Uuid,
    /// Opaque single-use authorization token from `POST /v1/use-tokens`.
    ///
    /// Required: the agent validates and consumes it (rejecting expired,
    /// replayed, or unknown tokens) before creating the FIFO or materializing
    /// any plaintext.
    pub use_token: String,
}

/// Response body for `POST /v1/use-tokens/fifo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseFifoResponse {
    /// Opaque token identifying the FIFO — the real path is never returned.
    pub opaque_token: String,
    pub expires_at: DateTime<Utc>,
}

/// Response body for `DELETE /v1/use-tokens/tempfiles/{opaque_token}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeTempfileResponse {
    pub revoked: bool,
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// A single check entry inside the doctor response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    /// `"pass"`, `"warn"`, or `"fail"`.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub duration_ms: u64,
}

/// Response body for `GET /v1/agent/doctor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorResponse {
    pub checks: Vec<DoctorCheck>,
    /// `"healthy"`, `"degraded"`, or `"unhealthy"`.
    pub overall: String,
}

// ---------------------------------------------------------------------------
// Proxy group — SSH
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/proxy/ssh/exec`.
///
/// # Design note (ADR-0024 §Proxy tool execution split)
///
/// Per ADR-0024 the proxy tools execute on the AGENT side. The request
/// supplies a `key_handle` referring to a stored secret; the agent resolves
/// and decrypts the key material internally before calling the External
/// Services port. Key bytes never cross the Companion Socket boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySshExecRequest {
    pub namespace_id: Uuid,
    /// Handle to the SSH private-key secret stored in the vault.
    pub key_handle: Handle,
    /// Remote host in `host:port` form (e.g. `"bastion.example.com:22"`).
    pub target: String,
    /// Shell command to execute on the remote host.
    pub command: String,
}

/// Response body for `POST /v1/proxy/ssh/exec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySshExecResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Request body for `POST /v1/proxy/ssh/copy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySshCopyRequest {
    pub namespace_id: Uuid,
    /// Handle to the SSH private-key secret stored in the vault.
    pub key_handle: Handle,
    /// SSH target in `host:port` form.
    pub target: String,
    /// Source path (local path for upload; remote path for download).
    pub source: String,
    /// Destination path (remote path for upload; local path for download).
    pub dest: String,
    /// Transfer direction.
    pub direction: SshCopyDirection,
}

/// Transfer direction for `ProxySshCopyRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshCopyDirection {
    Upload,
    Download,
}

/// Response body for `POST /v1/proxy/ssh/copy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySshCopyResponse {
    pub bytes_transferred: u64,
    pub exit_code: i32,
}

/// Request body for `POST /v1/proxy/ssh/port-forward`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPortForwardRequest {
    pub namespace_id: Uuid,
    /// Handle to the SSH private-key secret stored in the vault.
    pub key_handle: Handle,
    /// SSH bastion target in `host:port` form.
    pub target: String,
    /// Local port to bind on `127.0.0.1`.
    pub local_port: u16,
    /// Remote host for the forwarded connection.
    pub remote_host: String,
    /// Remote port for the forwarded connection.
    pub remote_port: u16,
    /// Optional TTL in seconds for the tunnel; agent enforces graceful shutdown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

/// Response body for `POST /v1/proxy/ssh/port-forward`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPortForwardResponse {
    pub session_id: Uuid,
    pub local_addr: String,
}

/// Request body for `POST /v1/proxy/ssh/shell`.
///
/// Full PTY proxy is out of scope for this phase. The endpoint is wired but
/// returns 501 Not Implemented. A future phase will introduce a streaming
/// WebSocket sub-protocol over the Companion Socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySshShellRequest {
    pub namespace_id: Uuid,
    /// Handle to the SSH private-key secret stored in the vault.
    pub key_handle: Handle,
    /// SSH target in `host:port` form.
    pub target: String,
}

/// Response placeholder for `POST /v1/proxy/ssh/shell` (501 today).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySshShellResponse {
    pub session_id: Uuid,
    /// Transport URI for the future streaming channel.
    pub transport_uri: String,
}

// ---------------------------------------------------------------------------
// Proxy group — HTTP
// ---------------------------------------------------------------------------

/// Inline HTTP auth specification in proxy requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum HttpAuthSpec {
    /// No authentication attached.
    None,
    /// Bearer token in the Authorization header.
    Bearer { token: String },
    /// HTTP Basic authentication.
    Basic { user: String, pass: String },
}

/// Inline HTTP request specification in proxy requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestSpecDto {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Request body for `POST /v1/proxy/http/request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHttpRequestRequest {
    pub namespace_id: Uuid,
    /// Optional handle to a vault secret whose plaintext is used as the auth
    /// credential. When set, the agent decrypts the secret and constructs
    /// the appropriate `HttpAuth` before calling `ExternalServices`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_handle: Option<Handle>,
    pub spec: HttpRequestSpecDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<HttpAuthSpec>,
}

/// Response body for `POST /v1/proxy/http/request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHttpRequestResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Response body; binary bodies are base64-encoded.
    pub body: String,
}

/// Request body for `POST /v1/proxy/http/download`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHttpDownloadRequest {
    pub namespace_id: Uuid,
    /// Optional handle to a vault secret used as auth credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_handle: Option<Handle>,
    pub url: String,
    /// Absolute destination path on the agent's filesystem.
    pub dest_path: String,
}

/// Response body for `POST /v1/proxy/http/download`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHttpDownloadResponse {
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub status: u16,
}

/// Request body for `POST /v1/proxy/http/upload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHttpUploadRequest {
    pub namespace_id: Uuid,
    /// Optional handle to a vault secret used as auth credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_handle: Option<Handle>,
    pub url: String,
    /// Absolute source path on the agent's filesystem.
    pub source_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Response body for `POST /v1/proxy/http/upload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHttpUploadResponse {
    pub status: u16,
    pub bytes_sent: u64,
}

// ---------------------------------------------------------------------------
// Proxy group — Spawn
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/proxy/spawn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySpawnRequest {
    pub namespace_id: Uuid,
    /// Handles to vault secrets injected as environment variables.
    ///
    /// Each handle is decrypted on the agent side; its plaintext is set as
    /// an env var named after the secret's canonical name (handle.secret_name()).
    #[serde(default)]
    pub secret_handles: Vec<Handle>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

/// Response body for `POST /v1/proxy/spawn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySpawnResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

// ---------------------------------------------------------------------------
// Proxy group — Crypto
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/proxy/crypto/sign`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCryptoSignRequest {
    pub namespace_id: Uuid,
    /// Handle to the signing-key secret (Ed25519 32-byte seed).
    pub key_handle: Handle,
    /// Message bytes, base64-encoded.
    pub message_b64: String,
    /// Signing algorithm.
    #[serde(default)]
    pub algorithm: CryptoSignAlgorithm,
}

/// Supported signing algorithms for the proxy crypto/sign endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoSignAlgorithm {
    #[default]
    Ed25519,
    RsaSha256,
}

/// Response body for `POST /v1/proxy/crypto/sign`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCryptoSignResponse {
    /// Signature bytes, base64-encoded.
    pub signature_b64: String,
    /// Algorithm used.
    pub algorithm: String,
}

/// Request body for `POST /v1/proxy/crypto/decrypt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCryptoDecryptRequest {
    pub namespace_id: Uuid,
    /// Handle to the 32-byte AEAD key secret.
    pub key_handle: Handle,
    /// Ciphertext, base64-encoded. Format: `[nonce 24 bytes || ct || tag 16 bytes]`.
    pub ciphertext_b64: String,
    /// Additional associated data, base64-encoded.
    #[serde(default)]
    pub aad_b64: String,
    /// AEAD algorithm identifier (informational; vault uses XChaCha20-Poly1305).
    #[serde(default)]
    pub algorithm: CryptoDecryptAlgorithm,
}

/// Supported AEAD algorithms for the proxy crypto/decrypt endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoDecryptAlgorithm {
    #[default]
    X25519Chacha20poly1305,
}

/// Response body for `POST /v1/proxy/crypto/decrypt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCryptoDecryptResponse {
    /// Decrypted plaintext, base64-encoded.
    pub plaintext_b64: String,
}

#[cfg(test)]
mod tests {
    use super::CreateSessionRequest;

    /// MERK-006: a multibyte `cwd_hash` whose byte index 24 falls inside a
    /// codepoint must not panic. `"a"` (1 byte) followed by 3-byte `"あ"`
    /// codepoints places byte index 24 mid-codepoint, so the old
    /// `&cwd_hash[..24]` byte slice would panic.
    #[test]
    fn cwd_hash_slug_is_char_safe_for_multibyte() {
        let req = CreateSessionRequest {
            cwd_hash: format!("a{}", "あ".repeat(40)),
            namespace_label: None,
            client_pid: None,
        };

        // Must not panic.
        let slug = req.cwd_hash_slug();

        assert_eq!(slug.chars().count(), 24);
        assert!(slug.starts_with('a'));
    }

    /// A shorter-than-24-char `cwd_hash` yields the whole string, no panic.
    #[test]
    fn cwd_hash_slug_handles_short_input() {
        let req = CreateSessionRequest {
            cwd_hash: "abc".into(),
            namespace_label: None,
            client_pid: None,
        };
        assert_eq!(req.cwd_hash_slug(), "abc");
    }
}
