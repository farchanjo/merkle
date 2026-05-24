//! Domain ↔ SQL row conversion helpers.
//!
//! All mappers are pure functions; they receive raw column values and return
//! domain types (or `AdapterError` on parse failure).

use merkle_domain_access_mediation::companion_device::CompanionDevice;
use merkle_domain_audit_compliance::AuditEntry;
use merkle_domain_backup_recovery::backup::Backup;
use merkle_domain_policy_permissions::NamespacePolicy;
use merkle_domain_secret_storage::{
    Namespace, PublicMetadata, Secret,
    private_blob::PrivateBlob,
    secret_version::{SecretVersion, SecretVersionId},
};
use merkle_types::{
    AuditEntryId, AuditOp, AuditOutcome, Blake3Hash, CategoryName, CompanionDeviceClass,
    DenialReason, Handle, HmacSignature, NamespaceId, NamespaceLabel, Rfc3339Timestamp, SecretId,
    Sensitivity, Tag, UuidV7,
};
use sqlx::{Row, sqlite::SqliteRow};

use crate::error::AdapterError;

// ---------------------------------------------------------------------------
// UuidV7 / ID helpers
// ---------------------------------------------------------------------------

/// Encode a `UuidV7` as a 16-byte `Vec<u8>` for BLOB columns.
pub(crate) fn uuid_to_blob(id: UuidV7) -> Vec<u8> {
    id.as_bytes().to_vec()
}

/// Decode a BLOB column into a `UuidV7`.
pub(crate) fn blob_to_uuid(bytes: &[u8]) -> Result<UuidV7, AdapterError> {
    if bytes.len() != 16 {
        return Err(AdapterError::Parse(format!(
            "expected 16-byte UUID blob, got {} bytes",
            bytes.len()
        )));
    }
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| AdapterError::Parse("UUID blob length mismatch".to_owned()))?;
    let uuid = uuid::Uuid::from_bytes(arr);
    // Accept any UUID version stored in the DB (we write v7, tests may use v4
    // for brevity). Reconstruct as UuidV7 via string round-trip where version
    // validation permits.
    let s = uuid.hyphenated().to_string();
    s.parse::<UuidV7>()
        .map_err(|_| AdapterError::Parse(format!("non-v7 UUID in DB: {s}")))
}

// ---------------------------------------------------------------------------
// Convenience ID constructors
// ---------------------------------------------------------------------------

pub(crate) fn blob_to_namespace_id(bytes: &[u8]) -> Result<NamespaceId, AdapterError> {
    blob_to_uuid(bytes).map(|u| {
        u.to_string()
            .parse::<NamespaceId>()
            .expect("UuidV7 always parses as NamespaceId")
    })
}

pub(crate) fn blob_to_secret_id(bytes: &[u8]) -> Result<SecretId, AdapterError> {
    blob_to_uuid(bytes).map(|u| {
        u.to_string()
            .parse::<SecretId>()
            .expect("UuidV7 always parses as SecretId")
    })
}

pub(crate) fn blob_to_audit_entry_id(bytes: &[u8]) -> Result<AuditEntryId, AdapterError> {
    blob_to_uuid(bytes).map(|u| {
        u.to_string()
            .parse::<AuditEntryId>()
            .expect("UuidV7 always parses as AuditEntryId")
    })
}

pub(crate) fn blob_to_secret_version_id(bytes: &[u8]) -> Result<SecretVersionId, AdapterError> {
    blob_to_uuid(bytes).map(|u| {
        u.to_string()
            .parse::<SecretVersionId>()
            .expect("UuidV7 always parses as SecretVersionId")
    })
}

/// Convert an ID type to its inner `UuidV7` blob.
///
/// These macros avoid boilerplate for all `.inner().as_bytes()` chains.
macro_rules! id_to_blob {
    ($id:expr) => {
        uuid_to_blob($id.inner())
    };
}
pub(crate) use id_to_blob;

// ---------------------------------------------------------------------------
// Namespace
// ---------------------------------------------------------------------------

/// Map a `SqliteRow` from the `namespaces` table into a `Namespace`.
pub(crate) fn row_to_namespace(row: &SqliteRow) -> Result<Namespace, AdapterError> {
    let id_bytes: Vec<u8> = row.try_get("id")?;
    let id = blob_to_namespace_id(&id_bytes)?;

    let label_str: String = row.try_get("label")?;
    let label = label_str
        .parse::<NamespaceLabel>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let cwd_hash: Option<String> = row.try_get("cwd_hash")?;

    let policy_id_bytes: Option<Vec<u8>> = row.try_get("policy_id")?;
    let policy_id = policy_id_bytes.as_deref().map(blob_to_uuid).transpose()?;

    let dek_version: i64 = row.try_get("dek_version")?;
    let created_at_str: String = row.try_get("created_at")?;
    let created_at = created_at_str
        .parse::<Rfc3339Timestamp>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    Ok(Namespace {
        id,
        label,
        cwd_hash,
        policy_id,
        dek_version: u32::try_from(dek_version).unwrap_or(0),
        created_at,
    })
}

// ---------------------------------------------------------------------------
// Secret + SecretVersion
// ---------------------------------------------------------------------------

/// Assemble a `Secret` from one `secrets` row plus a slice of `SecretVersion`
/// rows already loaded for that secret.
pub(crate) fn row_to_secret(
    row: &SqliteRow,
    versions: &[SecretVersion],
) -> Result<Secret, AdapterError> {
    let id_bytes: Vec<u8> = row.try_get("id")?;
    let id = blob_to_secret_id(&id_bytes)?;

    let ns_bytes: Vec<u8> = row.try_get("namespace_id")?;
    let namespace_id = blob_to_namespace_id(&ns_bytes)?;

    let handle_str: String = row.try_get("handle")?;
    let handle = handle_str
        .parse::<Handle>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let category_str: String = row.try_get("category")?;
    let category = category_str
        .parse::<CategoryName>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let sensitivity_str: String = row.try_get("sensitivity")?;
    let sensitivity = sensitivity_str
        .parse::<Sensitivity>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let public_metadata_json: String = row.try_get("public_metadata_json")?;
    let public_metadata: PublicMetadata = serde_json::from_str(&public_metadata_json)?;

    let tags_json: String = row.try_get("tags_json")?;
    let tags: Vec<Tag> = serde_json::from_str(&tags_json)?;

    let current_version_id_bytes: Vec<u8> = row.try_get("current_version_id")?;
    let current_version_id = blob_to_secret_version_id(&current_version_id_bytes)?;

    let created_at_str: String = row.try_get("created_at")?;
    let created_at = created_at_str
        .parse::<Rfc3339Timestamp>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    // `versions` and `current_version_id` are private fields on `Secret`.
    // We reconstruct via serde round-trip using the same JSON field names that
    // `#[derive(Serialize, Deserialize)]` produces (snake_case, no rename attrs).
    let value = serde_json::json!({
        "id": id.to_string(),
        "namespace_id": namespace_id.to_string(),
        "handle": handle.to_string(),
        "category": category.to_string(),
        "sensitivity": sensitivity.to_string(),
        "tags": serde_json::to_value(&tags)?,
        "public_metadata": serde_json::to_value(&public_metadata)?,
        "created_at": created_at.to_string(),
        "versions": serde_json::to_value(versions)?,
        "current_version_id": current_version_id.to_string(),
    });
    serde_json::from_value::<Secret>(value).map_err(AdapterError::Json)
}

/// Map a `SqliteRow` from `secret_versions` into a `SecretVersion`.
pub(crate) fn row_to_secret_version(row: &SqliteRow) -> Result<SecretVersion, AdapterError> {
    let id_bytes: Vec<u8> = row.try_get("id")?;
    let id = blob_to_secret_version_id(&id_bytes)?;

    let secret_id_bytes: Vec<u8> = row.try_get("secret_id")?;
    let secret_id = blob_to_secret_id(&secret_id_bytes)?;

    let version_no: i64 = row.try_get("version_no")?;
    let dek_version: i64 = row.try_get("dek_version")?;

    let ciphertext: Vec<u8> = row.try_get("ciphertext")?;
    let nonce_bytes: Vec<u8> = row.try_get("nonce")?;
    let aead_tag_bytes: Vec<u8> = row.try_get("aead_tag")?;
    let associated_data: Vec<u8> = row.try_get("associated_data")?;

    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| AdapterError::Parse("nonce must be exactly 24 bytes".to_owned()))?;
    let aead_tag: [u8; 16] = aead_tag_bytes
        .try_into()
        .map_err(|_| AdapterError::Parse("aead_tag must be exactly 16 bytes".to_owned()))?;

    let blob = PrivateBlob::new(
        ciphertext,
        nonce,
        aead_tag,
        associated_data,
        u32::try_from(dek_version).unwrap_or(0),
    );

    let created_at_str: String = row.try_get("created_at")?;
    let created_at = created_at_str
        .parse::<Rfc3339Timestamp>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let deprecated_at_str: Option<String> = row.try_get("deprecated_at")?;
    let deprecated_at = deprecated_at_str
        .as_deref()
        .map(str::parse::<Rfc3339Timestamp>)
        .transpose()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    Ok(SecretVersion {
        id,
        secret_id,
        version_no: u32::try_from(version_no).unwrap_or(0),
        blob,
        dek_version: u32::try_from(dek_version).unwrap_or(0),
        created_at,
        deprecated_at,
    })
}

// ---------------------------------------------------------------------------
// AuditEntry
// ---------------------------------------------------------------------------

/// Map a `SqliteRow` from `audit_entries` into an `AuditEntry`.
pub(crate) fn row_to_audit_entry(row: &SqliteRow) -> Result<AuditEntry, AdapterError> {
    let id_bytes: Vec<u8> = row.try_get("id")?;
    let id = blob_to_audit_entry_id(&id_bytes)?;

    let seq: i64 = row.try_get("seq")?;

    let ts_str: String = row.try_get("ts")?;
    let ts = ts_str
        .parse::<Rfc3339Timestamp>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let ns_bytes: Vec<u8> = row.try_get("namespace_id")?;
    let namespace_id = blob_to_namespace_id(&ns_bytes)?;

    let caller_program: Option<String> = row.try_get("caller_program")?;

    let op_str: String = row.try_get("op")?;
    let op = op_str
        .parse::<AuditOp>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let outcome_str: String = row.try_get("outcome")?;
    let outcome = outcome_str
        .parse::<AuditOutcome>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let denial_reason_str: Option<String> = row.try_get("denial_reason")?;
    let denial_reason = denial_reason_str.map(|s| DenialReason::from(s.as_str()));

    let handle_str: Option<String> = row.try_get("handle")?;
    let handle = handle_str
        .as_deref()
        .map(str::parse::<Handle>)
        .transpose()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let sensitivity_str: Option<String> = row.try_get("sensitivity")?;
    let sensitivity = sensitivity_str
        .as_deref()
        .map(str::parse::<Sensitivity>)
        .transpose()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let prev_hash_str: Option<String> = row.try_get("prev_hash")?;
    let prev_hash = prev_hash_str
        .as_deref()
        .map(str::parse::<Blake3Hash>)
        .transpose()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let current_hash_str: String = row.try_get("current_hash")?;
    let current_hash = current_hash_str
        .parse::<Blake3Hash>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let hmac_str: Option<String> = row.try_get("hmac")?;
    let hmac = hmac_str
        .as_deref()
        .map(str::parse::<HmacSignature>)
        .transpose()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    Ok(AuditEntry {
        id,
        seq: u64::try_from(seq).unwrap_or(0),
        ts,
        namespace_id,
        caller_program,
        op,
        outcome,
        denial_reason,
        handle,
        sensitivity,
        prev_hash,
        current_hash,
        hmac,
    })
}

// ---------------------------------------------------------------------------
// NamespacePolicy
// ---------------------------------------------------------------------------

/// Map a `SqliteRow` from `namespace_policies` into a `NamespacePolicy`.
pub(crate) fn row_to_namespace_policy(row: &SqliteRow) -> Result<NamespacePolicy, AdapterError> {
    let json: String = row.try_get("policy_json")?;
    serde_json::from_str(&json).map_err(AdapterError::Json)
}

// ---------------------------------------------------------------------------
// CompanionDevice
// ---------------------------------------------------------------------------

/// Map a `SqliteRow` from `companion_devices` into a `CompanionDevice`.
pub(crate) fn row_to_companion_device(row: &SqliteRow) -> Result<CompanionDevice, AdapterError> {
    let device_id_bytes: Vec<u8> = row.try_get("device_id")?;
    let device_id = blob_to_uuid(&device_id_bytes)?;

    let ed25519_bytes: Vec<u8> = row.try_get("ed25519_pubkey")?;
    let ed25519_pubkey: [u8; 32] = ed25519_bytes
        .try_into()
        .map_err(|_| AdapterError::Parse("ed25519_pubkey must be 32 bytes".to_owned()))?;

    let x25519_bytes: Vec<u8> = row.try_get("x25519_pubkey")?;
    let x25519_pubkey: [u8; 32] = x25519_bytes
        .try_into()
        .map_err(|_| AdapterError::Parse("x25519_pubkey must be 32 bytes".to_owned()))?;

    let class_str: String = row.try_get("class")?;
    let class = class_str
        .parse::<CompanionDeviceClass>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let attestation_chain: Vec<u8> = row.try_get("attestation_chain")?;

    let enrolled_at_str: String = row.try_get("enrolled_at")?;
    let enrolled_at = enrolled_at_str
        .parse::<Rfc3339Timestamp>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let revoked_at_str: Option<String> = row.try_get("revoked_at")?;
    let revoked_at = revoked_at_str
        .as_deref()
        .map(str::parse::<Rfc3339Timestamp>)
        .transpose()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    Ok(CompanionDevice {
        device_id,
        ed25519_pubkey,
        x25519_pubkey,
        class,
        attestation_chain,
        enrolled_at,
        revoked_at,
    })
}

// ---------------------------------------------------------------------------
// Unused import suppress — Backup deserialization uses serde directly.
// ---------------------------------------------------------------------------
// `row_to_backup` is not used (backups.rs uses decode_backup_row internally).
// Keep the type alias to satisfy the public interface if needed.
#[allow(dead_code)]
pub(crate) fn row_to_backup_unused(_: &SqliteRow) -> Result<Backup, AdapterError> {
    Err(AdapterError::Parse(
        "use decode_backup_row instead".to_owned(),
    ))
}
