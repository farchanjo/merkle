//! Account-index sentinel logic.
//!
//! The `keyring` crate provides no native `list` operation. To satisfy
//! [`merkle_ports::Keychain::list`] we maintain a **sentinel entry** inside the
//! keychain itself:
//!
//! ```text
//! service  = <caller-service>
//! account  = "<caller-service>__merkle_account_index"
//! payload  = JSON array of account name strings, e.g. ["master-v1","master-v2"]
//! ```
//!
//! Every `store` call adds the account to this index (idempotent).
//! Every `delete` call removes the account from this index.
//! `list` reads and returns the decoded array.
//!
//! Both `OsKeychainAdapter` and `MockKeychainAdapter` delegate index mutations
//! through this module so the sentinel logic stays in one place.

use merkle_ports::KeychainError;

/// Sentinel account-name suffix appended to the service name.
pub(crate) const INDEX_SUFFIX: &str = "__merkle_account_index";

/// Build the sentinel account name for a given service.
pub(crate) fn sentinel_account(service: &str) -> String {
    format!("{service}{INDEX_SUFFIX}")
}

/// Decode the raw bytes stored in the sentinel entry into a list of account
/// names.  An absent entry (empty slice) is treated as an empty list.
pub(crate) fn decode_index(raw: &[u8]) -> Result<Vec<String>, KeychainError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|e| KeychainError::Backend(format!("index decode: {e}")))?;
    match value {
        serde_json::Value::Array(arr) => arr
            .into_iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| KeychainError::Backend("index entry not a string".into()))
            })
            .collect(),
        _ => Err(KeychainError::Backend("index not a JSON array".into())),
    }
}

/// Encode a list of account names into bytes for storage in the sentinel entry.
pub(crate) fn encode_index(accounts: &[String]) -> Result<Vec<u8>, KeychainError> {
    serde_json::to_vec(accounts)
        .map_err(|e| KeychainError::Backend(format!("index encode: {e}")))
}

/// Add `account` to `current` if not already present.
///
/// Returns `true` when the list changed (caller should persist the new index).
pub(crate) fn index_add(current: &mut Vec<String>, account: &str) -> bool {
    if current.iter().any(|a| a == account) {
        return false;
    }
    current.push(account.to_owned());
    true
}

/// Remove `account` from `current`.
///
/// Returns `true` when the list changed (caller should persist the new index).
pub(crate) fn index_remove(current: &mut Vec<String>, account: &str) -> bool {
    let before = current.len();
    current.retain(|a| a != account);
    current.len() != before
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_account_appends_suffix() {
        assert_eq!(
            sentinel_account("dev.fapp.merkle"),
            "dev.fapp.merkle__merkle_account_index"
        );
    }

    #[test]
    fn decode_empty_is_empty_list() {
        assert_eq!(decode_index(b"").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn roundtrip_encode_decode() {
        let accounts = vec!["master-v1".to_owned(), "master-v2".to_owned()];
        let encoded = encode_index(&accounts).unwrap();
        let decoded = decode_index(&encoded).unwrap();
        assert_eq!(decoded, accounts);
    }

    #[test]
    fn index_add_idempotent() {
        let mut list = vec!["a".to_owned()];
        assert!(!index_add(&mut list, "a"), "re-adding existing should be no-op");
        assert_eq!(list.len(), 1);
        assert!(index_add(&mut list, "b"), "adding new should return true");
        assert_eq!(list, ["a", "b"]);
    }

    #[test]
    fn index_remove_returns_changed() {
        let mut list = vec!["a".to_owned(), "b".to_owned()];
        assert!(index_remove(&mut list, "a"));
        assert_eq!(list, ["b"]);
        assert!(!index_remove(&mut list, "z"), "removing absent should be no-op");
    }
}
