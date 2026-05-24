//! `NoteCategory` — public metadata for `category = "note"` Secrets.
//!
//! Note is a reveal-only category: the FTS5 index does NOT index the note
//! body (which lives in the encrypted `PrivateBlob`). Only `title`, `summary`,
//! `keywords`, and `tags` are indexed.

use serde::{Deserialize, Serialize};

/// MIME content type of the note body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteContentType {
    /// Plain text note.
    #[serde(rename = "text/plain")]
    PlainText,
    /// Markdown note.
    #[serde(rename = "text/markdown")]
    Markdown,
}

/// Public metadata fields for a `note` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/note/note.cue`.
///
/// The full note body lives in the encrypted `PrivateBlob` and is never
/// indexed or returned in list/describe responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCategory {
    /// Human-readable title (safe for the transcript).
    pub title: String,

    /// Content MIME type.
    pub content_type: NoteContentType,

    /// One-line summary safe for the transcript.
    ///
    /// Must not contain credential material. Written by the operator.
    pub summary: String,

    /// Keywords for FTS5 indexing.
    pub keywords: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let cat = NoteCategory {
            title: "Production deployment notes".into(),
            content_type: NoteContentType::Markdown,
            summary: "Steps to deploy the production service".into(),
            keywords: vec!["deploy".into(), "production".into()],
        };
        let json = serde_json::to_string(&cat).expect("serialize");
        let parsed: NoteCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cat, parsed);
    }
}
