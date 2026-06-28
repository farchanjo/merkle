//! MCP prompt catalog — slash commands exposed to MCP clients.
//!
//! Surfaces four user-facing slash commands as MCP prompts so clients such
//! as Claude Code can autocomplete `/mcp__merkle__merkle-reveal`,
//! `/mcp__merkle__merkle-show`, `/mcp__merkle__merkle-rollback`, and
//! `/mcp__merkle__merkle-doctor` from the Vault Agent adapter directly,
//! instead of relying on per-client `~/.claude/commands/*.md` wrappers.
//!
//! Each prompt returns a single user-role text message that instructs the
//! consuming LLM how to chain the relevant `vault.*` tool calls. The
//! `operator_confirmation: true` invariant remains enforced at the server
//! layer via the slash-originated `_meta` flag — these prompts do not
//! bypass it; they only surface the slash literal in the client UI.
//!
//! See `docs/arch/adr/0028-mcp-prompts-for-slash-commands.md`.

use rmcp::{
    ErrorData,
    model::{
        GetPromptRequestParam, GetPromptResult, ListPromptsResult, PaginatedRequestParam, Prompt,
        PromptArgument, PromptMessage, PromptMessageRole,
    },
};

/// Catalog of merkle MCP prompts exposed to clients.
///
/// Each entry maps a slash-command name to a `Prompt` definition (for
/// `prompts/list`) and a body renderer (for `prompts/get`).
#[derive(Debug, Default)]
pub struct MerklePrompts;

impl MerklePrompts {
    /// Build the `ListPromptsResult` returned for every `prompts/list`
    /// request. The catalog is static — pagination is a no-op (no cursor).
    #[must_use]
    pub fn list(_request: Option<PaginatedRequestParam>) -> ListPromptsResult {
        ListPromptsResult {
            next_cursor: None,
            prompts: vec![
                Self::merkle_doctor_def(),
                Self::merkle_show_def(),
                Self::merkle_reveal_def(),
                Self::merkle_rollback_def(),
            ],
        }
    }

    /// Resolve a single `prompts/get` request to a `GetPromptResult`.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorData::invalid_params`] when the prompt name is not
    /// known or a required argument is missing.
    pub fn get(request: GetPromptRequestParam) -> Result<GetPromptResult, ErrorData> {
        let args = request.arguments.unwrap_or_default();
        match request.name.as_str() {
            "merkle-doctor" => Ok(Self::merkle_doctor_body()),
            "merkle-show" => Self::merkle_show_body(&args),
            "merkle-reveal" => Self::merkle_reveal_body(&args),
            "merkle-rollback" => Self::merkle_rollback_body(&args),
            other => Err(ErrorData::invalid_params(
                format!("unknown prompt: {other}"),
                None,
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Prompt definitions (prompts/list)
    // -----------------------------------------------------------------------

    fn merkle_doctor_def() -> Prompt {
        Prompt::new(
            "merkle-doctor",
            Some(
                "Run merkle Vault Agent diagnostic. Reports sealed state, keychain, \
                 DB integrity, audit chain, backup schedule, expiring secrets, disk \
                 space, warnings. No operator confirmation required.",
            ),
            None,
        )
    }

    fn merkle_show_def() -> Prompt {
        Prompt::new(
            "merkle-show",
            Some(
                "Show public metadata for a merkle Secret. No plaintext is returned. \
                 Maps to vault.describe.",
            ),
            Some(vec![PromptArgument {
                name: "handle".to_owned(),
                description: Some(
                    "Secret handle URI (vault://<label>/<category>/<name>).".to_owned(),
                ),
                required: Some(true),
            }]),
        )
    }

    fn merkle_reveal_def() -> Prompt {
        Prompt::new(
            "merkle-reveal",
            Some(
                "Reveal plaintext of a merkle Secret. Requires Operator Confirmation \
                 (slash-invoked _meta flag). May trigger OOB prompt for medium/high \
                 sensitivity.",
            ),
            Some(vec![
                PromptArgument {
                    name: "handle".to_owned(),
                    description: Some(
                        "Secret handle URI (vault://<label>/<category>/<name>).".to_owned(),
                    ),
                    required: Some(true),
                },
                PromptArgument {
                    name: "purpose".to_owned(),
                    description: Some(
                        "Human-readable reason recorded in the audit log.".to_owned(),
                    ),
                    required: Some(false),
                },
            ]),
        )
    }

    fn merkle_rollback_def() -> Prompt {
        Prompt::new(
            "merkle-rollback",
            Some(
                "Roll a merkle Secret back to a previous version. Requires Operator \
                 Confirmation. Creates a new version containing the old value.",
            ),
            Some(vec![
                PromptArgument {
                    name: "handle".to_owned(),
                    description: Some(
                        "Secret handle URI (vault://<label>/<category>/<name>).".to_owned(),
                    ),
                    required: Some(true),
                },
                PromptArgument {
                    name: "version".to_owned(),
                    description: Some("Version number to restore (positive integer).".to_owned()),
                    required: Some(true),
                },
            ]),
        )
    }

    // -----------------------------------------------------------------------
    // Prompt bodies (prompts/get)
    // -----------------------------------------------------------------------

    fn merkle_doctor_body() -> GetPromptResult {
        let text = "Run the merkle Vault Agent diagnostic. Invoke the `vault.doctor` tool \
                    with empty arguments. Report sealed state, keychain reachability, DB \
                    integrity, audit-chain head, backup schedule, expiring secrets, disk \
                    space and any warnings verbatim. No operator confirmation required.";
        Self::single_user_message("Run /merkle-doctor.", text)
    }

    fn merkle_show_body(
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<GetPromptResult, ErrorData> {
        let handle = required_str(args, "handle")?;
        let text = format!(
            "Show the public metadata for the merkle Secret at `{handle}`. Invoke \
             `vault.describe` with arguments `{{ \"handle\": \"{handle}\" }}`. Report \
             category, sensitivity, tags, schema_id, created_at, current version, and \
             expires_at. Plaintext must not be revealed."
        );
        Ok(Self::single_user_message(
            &format!("Run /merkle-show {handle}."),
            &text,
        ))
    }

    fn merkle_reveal_body(
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<GetPromptResult, ErrorData> {
        let handle = required_str(args, "handle")?;
        let purpose = optional_str(args, "purpose").unwrap_or("slash-invoked reveal");
        let text = format!(
            "Reveal the plaintext of the merkle Secret at `{handle}`. Invoke \
             `vault.reveal` with arguments `{{ \"handle\": \"{handle}\", \"purpose\": \
             \"{purpose}\", \"operator_confirmation\": true }}`. If the agent emits an \
             out-of-band confirmation request (medium/high sensitivity or policy-required), \
             wait for the operator acknowledgement before reporting the plaintext. \
             Security invariant: `operator_confirmation: true` is only honored when the \
             /merkle-reveal slash literal was typed by the operator."
        );
        Ok(Self::single_user_message(
            &format!("Run /merkle-reveal {handle} (purpose: {purpose})."),
            &text,
        ))
    }

    fn merkle_rollback_body(
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<GetPromptResult, ErrorData> {
        let handle = required_str(args, "handle")?;
        let version = required_str(args, "version")?;
        let text = format!(
            "Roll the merkle Secret at `{handle}` back to version `{version}`. Steps: \
             (1) invoke `vault.history` with arguments `{{ \"handle\": \"{handle}\" }}` \
             and locate the entry for version `{version}`; (2) invoke `vault.rotate` with \
             arguments `{{ \"handle\": \"{handle}\", \"new_value\": <historical_value>, \
             \"purpose\": \"rollback to version {version}\", \"operator_confirmation\": \
             true }}`. Report the new version metadata (created_at, version_number, \
             audit_event_id). Operator Confirmation is mandatory — rollback overwrites \
             the live value."
        );
        Ok(Self::single_user_message(
            &format!("Run /merkle-rollback {handle} {version}."),
            &text,
        ))
    }

    fn single_user_message(description: &str, body: &str) -> GetPromptResult {
        GetPromptResult {
            description: Some(description.to_owned()),
            messages: vec![PromptMessage::new_text(PromptMessageRole::User, body)],
        }
    }
}

fn required_str(
    args: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, ErrorData> {
    args.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ErrorData::invalid_params(format!("missing required argument: {key}"), None))
}

fn optional_str<'a>(
    args: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    args.get(key).and_then(serde_json::Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with(pairs: &[(&str, &str)]) -> serde_json::Map<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), serde_json::Value::String((*v).to_owned())))
            .collect()
    }

    #[test]
    fn list_returns_four_prompts() {
        let result = MerklePrompts::list(None);
        assert!(result.next_cursor.is_none());
        let names: Vec<&str> = result.prompts.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "merkle-doctor",
                "merkle-show",
                "merkle-reveal",
                "merkle-rollback",
            ],
        );
    }

    #[test]
    fn doctor_get_has_one_user_message() {
        let result = MerklePrompts::get(GetPromptRequestParam {
            name: "merkle-doctor".to_owned(),
            arguments: None,
        })
        .expect("doctor prompt must resolve");
        assert_eq!(result.messages.len(), 1);
        assert!(matches!(result.messages[0].role, PromptMessageRole::User));
    }

    #[test]
    fn show_get_inlines_handle() {
        let args = args_with(&[("handle", "vault://prod/ssh/bastion")]);
        let result = MerklePrompts::get(GetPromptRequestParam {
            name: "merkle-show".to_owned(),
            arguments: Some(args),
        })
        .expect("show prompt must resolve with handle");
        let body = render_user_text(&result);
        assert!(body.contains("vault://prod/ssh/bastion"));
        assert!(body.contains("vault.describe"));
    }

    #[test]
    fn reveal_get_defaults_purpose_when_absent() {
        let args = args_with(&[("handle", "vault://prod/password/db-root")]);
        let result = MerklePrompts::get(GetPromptRequestParam {
            name: "merkle-reveal".to_owned(),
            arguments: Some(args),
        })
        .expect("reveal prompt must resolve");
        let body = render_user_text(&result);
        assert!(body.contains("slash-invoked reveal"));
        assert!(body.contains("\"operator_confirmation\": true"));
    }

    #[test]
    fn reveal_get_uses_custom_purpose_when_present() {
        let args = args_with(&[
            ("handle", "vault://prod/password/db-root"),
            ("purpose", "manual admin reset"),
        ]);
        let result = MerklePrompts::get(GetPromptRequestParam {
            name: "merkle-reveal".to_owned(),
            arguments: Some(args),
        })
        .expect("reveal prompt must resolve");
        let body = render_user_text(&result);
        assert!(body.contains("manual admin reset"));
    }

    #[test]
    fn rollback_get_requires_both_args() {
        let args = args_with(&[("handle", "vault://prod/token/github-ci")]);
        let err = MerklePrompts::get(GetPromptRequestParam {
            name: "merkle-rollback".to_owned(),
            arguments: Some(args),
        })
        .expect_err("rollback must error when version is absent");
        assert!(err.message.contains("version"));
    }

    #[test]
    fn rollback_get_emits_both_tool_calls() {
        let args = args_with(&[("handle", "vault://prod/token/github-ci"), ("version", "2")]);
        let result = MerklePrompts::get(GetPromptRequestParam {
            name: "merkle-rollback".to_owned(),
            arguments: Some(args),
        })
        .expect("rollback prompt must resolve");
        let body = render_user_text(&result);
        assert!(body.contains("vault.history"));
        assert!(body.contains("vault.rotate"));
        assert!(body.contains("rollback to version 2"));
    }

    #[test]
    fn show_get_rejects_missing_handle() {
        let err = MerklePrompts::get(GetPromptRequestParam {
            name: "merkle-show".to_owned(),
            arguments: Some(serde_json::Map::new()),
        })
        .expect_err("show must error when handle missing");
        assert!(err.message.contains("handle"));
    }

    #[test]
    fn get_unknown_prompt_returns_invalid_params() {
        let err = MerklePrompts::get(GetPromptRequestParam {
            name: "merkle-bogus".to_owned(),
            arguments: None,
        })
        .expect_err("unknown prompt must fail");
        assert!(err.message.contains("unknown prompt"));
    }

    fn render_user_text(result: &GetPromptResult) -> String {
        match &result.messages[0].content {
            rmcp::model::PromptMessageContent::Text { text } => text.clone(),
            other => panic!("expected text content, got {other:?}"),
        }
    }
}
