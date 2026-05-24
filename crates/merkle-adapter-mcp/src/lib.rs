//! # merkle-adapter-mcp
//!
//! **Driving-port adapter** — MCP Server via the `rmcp` official Rust SDK
//! (rmcp 0.3).
//!
//! See `docs/arch/adr/0016-rmcp-official-rust-sdk-for-mcp.md`.
//! See `docs/arch/adr/0024-mcp-adapter-consumes-companion-socket-client.md`.
//!
//! ## Role
//!
//! One process per MCP client window. Accepts MCP tool calls over stdio
//! (newline-delimited JSON-RPC 2.0), translates them into typed HTTP calls to
//! the Vault Agent's Companion Socket via [`CompanionSocketClient`], and returns
//! the serialised outputs. No `AppContext` or domain layer is imported.
//!
//! ## Tools exposed (29 total)
//!
//! Identity (3): `vault.unseal`, `vault.seal`, `vault.bind`
//! Secrets (8): `vault.put`, `vault.get`, `vault.list`, `vault.describe`,
//!               `vault.search`, `vault.rotate`, `vault.delete`, `vault.history`
//! Reveal (1): `vault.reveal`
//! Use-token (4): `vault.use`, `vault.write_tempfile`, `vault.write_fifo`,
//!                `vault.revoke_tempfile`
//! Proxy (10): `vault.ssh.exec`, `vault.ssh.copy`, `vault.ssh.port_forward`,
//!              `vault.ssh.shell`, `vault.http.request`, `vault.http.download`,
//!              `vault.http.upload`, `vault.spawn`,
//!              `vault.crypto.sign`, `vault.crypto.decrypt`
//! Audit (1): `vault.audit.query`
//! Backup (2): `vault.backup`, `vault.restore`
//! Diagnostics (1): `vault.doctor`
//!
//! ## Usage
//!
//! ```rust,ignore
//! use std::{path::PathBuf, sync::Arc};
//! use merkle_adapter_mcp::MerkleMcpServer;
//! use merkle_companion_client::CompanionSocketClient;
//! use rmcp::ServiceExt as _;
//!
//! async fn run(socket: PathBuf) -> anyhow::Result<()> {
//!     let client = Arc::new(CompanionSocketClient::new(socket));
//!     let transport = rmcp::transport::io::stdio();
//!     let server = MerkleMcpServer::new(client);
//!     server.serve(transport).await?.waiting().await?;
//!     Ok(())
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod errors;
pub mod prompts;
pub mod session;
pub mod tools;

use std::sync::Arc;

use merkle_companion_client::CompanionSocketClient;
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{
        GetPromptRequestParam, GetPromptResult, ListPromptsResult, PaginatedRequestParam,
        ServerInfo,
    },
    service::RequestContext,
    tool_handler,
};
use tokio::sync::RwLock;
use tracing::info;

pub use prompts::MerklePrompts;
pub use session::SessionState;

/// MCP server that exposes all 29 Vault Agent capabilities as MCP tools.
///
/// Each instance wraps an [`Arc<CompanionSocketClient>`] pointing at the
/// running Vault Agent's Companion Socket, plus per-session [`SessionState`].
/// Constructed once per MCP session (one spawned process = one Claude Code
/// window).
#[derive(Clone, Debug)]
pub struct MerkleMcpServer {
    /// Shared typed client for the Vault Agent Companion Socket.
    pub client: Arc<CompanionSocketClient>,
    /// Per-session state: namespace binding, session ID, etc.
    pub session: Arc<RwLock<SessionState>>,
    /// The combined `ToolRouter` built from all tool sub-module routers.
    pub(crate) tool_router: ToolRouter<Self>,
}

impl MerkleMcpServer {
    /// Construct a new `MerkleMcpServer` targeting the given Companion Socket
    /// client.
    ///
    /// Builds the `ToolRouter` by merging the per-group sub-routers from each
    /// tool sub-module (identity, secrets, reveal, use_token, proxy, audit,
    /// backup, diagnostics).
    #[must_use]
    pub fn new(client: Arc<CompanionSocketClient>) -> Self {
        use tools::{
            audit::AuditTools, backup::BackupTools, diagnostics::DiagnosticsTools,
            identity::IdentityTools, proxy::ProxyTools, reveal::RevealTools, secrets::SecretsTools,
            use_token::UseTokenTools,
        };

        let tool_router = IdentityTools::router()
            + SecretsTools::router()
            + RevealTools::router()
            + UseTokenTools::router()
            + ProxyTools::router()
            + AuditTools::router()
            + BackupTools::router()
            + DiagnosticsTools::router();

        Self {
            client,
            session: Arc::new(RwLock::new(SessionState::default())),
            tool_router,
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MerkleMcpServer {
    fn get_info(&self) -> ServerInfo {
        use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities};
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .build(),
            server_info: Implementation {
                name: "merkle".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            instructions: Some(
                "Merkle Vault Agent MCP adapter. \
                 Call vault.bind to associate a Namespace before using secret tools."
                    .to_owned(),
            ),
        }
    }

    async fn on_initialized(&self, _context: rmcp::service::NotificationContext<rmcp::RoleServer>) {
        info!("MCP client initialized — Merkle vault adapter ready");
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParam>,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Ok(MerklePrompts::list(request))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        MerklePrompts::get(request)
    }
}
