//! # merkle-adapter-mcp
//!
//! **Driving-port adapter** — MCP Server via the `rmcp` official Rust SDK
//! (rmcp 0.3).
//!
//! See `docs/arch/adr/0016-rmcp-official-rust-sdk-for-mcp.md`.
//!
//! ## Role
//!
//! One process per MCP client window. Accepts MCP tool calls over stdio
//! (newline-delimited JSON-RPC 2.0), calls `merkle_application` command
//! structs on the shared `AppContext`, and returns the serialised outputs.
//!
//! ## Tools exposed (29 total)
//!
//! Identity (3): `vault.unseal`, `vault.seal`, `vault.bind`
//! Secrets (8): `vault.put`, `vault.get`, `vault.list`, `vault.describe`,
//!               `vault.search`, `vault.rotate`, `vault.delete`, `vault.history`
//! Reveal (1): `vault.reveal`
//! Use-token (4): `vault.use`, `vault.write_tempfile`, `vault.write_fifo`,
//!                `vault.revoke_tempfile`
//! Proxy (11): `vault.ssh.exec`, `vault.ssh.copy`, `vault.ssh.port_forward`,
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
//! use std::sync::Arc;
//! use merkle_adapter_mcp::MerkleMcpServer;
//! use merkle_application::AppContext;
//! use rmcp::ServiceExt as _;
//!
//! async fn run(ctx: Arc<AppContext>) -> anyhow::Result<()> {
//!     // Requires the `transport-io` feature on the `rmcp` crate.
//!     let transport = rmcp::transport::io::stdio();
//!     let server = MerkleMcpServer::new(ctx);
//!     server.serve(transport).await?.waiting().await?;
//!     Ok(())
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod errors;
pub mod session;
pub mod tools;

use std::sync::Arc;

use rmcp::{
    ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::ServerInfo,
    tool_handler,
};
use tokio::sync::RwLock;
use tracing::info;

use merkle_application::AppContext;

pub use session::SessionState;

/// MCP server that exposes all 29 Vault Agent capabilities as MCP tools.
///
/// Wraps the shared `AppContext` and per-session `SessionState`. Constructed
/// once per MCP session (one spawned process = one Claude Code window).
#[derive(Clone, Debug)]
pub struct MerkleMcpServer {
    /// Shared driven-port handles + in-memory vault state.
    pub app_ctx: Arc<AppContext>,
    /// Per-session state: namespace binding, etc.
    pub session: Arc<RwLock<SessionState>>,
    /// The combined `ToolRouter` built from all tool sub-module routers.
    pub(crate) tool_router: ToolRouter<Self>,
}

impl MerkleMcpServer {
    /// Construct a new `MerkleMcpServer` wrapping the given `AppContext`.
    ///
    /// Builds the `ToolRouter` by merging the per-group sub-routers from
    /// each tool sub-module (identity, secrets, reveal, use_token, proxy,
    /// audit, backup, diagnostics).
    #[must_use]
    pub fn new(app_ctx: Arc<AppContext>) -> Self {
        use tools::{
            audit::AuditTools, backup::BackupTools, diagnostics::DiagnosticsTools,
            identity::IdentityTools, proxy::ProxyTools, reveal::RevealTools,
            secrets::SecretsTools, use_token::UseTokenTools,
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
            app_ctx,
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
            capabilities: ServerCapabilities::builder().enable_tools().build(),
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

    async fn on_initialized(
        &self,
        _context: rmcp::service::NotificationContext<rmcp::RoleServer>,
    ) {
        info!("MCP client initialized — Merkle vault adapter ready");
    }
}
