//! `AgentConfig` — configuration loaded from TOML + environment overrides.
//!
//! Default path: `~/.config/merkle/config.toml`.
//! The `MERKLE_CONFIG` environment variable overrides the path.
//!
//! ## Environment overlay
//!
//! Every field in the TOML can be overridden by an environment variable
//! following the pattern `MERKLE__SECTION__KEY` (double-underscore as separator).
//! Example: `MERKLE__METRICS__PORT=9200` overrides `[metrics] port`.
//!
//! ## Example `config.toml`
//!
//! ```toml
//! [storage]
//! database_url      = "sqlite:~/.local/share/merkle/vault.db"
//! audit_log_path    = "~/.local/state/merkle/audit.jsonl"
//! audit_head_path   = "~/.local/state/merkle/audit_head.json"
//!
//! [keystore]
//! backend   = "auto"   # "os" | "file" | "auto" (default)
//! # file_path = "~/.local/share/merkle/keystore.age"
//!
//! [companion_socket]
//! path            = "~/.local/run/merkle/agent.sock"
//! max_connections = 100
//!
//! [mcp]
//! transport               = "stdio"
//! session_idle_timeout_secs = 1800
//!
//! [metrics]
//! enabled = true
//! port    = 9117
//! host    = "127.0.0.1"
//!
//! [oob]
//! default_channel        = "desktop-notif"
//! challenge_timeout_secs = 60
//!
//! [security]
//! security_profile = "balanced"
//!
//! [logging]
//! level  = "info"
//! format = "text"
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Full agent configuration, assembled from TOML + environment variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Storage adapter settings.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Keychain / keystore adapter settings (ADR-0022).
    #[serde(default)]
    pub keystore: KeystoreConfig,

    /// Companion Socket settings.
    #[serde(default)]
    pub companion_socket: CompanionSocketConfig,

    /// MCP transport settings.
    #[serde(default)]
    pub mcp: McpConfig,

    /// Prometheus metrics settings.
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Out-of-band notifier settings.
    #[serde(default)]
    pub oob: OobConfig,

    /// Security policy settings.
    #[serde(default)]
    pub security: SecurityConfig,

    /// Logging settings.
    #[serde(default)]
    pub logging: LoggingConfig,
}

// ---------------------------------------------------------------------------
// KeystoreConfig (ADR-0022)
// ---------------------------------------------------------------------------

/// Selects the backing implementation for the [`merkle_ports::Keychain`] port.
///
/// - `Os` — OS-native keychain only (macOS Keychain, Linux Secret Service,
///   Windows Credential Manager). Fails loud on `PersistenceFailed`.
/// - `File` — Age-encrypted file only. Requires `MERKLE_KEYSTORE_PASSPHRASE`
///   or an interactive TTY prompt.
/// - `Auto` — Probe OS keychain first; fall back to file on `PersistenceFailed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeystoreBackend {
    /// Use the OS-native keychain exclusively.
    Os,
    /// Use the age-encrypted file keystore exclusively.
    File,
    /// Auto-probe OS keychain; fall back to file on `PersistenceFailed` (default).
    #[default]
    Auto,
}

/// Configuration for the keychain / keystore adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreConfig {
    /// Which backend to use. Default: `auto`.
    #[serde(default)]
    pub backend: KeystoreBackend,

    /// Override path for the age-encrypted keystore file.
    ///
    /// Resolved when `backend` is `file` or when `auto` falls back to file.
    /// Default: `~/.local/share/merkle/keystore.age` or `$MERKLE_KEYSTORE_PATH`.
    #[serde(default)]
    pub file_path: Option<PathBuf>,
}

impl Default for KeystoreConfig {
    fn default() -> Self {
        Self {
            backend: KeystoreBackend::Auto,
            file_path: None,
        }
    }
}

impl KeystoreConfig {
    /// Resolve the effective keystore file path.
    ///
    /// Priority: `file_path` config field → `$MERKLE_KEYSTORE_PATH` env var →
    /// `~/.local/share/merkle/keystore.age`.
    #[must_use]
    pub fn resolved_file_path(&self) -> PathBuf {
        if let Some(ref p) = self.file_path {
            return p.clone();
        }
        if let Ok(env_path) = std::env::var("MERKLE_KEYSTORE_PATH") {
            return PathBuf::from(env_path);
        }
        xdg_data_home().join("merkle/keystore.age")
    }
}

/// SQLite storage settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// SQLite connection URL (e.g. `sqlite:~/.local/share/merkle/vault.db`).
    #[serde(default = "default_database_url")]
    pub database_url: String,

    /// Path for the JSONL audit log file.
    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: PathBuf,

    /// Path for the audit head JSON file.
    #[serde(default = "default_audit_head_path")]
    pub audit_head_path: PathBuf,
}

fn default_database_url() -> String {
    format!(
        "sqlite://{}",
        xdg_data_home().join("merkle/vault.db").display()
    )
}

fn default_audit_log_path() -> PathBuf {
    xdg_state_home().join("merkle/audit.jsonl")
}

fn default_audit_head_path() -> PathBuf {
    xdg_state_home().join("merkle/audit_head.json")
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_url: default_database_url(),
            audit_log_path: default_audit_log_path(),
            audit_head_path: default_audit_head_path(),
        }
    }
}

/// Companion Socket settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanionSocketConfig {
    /// Unix domain socket path.
    #[serde(default = "default_socket_path")]
    pub path: PathBuf,

    /// Maximum concurrent connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

fn default_socket_path() -> PathBuf {
    xdg_runtime_dir().join("merkle/agent.sock")
}

fn default_max_connections() -> u32 {
    100
}

impl Default for CompanionSocketConfig {
    fn default() -> Self {
        Self {
            path: default_socket_path(),
            max_connections: default_max_connections(),
        }
    }
}

/// MCP transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    /// JSON-RPC 2.0 over stdio (default for Claude Code).
    #[default]
    Stdio,
    /// The MCP adapter is spawned as a subprocess of the agent.
    Subprocess,
}

/// MCP adapter settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Transport mode: `stdio` or `subprocess`.
    #[serde(default)]
    pub transport: McpTransport,

    /// Seconds before an idle MCP session is closed.
    #[serde(default = "default_session_idle_timeout_secs")]
    pub session_idle_timeout_secs: u64,
}

fn default_session_idle_timeout_secs() -> u64 {
    1800
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            transport: McpTransport::Stdio,
            session_idle_timeout_secs: default_session_idle_timeout_secs(),
        }
    }
}

/// Prometheus metrics HTTP server settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable the `/metrics` endpoint.
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,

    /// TCP port to listen on (localhost only).
    #[serde(default = "default_metrics_port")]
    pub port: u16,

    /// Bind host (should always be `127.0.0.1` in production).
    #[serde(default = "default_metrics_host")]
    pub host: String,
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9117
}

fn default_metrics_host() -> String {
    "127.0.0.1".to_owned()
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9117,
            host: "127.0.0.1".to_owned(),
        }
    }
}

/// OOB notifier settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobConfig {
    /// Default channel name when none is specified by the caller.
    #[serde(default = "default_oob_channel")]
    pub default_channel: String,

    /// Seconds before a pending OOB challenge expires.
    #[serde(default = "default_challenge_timeout_secs")]
    pub challenge_timeout_secs: u64,
}

fn default_oob_channel() -> String {
    "desktop-notif".to_owned()
}

fn default_challenge_timeout_secs() -> u64 {
    60
}

impl Default for OobConfig {
    fn default() -> Self {
        Self {
            default_channel: default_oob_channel(),
            challenge_timeout_secs: default_challenge_timeout_secs(),
        }
    }
}

/// Security profile selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecurityProfile {
    /// Relaxed: no OOB for medium-sensitivity reveals; short idle timeout.
    Relaxed,
    /// Balanced: OOB for high-sensitivity reveals; 30-minute idle timeout.
    #[default]
    Balanced,
    /// Paranoid: OOB for all reveals; 5-minute idle timeout; mlock required.
    Paranoid,
}

/// Top-level security settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Active security profile.
    #[serde(default)]
    pub security_profile: SecurityProfile,

    /// Idle re-lock timeout in seconds (overrides profile default when set).
    #[serde(default)]
    pub idle_lock_timeout_secs: Option<u64>,

    /// Re-lock the vault when the OS enters sleep.
    #[serde(default)]
    pub lock_on_sleep: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            security_profile: SecurityProfile::Balanced,
            idle_lock_timeout_secs: None,
            lock_on_sleep: false,
        }
    }
}

/// Logging format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Human-readable text (development).
    #[default]
    Text,
    /// Structured JSON (production / service manager).
    Json,
}

/// Logging settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level directive (e.g. `"info"`, `"merkle=debug,sqlx=warn"`).
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Output format: `text` or `json`.
    #[serde(default)]
    pub format: LogFormat,
}

fn default_log_level() -> String {
    "info".to_owned()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::Text,
        }
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load `AgentConfig` from the default TOML path and environment overrides.
///
/// Resolution order (highest priority first):
/// 1. Environment variables (`MERKLE__SECTION__KEY`).
/// 2. TOML file at `$MERKLE_CONFIG` or `~/.config/merkle/config.toml`.
/// 3. Compiled-in defaults.
///
/// # Errors
///
/// Returns `ConfigError` when the TOML is malformed or a required field
/// cannot be resolved.
pub fn load() -> Result<AgentConfig, ::config::ConfigError> {
    let config_path = std::env::var("MERKLE_CONFIG").map_or_else(
        |_| xdg_config_home().join("merkle/config.toml"),
        PathBuf::from,
    );

    let cfg = ::config::Config::builder()
        .add_source(
            ::config::File::from(config_path)
                .required(false)
                .format(::config::FileFormat::Toml),
        )
        .add_source(
            ::config::Environment::with_prefix("MERKLE")
                .separator("__")
                .try_parsing(true),
        )
        .build()?;

    cfg.try_deserialize()
}

/// Load an `AgentConfig` from a raw TOML string (used in unit tests).
///
/// # Errors
///
/// Returns `ConfigError` when the TOML is malformed.
// Used by unit tests in the cfg(test) block below; the dead_code lint fires
// because test modules are compiled separately under --cfg test.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used only in #[cfg(test)] config tests")
)]
pub fn load_from_str(toml: &str) -> Result<AgentConfig, ::config::ConfigError> {
    let cfg = ::config::Config::builder()
        .add_source(::config::File::from_str(toml, ::config::FileFormat::Toml))
        .build()?;
    cfg.try_deserialize()
}

/// `$HOME` (or `.` when unset).
fn home_dir() -> PathBuf {
    std::env::var("HOME").map_or_else(|_| PathBuf::from("."), PathBuf::from)
}

/// XDG data home — `$XDG_DATA_HOME` or `$HOME/.local/share` per
/// <https://specifications.freedesktop.org/basedir-spec/>.
fn xdg_data_home() -> PathBuf {
    std::env::var("XDG_DATA_HOME").map_or_else(|_| home_dir().join(".local/share"), PathBuf::from)
}

/// XDG state home — `$XDG_STATE_HOME` or `$HOME/.local/state`.
fn xdg_state_home() -> PathBuf {
    std::env::var("XDG_STATE_HOME").map_or_else(|_| home_dir().join(".local/state"), PathBuf::from)
}

/// XDG config home — `$XDG_CONFIG_HOME` or `$HOME/.config`.
fn xdg_config_home() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME").map_or_else(|_| home_dir().join(".config"), PathBuf::from)
}

/// XDG runtime dir — `$XDG_RUNTIME_DIR` or a per-user fallback under
/// `$TMPDIR`/`/tmp`. Used for the Companion Socket (UDS).
fn xdg_runtime_dir() -> PathBuf {
    if let Ok(p) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(p);
    }
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
    let uid = std::env::var("USER").unwrap_or_else(|_| "merkle".to_owned());
    PathBuf::from(tmp).join(format!("merkle-{uid}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_database_url_lands_under_xdg_data_home() {
        // Spec: docstring promises `~/.local/share/merkle/vault.db`. The
        // previous implementation produced `~/share/merkle/...` — bug fix
        // regression guard.
        let url = default_database_url();
        assert!(url.starts_with("sqlite://"), "url={url}");
        let expected_suffix = "/merkle/vault.db";
        assert!(url.ends_with(expected_suffix), "url={url}");
        // Must include the `.local/share` or `XDG_DATA_HOME` segment — never
        // the bare `~/share/...` produced by the old `dirs_base()`.
        let raw_share = format!("{}/share/merkle/", home_dir().display());
        assert!(
            !url.contains(&raw_share),
            "regression: default url falls back to bare $HOME/share/merkle ({url})"
        );
    }

    #[test]
    fn default_audit_paths_land_under_xdg_state_home() {
        let log = default_audit_log_path();
        let head = default_audit_head_path();
        assert!(log.ends_with("merkle/audit.jsonl"), "log={}", log.display());
        assert!(
            head.ends_with("merkle/audit_head.json"),
            "head={}",
            head.display()
        );
        let bare = home_dir().join("state");
        assert!(
            !log.starts_with(&bare),
            "regression: audit log under bare $HOME/state ({})",
            log.display()
        );
    }

    #[test]
    fn default_socket_path_lands_under_xdg_runtime_dir() {
        let p = default_socket_path();
        assert!(p.ends_with("merkle/agent.sock"), "socket={}", p.display());
        let bare = home_dir().join("run");
        assert!(
            !p.starts_with(&bare),
            "regression: socket under bare $HOME/run ({})",
            p.display()
        );
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = AgentConfig {
            storage: StorageConfig::default(),
            keystore: KeystoreConfig::default(),
            companion_socket: CompanionSocketConfig::default(),
            mcp: McpConfig::default(),
            metrics: MetricsConfig::default(),
            oob: OobConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
        };
        assert!(cfg.metrics.enabled);
        assert_eq!(cfg.metrics.port, 9117);
        assert_eq!(cfg.mcp.transport, McpTransport::Stdio);
        assert_eq!(cfg.security.security_profile, SecurityProfile::Balanced);
        assert_eq!(cfg.keystore.backend, KeystoreBackend::Auto);
        assert!(cfg.keystore.file_path.is_none());
    }

    #[test]
    fn keystore_config_defaults_to_auto() {
        let cfg = KeystoreConfig::default();
        assert_eq!(cfg.backend, KeystoreBackend::Auto);
        assert!(cfg.file_path.is_none());
    }

    #[test]
    fn keystore_config_resolved_file_path_uses_config_field_when_set() {
        // When file_path is explicitly set, resolved_file_path returns that value.
        let cfg = KeystoreConfig {
            backend: KeystoreBackend::File,
            file_path: Some(PathBuf::from("/custom/path/keystore.age")),
        };
        let path = cfg.resolved_file_path();
        assert_eq!(path, PathBuf::from("/custom/path/keystore.age"));
    }

    #[test]
    fn keystore_config_resolved_file_path_ends_in_age_when_default() {
        // When file_path is None and $MERKLE_KEYSTORE_PATH is not set (normal CI),
        // the resolved path ends in "keystore.age".
        let cfg = KeystoreConfig::default();
        if std::env::var("MERKLE_KEYSTORE_PATH").is_err() {
            let path = cfg.resolved_file_path();
            assert!(
                path.to_string_lossy().ends_with("keystore.age"),
                "expected path ending in keystore.age, got {path:?}"
            );
        }
    }

    #[test]
    fn load_from_str_minimal() {
        let toml = "[metrics]\nport = 9200\n";
        let cfg = load_from_str(toml).expect("should parse");
        assert_eq!(cfg.metrics.port, 9200);
        // Defaults for other sections.
        assert_eq!(cfg.companion_socket.max_connections, 100);
    }

    #[test]
    fn load_from_str_full() {
        let toml = r#"
[storage]
database_url    = "sqlite:///tmp/test.db"
audit_log_path  = "/tmp/audit.jsonl"
audit_head_path = "/tmp/audit_head.json"

[keystore]
backend   = "file"
file_path = "/tmp/keystore.age"

[companion_socket]
path            = "/tmp/agent.sock"
max_connections = 50

[mcp]
transport                 = "stdio"
session_idle_timeout_secs = 900

[metrics]
enabled = false
port    = 9999
host    = "127.0.0.1"

[oob]
default_channel        = "terminal-prompt"
challenge_timeout_secs = 30

[security]
security_profile      = "paranoid"
idle_lock_timeout_secs = 300
lock_on_sleep         = true

[logging]
level  = "debug"
format = "json"
"#;
        let cfg = load_from_str(toml).expect("should parse");
        assert_eq!(cfg.storage.database_url, "sqlite:///tmp/test.db");
        assert_eq!(cfg.companion_socket.max_connections, 50);
        assert_eq!(cfg.mcp.session_idle_timeout_secs, 900);
        assert!(!cfg.metrics.enabled);
        assert_eq!(cfg.metrics.port, 9999);
        assert_eq!(cfg.security.security_profile, SecurityProfile::Paranoid);
        assert_eq!(cfg.security.idle_lock_timeout_secs, Some(300));
        assert!(cfg.security.lock_on_sleep);
        assert_eq!(cfg.logging.level, "debug");
        assert_eq!(cfg.logging.format, LogFormat::Json);
        assert_eq!(cfg.keystore.backend, KeystoreBackend::File);
        assert_eq!(
            cfg.keystore.file_path,
            Some(PathBuf::from("/tmp/keystore.age"))
        );
    }

    #[test]
    fn load_from_str_keystore_os_backend() {
        let toml = "[keystore]\nbackend = \"os\"\n";
        let cfg = load_from_str(toml).expect("should parse");
        assert_eq!(cfg.keystore.backend, KeystoreBackend::Os);
    }
}
