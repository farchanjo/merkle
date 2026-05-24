//! CLI configuration: reads `~/.config/merkle/config.toml` (XDG-aware).

use std::path::PathBuf;

use anyhow::Context as _;
use serde::Deserialize;

/// Top-level CLI configuration.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct CliConfig {
    /// Path to the Companion Socket.
    ///
    /// MUST match `merkle-agent`'s `companion_socket.path` default
    /// (`bin/merkle-agent/src/config.rs::default_socket_path`); a
    /// mismatch silently breaks the CLI with "agent unreachable".
    ///
    /// Defaults to:
    /// - macOS: `$TMPDIR/merkle-$USER/merkle/agent.sock`
    /// - Linux: `$XDG_RUNTIME_DIR/merkle/agent.sock`
    ///   (fallback: `$TMPDIR/merkle-$USER/merkle/agent.sock`)
    #[serde(default)]
    pub socket_path: Option<PathBuf>,

    /// Default output format: `human` | `json` | `plain`.
    /// Reserved for future use when the CLI reads the format from config.
    #[serde(default = "default_output_format")]
    #[expect(dead_code, reason = "future: config-driven output format")]
    pub output_format: String,
}

fn default_output_format() -> String {
    "human".to_owned()
}

impl CliConfig {
    /// Load configuration from the XDG config file.
    ///
    /// Precedence (highest first):
    /// 1. `$MERKLE_CONFIG` env var (path to config file)
    /// 2. `$XDG_CONFIG_HOME/merkle/config.toml`
    /// 3. `~/.config/merkle/config.toml`
    /// 4. Built-in defaults (all fields)
    pub fn load() -> anyhow::Result<Self> {
        let config_path = config_path();

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("reading config file {}", config_path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("parsing config file {}", config_path.display()))
    }

    /// Return the resolved socket path, computing the platform default if not
    /// configured.
    pub fn resolved_socket_path(&self) -> PathBuf {
        self.socket_path.clone().unwrap_or_else(default_socket_path)
    }
}

/// Return the config file path, respecting `$MERKLE_CONFIG` and XDG.
fn config_path() -> PathBuf {
    if let Ok(env_path) = std::env::var("MERKLE_CONFIG") {
        return PathBuf::from(env_path);
    }

    let base = std::env::var("XDG_CONFIG_HOME").map_or_else(
        |_| {
            std::env::var("HOME")
                .map_or_else(|_| PathBuf::from("."), PathBuf::from)
                .join(".config")
        },
        PathBuf::from,
    );

    base.join("merkle").join("config.toml")
}

/// Platform-specific default socket path.
///
/// MUST stay in lock-step with `merkle-agent`'s default in
/// `bin/merkle-agent/src/config.rs::default_socket_path`. Both functions
/// build `<xdg_runtime_dir>/merkle/agent.sock`; the divergence (CLI used
/// `companion.sock`; agent uses `agent.sock`) caused `merkle init` to
/// fail with "agent unreachable" even when the agent was healthy.
fn default_socket_path() -> PathBuf {
    xdg_runtime_dir().join("merkle/agent.sock")
}

/// XDG runtime dir, aligned with the agent helper of the same name.
///
/// Resolution order:
/// 1. `$XDG_RUNTIME_DIR` (Linux: `/run/user/<uid>`).
/// 2. `$TMPDIR/merkle-$USER` (macOS per-user temp; Linux fallback).
/// 3. `/tmp/merkle-merkle` (last-resort fallback).
fn xdg_runtime_dir() -> PathBuf {
    if let Ok(p) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(p);
    }
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
    let uid = std::env::var("USER").unwrap_or_else(|_| "merkle".to_owned());
    PathBuf::from(tmp).join(format!("merkle-{uid}"))
}

#[cfg(test)]
mod tests {
    use super::default_socket_path;

    // Regression guard: the CLI default MUST end in `merkle/agent.sock` —
    // the agent binds that exact filename. A divergence (e.g. the legacy
    // `companion.sock`) silently breaks every CLI command with the
    // misleading "agent unreachable: client error (Connect)" message even
    // when the agent is healthy.
    #[test]
    fn default_socket_filename_is_agent_sock() {
        let p = default_socket_path();
        assert!(
            p.ends_with("merkle/agent.sock"),
            "CLI default socket must end in merkle/agent.sock, got {}",
            p.display()
        );
    }

    #[test]
    fn default_socket_never_uses_legacy_companion_sock() {
        let p = default_socket_path();
        let s = p.display().to_string();
        assert!(
            !s.contains("companion.sock"),
            "regression: CLI still pointing at legacy companion.sock — {s}"
        );
    }
}
