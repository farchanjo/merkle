//! CLI configuration: reads `~/.config/merkle/config.toml` (XDG-aware).

use std::path::PathBuf;

use anyhow::Context as _;
use serde::Deserialize;

/// Top-level CLI configuration.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct CliConfig {
    /// Path to the Companion Socket.
    ///
    /// Defaults to:
    /// - macOS: `$TMPDIR/merkle/companion.sock`
    /// - Linux: `$XDG_RUNTIME_DIR/merkle/companion.sock` or `/run/merkle/companion.sock`
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
fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // On macOS, `$TMPDIR` is a per-user temp directory.
        let tmpdir = std::env::var("TMPDIR")
            .map_or_else(|_| PathBuf::from("/tmp"), PathBuf::from);
        tmpdir.join("merkle").join("companion.sock")
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Linux: prefer XDG_RUNTIME_DIR, fall back to /run/merkle.
        std::env::var("XDG_RUNTIME_DIR").map_or_else(
            |_| PathBuf::from("/run/merkle/companion.sock"),
            |runtime| PathBuf::from(runtime).join("merkle").join("companion.sock"),
        )
    }
}
