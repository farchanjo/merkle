//! [`AgentProcessHandle`] — spawn, wait, and gracefully kill `merkle-agent`.
#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, bail};
use tokio::process::Command;

/// Max time to wait for the companion socket file to appear.
const SOCKET_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval between socket-existence polls.
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Max time to wait for the agent to exit after SIGTERM.
const KILL_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Locate the `merkle-agent` binary relative to the current test executable.
///
/// When running via `cargo test`, the binary is in the workspace target dir at
/// `<target>/<profile>/merkle-agent`.  The test executable lives in
/// `<target>/<profile>/deps/<test_binary>`, so we step up from `deps/`.
fn agent_bin_path() -> PathBuf {
    let mut p = std::env::current_exe()
        .expect("cannot locate test executable")
        .parent()
        .expect("test exe has no parent")
        .to_path_buf();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("merkle-agent")
}

/// Locate the `merkle` CLI binary relative to the current test executable.
fn cli_bin_path() -> PathBuf {
    let mut p = std::env::current_exe()
        .expect("cannot locate test executable")
        .parent()
        .expect("test exe has no parent")
        .to_path_buf();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("merkle")
}

/// Expose the CLI binary path for use by [`super::cli::CliRunner`].
pub fn locate_cli_bin() -> PathBuf {
    cli_bin_path()
}

/// Handle to a spawned `merkle-agent` process.
///
/// Drop calls `kill_on_drop` so the process is cleaned up automatically.
/// Prefer calling [`kill_graceful`](AgentProcessHandle::kill_graceful) in
/// tests to verify clean shutdown.
pub struct AgentProcessHandle {
    /// Underlying child process.
    child: tokio::process::Child,
    /// Path of the Unix domain socket (created by the agent on startup).
    pub socket_path: PathBuf,
    /// Path of the temp directory holding the SQLite DB.
    pub db_path: PathBuf,
    /// Path of the audit head JSON file.
    pub audit_head_path: PathBuf,
    /// Temp-dir guard — keeps the directory alive for the lifetime of the handle.
    _tempdir: tempfile::TempDir,
}

impl AgentProcessHandle {
    /// Spawn `merkle-agent` with isolated temp paths.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary is not found, cannot be spawned, or the
    /// socket does not appear within 10 seconds.
    pub async fn spawn() -> anyhow::Result<Self> {
        Self::spawn_with_oob_fixture(None).await
    }

    /// Spawn with an optional `MERKLE_OOB_FIXTURE_PATH` env var.
    pub async fn spawn_with_oob_fixture(
        oob_fixture_path: Option<&PathBuf>,
    ) -> anyhow::Result<Self> {
        let agent_bin = agent_bin_path();
        anyhow::ensure!(
            agent_bin.exists(),
            "merkle-agent binary not found at {}: run `cargo build -p merkle-agent` first",
            agent_bin.display()
        );

        let tempdir = tempfile::tempdir().context("create temp dir")?;

        let db_path = tempdir.path().join("vault.db");
        let socket_path = tempdir.path().join("agent.sock");
        let audit_log_path = tempdir.path().join("audit.jsonl");
        let audit_head_path = tempdir.path().join("audit_head.json");

        let database_url = format!("sqlite://{}", db_path.display());

        // Isolate the keystore in the temp dir: force the file backend (the OS
        // keychain probe is unavailable/flaky outside a login session) and
        // supply its passphrase, so the agent never touches the real
        // `~/.local/share/merkle/keystore.age`.
        let keystore_path = tempdir.path().join("keystore.age");

        let mut cmd = Command::new(&agent_bin);
        cmd.env("MERKLE__STORAGE__DATABASE_URL", &database_url)
            .env("MERKLE__STORAGE__AUDIT_LOG_PATH", &audit_log_path)
            .env("MERKLE__STORAGE__AUDIT_HEAD_PATH", &audit_head_path)
            .env("MERKLE__COMPANION_SOCKET__PATH", &socket_path)
            .env("MERKLE__KEYSTORE__BACKEND", "file")
            .env("MERKLE_KEYSTORE_PATH", &keystore_path)
            .env("MERKLE_KEYSTORE_PASSPHRASE", "e2e-test-passphrase")
            // GAP-003: the agent refuses to seed a placeholder recovery
            // recipient; supply a real (test) age recipient so it can build the
            // initial identity.
            .env(
                "MERKLE_RECOVERY_RECIPIENT",
                "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
            )
            .env("MERKLE__METRICS__ENABLED", "false")
            .env("MERKLE__LOGGING__LEVEL", "warn")
            .env("MERKLE__MCP__TRANSPORT", "stdio")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            // Kill child when the handle is dropped (test cleanup).
            .kill_on_drop(true);

        if let Some(fixture_path) = oob_fixture_path {
            cmd.env("MERKLE_OOB_FIXTURE_PATH", fixture_path);
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn merkle-agent: {}", agent_bin.display()))?;

        let handle = Self {
            child,
            socket_path,
            db_path,
            audit_head_path,
            _tempdir: tempdir,
        };

        handle.wait_socket().await?;
        Ok(handle)
    }

    /// Poll for the socket file to appear (up to 10 seconds).
    ///
    /// # Errors
    ///
    /// Returns an error if the socket does not appear within the timeout.
    pub async fn wait_socket(&self) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + SOCKET_WAIT_TIMEOUT;
        loop {
            if self.socket_path.exists() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "timeout waiting for companion socket to appear at {}",
                    self.socket_path.display()
                );
            }
            tokio::time::sleep(SOCKET_POLL_INTERVAL).await;
        }
    }

    /// Send SIGTERM via `kill(1)`, then wait up to 10 seconds for exit.
    ///
    /// Uses the `kill -TERM <pid>` shell command to avoid `unsafe` libc calls.
    ///
    /// # Errors
    ///
    /// Returns an error if the process does not exit within the hard timeout.
    pub async fn kill_graceful(mut self) -> anyhow::Result<()> {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }

        #[cfg(not(unix))]
        {
            let _ = self.child.start_kill();
        }

        let wait = tokio::time::timeout(KILL_WAIT_TIMEOUT, self.child.wait());
        match wait.await {
            Ok(Ok(_status)) => Ok(()),
            Ok(Err(e)) => Err(anyhow::anyhow!("error waiting for agent to exit: {e}")),
            Err(_) => bail!("timeout waiting for merkle-agent to exit after SIGTERM"),
        }
    }

    /// Returns the socket path (convenience accessor for use in tests).
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Returns the audit head JSON path.
    pub fn audit_head_path(&self) -> &PathBuf {
        &self.audit_head_path
    }
}
