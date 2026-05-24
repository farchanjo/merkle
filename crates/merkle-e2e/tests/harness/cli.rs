//! [`CliRunner`] — run `merkle` CLI subcommands and capture output.
#![allow(dead_code)]

use std::path::PathBuf;

use anyhow::Context as _;

/// Captured output from a single `merkle` invocation.
#[derive(Debug, Clone)]
pub struct CliOutput {
    /// Standard output (decoded from UTF-8).
    pub stdout: String,
    /// Standard error (decoded from UTF-8).
    pub stderr: String,
    /// Process exit code (`0` on success).
    pub exit_code: i32,
}

impl CliOutput {
    /// Returns `true` when the exit code is zero.
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }

    /// Panics with a descriptive message when the exit code is non-zero.
    #[track_caller]
    pub fn assert_success(self) -> Self {
        assert!(
            self.is_success(),
            "CLI command failed (exit {}):\nstdout: {}\nstderr: {}",
            self.exit_code,
            self.stdout,
            self.stderr,
        );
        self
    }

    /// Assert that stdout or stderr contains `fragment`.
    #[track_caller]
    pub fn assert_output_contains(self, fragment: &str) -> Self {
        let found = self.stdout.contains(fragment) || self.stderr.contains(fragment);
        assert!(
            found,
            "expected output to contain {fragment:?}\nstdout: {}\nstderr: {}",
            self.stdout, self.stderr,
        );
        self
    }
}

/// Runs `merkle` subcommands against a fixed companion socket path.
#[derive(Debug, Clone)]
pub struct CliRunner {
    socket_path: PathBuf,
    cli_bin: PathBuf,
}

impl CliRunner {
    /// Create a runner that dials `socket_path` for every invocation.
    pub fn new(socket_path: PathBuf) -> Self {
        let cli_bin = super::agent_handle::locate_cli_bin();
        Self {
            socket_path,
            cli_bin,
        }
    }

    /// Run `merkle <args...>` with `MERKLE_SOCKET` set.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary cannot be spawned or I/O collection fails.
    pub async fn run(&self, args: &[&str]) -> anyhow::Result<CliOutput> {
        self.run_with_stdin(args, None).await
    }

    /// Run with optional stdin bytes.
    pub async fn run_with_stdin(
        &self,
        args: &[&str],
        stdin_data: Option<&[u8]>,
    ) -> anyhow::Result<CliOutput> {
        let stdin_cfg = if stdin_data.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        };

        anyhow::ensure!(
            self.cli_bin.exists(),
            "merkle CLI binary not found at {}: run `cargo build -p merkle-cli` first",
            self.cli_bin.display()
        );

        let mut child = tokio::process::Command::new(&self.cli_bin)
            .args(args)
            .env("MERKLE_SOCKET", &self.socket_path)
            .env("RUST_LOG", "warn")
            .stdin(stdin_cfg)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn merkle CLI: {}", self.cli_bin.display()))?;

        if let Some(data) = stdin_data {
            use tokio::io::AsyncWriteExt as _;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(data).await.context("write stdin")?;
            }
        }

        let output = child.wait_with_output().await.context("wait for CLI")?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let exit_code = output.status.code().unwrap_or(-1);

        Ok(CliOutput {
            stdout,
            stderr,
            exit_code,
        })
    }
}
