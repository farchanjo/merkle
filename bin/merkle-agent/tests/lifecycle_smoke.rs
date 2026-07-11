//! Lifecycle smoke tests for `merkle-agent`.
//!
//! These tests spawn the agent as a subprocess, verify that it binds the
//! Companion Socket, and confirm that SIGTERM triggers a clean shutdown within
//! 10 seconds.
//!
//! All tests in this file are marked `#[ignore]` because they:
//! 1. Require the binary to have been built (`cargo build -p merkle-agent`).
//! 2. Bind Unix sockets and interact with the OS keychain / filesystem.
//! 3. Are inherently flaky in sandboxed CI environments.
//!
//! Run manually with:
//! ```sh
//! cargo test -p merkle-agent -- --ignored --nocapture
//! ```

#[cfg(unix)]
mod unix_tests {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// Path to the compiled agent binary.
    fn agent_bin() -> PathBuf {
        // When running via `cargo test`, the binary is in the workspace target dir.
        let mut p = std::env::current_exe()
            .expect("cannot locate test executable")
            .parent()
            .expect("test exe has no parent")
            .to_path_buf();
        // Step from `deps/` up to `debug/` or `release/`.
        if p.ends_with("deps") {
            p.pop();
        }
        p.join("merkle-agent")
    }

    /// Write a minimal config TOML to a temp directory and return its path.
    fn write_temp_config(dir: &tempfile::TempDir) -> PathBuf {
        let sock_path = dir.path().join("agent.sock");
        let db_path = dir.path().join("vault.db");
        let audit_log = dir.path().join("audit.jsonl");
        let audit_head = dir.path().join("audit_head.json");
        let keystore = dir.path().join("keystore.age");
        let cfg_path = dir.path().join("config.toml");

        let toml = format!(
            r"
[storage]
database_url    = {db:?}
audit_log_path  = {audit_log:?}
audit_head_path = {audit_head:?}

[companion_socket]
path = {sock:?}

[keystore]
backend   = 'file'
file_path = {keystore:?}

[metrics]
enabled = false
port    = 0
host    = '127.0.0.1'

[logging]
level  = 'warn'
format = 'text'
",
            db = db_path.display().to_string(),
            audit_log = audit_log.display().to_string(),
            audit_head = audit_head.display().to_string(),
            sock = sock_path.display().to_string(),
            keystore = keystore.display().to_string(),
        );

        std::fs::write(&cfg_path, toml).expect("failed to write temp config");
        cfg_path
    }

    /// Wait until `path` exists on the filesystem or `timeout` elapses.
    fn wait_for_path(path: &Path, timeout: Duration) -> bool {
        let start = Instant::now();
        loop {
            if path.exists() {
                return true;
            }
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Send SIGTERM to a process by PID using `kill(1)` subprocess.
    ///
    /// This avoids unsafe libc calls while still sending a real SIGTERM.
    fn sigterm(pid: u32) {
        // `kill -TERM <pid>` is universally available on POSIX systems.
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }

    #[test]
    #[ignore = "requires built binary and OS socket support; run manually"]
    fn agent_binds_companion_socket_and_sigterm_shuts_down() {
        let bin = agent_bin();
        assert!(
            bin.exists(),
            "merkle-agent binary not found at {}: run `cargo build -p merkle-agent` first",
            bin.display()
        );

        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = write_temp_config(&tmp);
        let sock_path = tmp.path().join("agent.sock");

        let keystore_path = tmp.path().join("keystore.age");
        let stderr_path = tmp.path().join("agent.stderr");
        let stderr_file = std::fs::File::create(&stderr_path).expect("create stderr log");

        // Spawn the agent.
        //
        // Force file keystore via env: the config crate overlays
        // `MERKLE__KEYSTORE__BACKEND` over the TOML, and developer shells often
        // export `=os` (login keychain). Without the override the agent hangs
        // on the OS keychain and never binds the socket.
        let mut child = Command::new(&bin)
            .arg("--config")
            .arg(&cfg_path)
            .env("MERKLE__KEYSTORE__BACKEND", "file")
            .env("MERKLE_KEYSTORE_PATH", &keystore_path)
            .env("MERKLE_KEYSTORE_PASSPHRASE", "lifecycle-test-pass")
            .env("MERKLE__METRICS__ENABLED", "false")
            .env(
                "MERKLE_RECOVERY_RECIPIENT",
                "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
            )
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .expect("failed to spawn merkle-agent");

        // Wait up to 15 s for the Companion Socket to appear (cold debug binary).
        let socket_bound = wait_for_path(&sock_path, Duration::from_secs(15));
        if !socket_bound {
            let _ = child.kill();
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!(
                "companion socket did not appear at {} within 15 s\nagent stderr:\n{stderr}",
                sock_path.display()
            );
        }

        // Send SIGTERM to trigger graceful shutdown.
        sigterm(child.id());

        // Wait up to 10 s for the process to exit cleanly.
        let start = Instant::now();
        loop {
            match child.try_wait().expect("try_wait failed") {
                Some(status) => {
                    assert!(
                        status.success(),
                        "agent exited with non-zero status: {status}"
                    );
                    break;
                }
                None if start.elapsed() >= Duration::from_secs(10) => {
                    child.kill().ok();
                    panic!("agent did not exit within 10 s after SIGTERM");
                }
                None => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }
}
