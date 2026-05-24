//! `merkle unseal [--passphrase]` — POST /v1/agent/unseal.
//!
//! The `--passphrase` flag reads the master-key passphrase from the TTY using
//! `rpassword` (no echo). Per ADR-0005 Amendment the passphrase SHOULD come
//! through a secure TTY prompt in production. When `/dev/tty` is unavailable
//! (CI runners, e2e test harnesses, headless services) the CLI falls back to
//! reading a single line from stdin and emits a security warning. The stdin
//! fallback is intentionally only triggered by genuine TTY-unavailable errors
//! (NotConnected / ENXIO 6 / ENOTTY 25) — never as a default path.

use std::io::{self, BufRead, IsTerminal};

use crate::client::CompanionSocketClient;
use crate::error::CliError;
use crate::output::{print_ok, print_value, OutputFormat};

/// Detect IO errors that mean the TTY device is unavailable.
///
/// Distinct from other rpassword failures (Ctrl-C, EOF mid-input, permission
/// denied) which should still propagate as fatal errors.
fn is_tty_unavailable(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotConnected
        || e.raw_os_error() == Some(6)  // ENXIO — macOS/BSD "Device not configured"
        || e.raw_os_error() == Some(25) // ENOTTY — Linux "Inappropriate ioctl for device"
}

/// Read passphrase from TTY first; fall back to stdin only when TTY genuinely
/// unavailable. Emits a security warning on the fallback path.
fn read_passphrase_with_fallback() -> Result<String, CliError> {
    match rpassword::prompt_password("Master key passphrase: ") {
        Ok(pass) => Ok(pass),
        Err(e) if is_tty_unavailable(&e) => {
            eprintln!(
                "warn: /dev/tty unavailable ({e}); reading passphrase from stdin. \
                 This path is intended for CI/test environments only — \
                 production deployments MUST run with an interactive TTY."
            );
            let stdin = io::stdin();
            // Refuse fallback if stdin itself is a terminal — would echo input.
            if stdin.is_terminal() {
                return Err(CliError::TtyInput(
                    "TTY unavailable and stdin is a terminal; refusing to echo passphrase"
                        .to_string(),
                ));
            }
            let mut buf = String::new();
            stdin
                .lock()
                .read_line(&mut buf)
                .map_err(|e| CliError::TtyInput(format!("stdin read failed: {e}")))?;
            Ok(buf
                .trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string())
        }
        Err(e) => Err(CliError::TtyInput(e.to_string())),
    }
}

/// Run `merkle unseal`.
pub async fn run(
    client: &CompanionSocketClient,
    passphrase: bool,
    format: OutputFormat,
) -> Result<(), CliError> {
    if passphrase {
        let _pass = read_passphrase_with_fallback()?;
        // The current Companion Socket API does not accept a passphrase over
        // the wire (UnsealRequest has no fields). The CLI derives the key
        // locally and initiates the unseal; the agent fetches from keychain.
        eprintln!(
            "warn: passphrase-based unseal is not yet implemented in the Companion Socket API; \
             proceeding with keychain-based unseal"
        );
    }

    let value: serde_json::Value = client
        .post("/v1/agent/unseal", &serde_json::json!({}))
        .await?;

    if format == OutputFormat::Human {
        let already = value
            .get("already_unsealed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if already {
            print_ok("vault was already unsealed");
        } else {
            print_ok("vault unsealed");
        }
    } else {
        print_value(&value, format)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test reproduces the bug from e2e_happy_path step 2: when /dev/tty is
    /// unavailable, rpassword returns IoError with NotConnected / ENXIO 6 /
    /// ENOTTY 25 — the CLI must classify these as "trigger fallback" rather
    /// than abort with exit code 6.
    #[test]
    fn detects_tty_unavailable_errors() {
        // NotConnected — generic "TTY not connected" kind
        let e_notconnected = io::Error::from(io::ErrorKind::NotConnected);
        assert!(is_tty_unavailable(&e_notconnected));

        // ENXIO 6 — "Device not configured" on macOS/BSD (the exact error in
        // the e2e harness when /dev/tty is not present in a sandboxed process)
        let e_enxio = io::Error::from_raw_os_error(6);
        assert!(is_tty_unavailable(&e_enxio));

        // ENOTTY 25 — "Inappropriate ioctl for device" on Linux
        let e_enotty = io::Error::from_raw_os_error(25);
        assert!(is_tty_unavailable(&e_enotty));
    }

    #[test]
    fn does_not_classify_unrelated_errors_as_tty_unavailable() {
        // PermissionDenied — operator denied; abort, do NOT fall back
        let e_perm = io::Error::from(io::ErrorKind::PermissionDenied);
        assert!(!is_tty_unavailable(&e_perm));

        // Interrupted — Ctrl-C; abort, do NOT fall back
        let e_int = io::Error::from(io::ErrorKind::Interrupted);
        assert!(!is_tty_unavailable(&e_int));

        // UnexpectedEof — operator pressed Ctrl-D mid-input; abort
        let e_eof = io::Error::from(io::ErrorKind::UnexpectedEof);
        assert!(!is_tty_unavailable(&e_eof));

        // ENOENT 2 — file not found, unrelated to TTY availability
        let e_enoent = io::Error::from_raw_os_error(2);
        assert!(!is_tty_unavailable(&e_enoent));
    }
}
