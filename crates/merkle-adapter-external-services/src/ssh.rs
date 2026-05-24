//! SSH exec implementation using `tokio::process::Command` + a short-lived
//! identity tempfile.
//!
//! The private key material is written to a `tempfile::NamedTempFile` with
//! mode `0600`, passed to `ssh -i <path>`, and the file is removed when the
//! `NamedTempFile` guard is dropped (which happens before this function
//! returns, regardless of the command outcome).
//!
//! Key material never appears in the `ssh` command-line arguments; it only
//! touches the filesystem for the lifetime of the subprocess.

use std::time::Duration;

use tempfile::NamedTempFile;
use tokio::{io::AsyncWriteExt as _, process::Command, time::timeout};
use tracing::{debug, warn};

use merkle_ports::{ExternalError, SshExecOutput};

/// Default wall-clock limit for the entire SSH exec operation.
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Execute `command` on `target` (user@host or host) using `key_material` as
/// the SSH private key.
///
/// # Algorithm
///
/// 1. Write `key_material` to a temporary file with mode `0600`.
/// 2. Build: `ssh -i <tmpfile> -o BatchMode=yes -o StrictHostKeyChecking=accept-new <target> <command>`.
/// 3. Spawn via `tokio::process::Command`, capturing stdout + stderr.
/// 4. Await the process, bounded by `timeout_secs`.
/// 5. Return `SshExecOutput`; tempfile is dropped (unlinked) automatically.
pub(crate) async fn ssh_exec(
    target: &str,
    key_material: &[u8],
    command: &str,
    timeout_secs: Duration,
) -> Result<SshExecOutput, ExternalError> {
    let identity_file = write_identity(key_material).await?;

    debug!(
        target = %target,
        command = %command,
        identity_path = %identity_file.path().display(),
        "spawning ssh subprocess"
    );

    let child_result = timeout(timeout_secs, run_ssh(target, identity_file.path(), command)).await;

    // identity_file is dropped (unlinked) here regardless of the outcome.
    drop(identity_file);

    match child_result {
        Ok(inner) => inner,
        Err(_elapsed) => {
            warn!(target = %target, command = %command, "ssh exec timed out");
            Err(ExternalError::OperationFailed(format!(
                "ssh exec timed out after {}s",
                timeout_secs.as_secs()
            )))
        }
    }
}

/// Write `key_material` to a new `NamedTempFile` with mode `0600`.
async fn write_identity(key_material: &[u8]) -> Result<NamedTempFile, ExternalError> {
    // NamedTempFile::new() is synchronous (single syscall); acceptable on the
    // async executor for this brief operation.
    let mut file = NamedTempFile::new().map_err(|e| {
        ExternalError::Backend(format!("failed to create identity tempfile: {e}"))
    })?;

    // Restrict permissions to owner-read-write only (0600) before writing.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|e| ExternalError::Backend(format!("chmod 0600 on identity file: {e}")))?;
    }

    // Write key material via the async handle for Tokio-friendliness.
    let std_file = file
        .as_file_mut()
        .try_clone()
        .map_err(|e| ExternalError::Backend(format!("clone identity file: {e}")))?;
    let mut async_file = tokio::fs::File::from_std(std_file);
    async_file
        .write_all(key_material)
        .await
        .map_err(|e| ExternalError::Backend(format!("write identity file: {e}")))?;
    async_file
        .flush()
        .await
        .map_err(|e| ExternalError::Backend(format!("flush identity file: {e}")))?;

    Ok(file)
}

/// Spawn the ssh subprocess and collect its output.
async fn run_ssh(
    target: &str,
    identity_path: &std::path::Path,
    command: &str,
) -> Result<SshExecOutput, ExternalError> {
    let output = Command::new("ssh")
        .arg("-i")
        .arg(identity_path)
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("--")
        .arg(target)
        .arg(command)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ExternalError::ConnectFailed("ssh binary not found in PATH".to_owned())
            } else {
                ExternalError::ConnectFailed(format!("failed to spawn ssh: {e}"))
            }
        })?;

    let exit_code = output.status.code().unwrap_or(-1);

    debug!(
        target = %target,
        command = %command,
        exit_code,
        stdout_bytes = output.stdout.len(),
        stderr_bytes = output.stderr.len(),
        "ssh subprocess finished"
    );

    Ok(SshExecOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code,
    })
}
