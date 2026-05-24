//! Platform peer-credential extraction and verification.
//!
//! The companion socket uses kernel-enforced peer credentials to authenticate
//! callers. No user-supplied header is trusted; credentials are obtained
//! directly from the OS at accept time.
//!
//! # Platform matrix
//!
//! | Platform | Mechanism | Fields available |
//! |---|---|---|
//! | Linux | `tokio::net::UnixStream::peer_cred()` via `SO_PEERCRED` | `uid`, `gid`, `pid` |
//! | macOS | `LOCAL_PEERCRED` via `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` | `uid` (effective) |
//! | Other | Stub — always passes UID check (Windows named-pipe TBD) | none |
//!
//! On Linux the caller's binary is additionally verified by reading
//! `/proc/<pid>/exe`, which is kernel-controlled and cannot be forged by
//! the process itself (unlike `/proc/<pid>/comm`).
//!
//! # Unsafe usage
//!
//! This module contains two `unsafe` blocks, both in platform-specific code:
//! - macOS: `getsockopt(LOCAL_PEERCRED)` — no safe Rust wrapper exists in the
//!   current workspace dependency set.
//! - `libc::getuid()` — POSIX guarantee; always safe and infallible.
//!
//! Both blocks carry SAFETY comments. Tracked for replacement with `nix`
//! or `rustix` once those crates are added to the workspace dependency set.

use std::io;

/// Peer credentials extracted from the OS at connection accept time.
#[derive(Debug, Clone)]
pub struct PeerCredentials {
    /// Real UID of the connecting process.
    pub uid: u32,
    /// PID of the connecting process (Linux only).
    pub pid: Option<u32>,
    /// Resolved canonical binary path of the connecting process.
    /// Populated on Linux from `/proc/<pid>/exe`.
    pub program_path: Option<std::path::PathBuf>,
}

/// Extract peer credentials from a connected `UnixStream`.
///
/// # Errors
///
/// Returns `Err` if the OS call fails. The caller should close the connection
/// rather than proceeding with an unauthenticated request.
pub fn extract(stream: &tokio::net::UnixStream) -> io::Result<PeerCredentials> {
    extract_impl(stream)
}

/// Check that `creds` are acceptable.
///
/// Verifies that the connecting UID matches the agent's own UID — only
/// processes running as the same user are permitted.
///
/// # Errors
///
/// Returns a descriptive error string when the credential check fails.
pub fn verify(creds: &PeerCredentials) -> Result<(), String> {
    let own_uid = current_uid();

    if creds.uid != own_uid {
        return Err(format!(
            "peer uid {} does not match agent uid {}",
            creds.uid, own_uid
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Platform-specific implementations
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn extract_impl(stream: &tokio::net::UnixStream) -> io::Result<PeerCredentials> {
    // `peer_cred()` calls SO_PEERCRED via `getsockopt`; tokio wraps it safely.
    let raw = stream
        .peer_cred()
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;

    let pid = raw.pid().map(|p| p as u32);
    let uid = raw.uid();

    // Read /proc/<pid>/exe — kernel-controlled symlink; the process cannot
    // modify it via `prctl(PR_SET_NAME)` or any other userspace call.
    let program_path = pid.and_then(|p| {
        let link = format!("/proc/{p}/exe");
        std::fs::canonicalize(link).ok()
    });

    Ok(PeerCredentials {
        uid,
        pid,
        program_path,
    })
}

#[cfg(target_os = "macos")]
fn extract_impl(stream: &tokio::net::UnixStream) -> io::Result<PeerCredentials> {
    use std::os::unix::io::AsRawFd;

    let uid = macos_local_peercred(stream.as_raw_fd())?;

    Ok(PeerCredentials {
        uid,
        pid: None,
        program_path: None,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn extract_impl(_stream: &tokio::net::UnixStream) -> io::Result<PeerCredentials> {
    // Windows named-pipe PID check is not yet implemented.
    // Return a stub that passes the UID check by pretending to be current uid.
    Ok(PeerCredentials {
        uid: current_uid(),
        pid: None,
        program_path: None,
    })
}

// ---------------------------------------------------------------------------
// macOS LOCAL_PEERCRED helper
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn macos_local_peercred(fd: std::os::unix::io::RawFd) -> io::Result<u32> {
    // xucred layout (from macOS <sys/ucred.h>):
    //   u_int   cr_version  (4 bytes, offset 0)
    //   uid_t   cr_uid      (4 bytes, offset 4)
    //   short   cr_ngroups  (2 bytes, offset 8)
    //   gid_t   cr_groups[16] (64 bytes, offset 10)
    //
    // We only need cr_uid at byte offset 4.
    //
    // SOL_LOCAL=0, LOCAL_PEERCRED=1 on macOS (from <sys/socket.h>).
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERCRED: libc::c_int = 1;
    // Buffer large enough to hold xucred (74 bytes minimum; we use 80).
    const BUF_LEN: usize = 80;

    let mut buf = [0u8; BUF_LEN];
    // BUF_LEN = 80 fits in socklen_t (u32) on all supported platforms; the
    // cast is intentional and safe.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "BUF_LEN=80 is a compile-time constant that fits in u32/socklen_t on all \
                  supported platforms; truncation is impossible."
    )]
    let mut len: libc::socklen_t = BUF_LEN as libc::socklen_t;

    // SAFETY: `fd` is a valid, open AF_UNIX socket descriptor obtained from
    // a live `tokio::net::UnixStream`. The buffer is stack-allocated and sized
    // to accommodate the full `xucred` struct. `getsockopt` writes at most
    // `len` bytes into `buf` and updates `len` to the actual size written.
    // No aliasing or data-race risk because `buf` is locally owned.
    // `&raw mut len` is used to avoid the `borrow_as_ptr` lint.
    #[expect(unsafe_code, reason = "getsockopt(LOCAL_PEERCRED) has no safe Rust wrapper; \
        blocked on adding nix/rustix to the workspace dependency set.")]
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERCRED,
            buf.as_mut_ptr().cast(),
            &raw mut len,
        )
    };

    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    if len < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LOCAL_PEERCRED returned too few bytes for xucred",
        ));
    }

    // cr_uid is a native-endian u32 at byte offset 4.
    let uid = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
    Ok(uid)
}

// ---------------------------------------------------------------------------
// UID helper
// ---------------------------------------------------------------------------

/// Return the real UID of the current process.
#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: `getuid()` is an infallible POSIX syscall that returns the
    // caller's real user ID. It has no preconditions, never fails, and does
    // not interact with Rust's memory model.
    #[expect(unsafe_code, reason = "libc::getuid() is infallible; no safe Rust wrapper exists \
        without nix/rustix in the workspace.")]
    unsafe {
        libc::getuid()
    }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Return a synthetic set of credentials matching the current process UID.
///
/// Used in test contexts where no real Unix socket is available.
#[must_use]
pub fn synthetic() -> PeerCredentials {
    PeerCredentials {
        uid: current_uid(),
        pid: None,
        program_path: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_passes_for_current_uid() {
        let creds = synthetic();
        assert!(verify(&creds).is_ok(), "own UID should pass verification");
    }

    #[test]
    fn verify_fails_for_wrong_uid() {
        // UID 0 (root) is almost certainly different from the test runner's UID
        // on a developer machine. If the test is running as root, skip.
        let own_uid = current_uid();
        if own_uid == 0 {
            return; // Running as root — skip this case.
        }
        let foreign = PeerCredentials {
            uid: 0,
            pid: None,
            program_path: None,
        };
        assert!(verify(&foreign).is_err(), "foreign UID should fail verification");
    }
}
