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
//! | Linux | `tokio::net::UnixStream::peer_cred()` via `SO_PEERCRED` | `uid`, `pid`, `program_path` |
//! | macOS | `LOCAL_PEERCRED` + `LOCAL_PEERPID` + `proc_pidpath` | `uid` (effective), `pid`, `program_path` |
//! | Other | Fails closed — no verified credential source | none |
//!
//! The caller's binary is additionally resolved to a canonical path so the
//! per-namespace `allowed_consumers` process allowlist can be enforced:
//! - Linux reads `/proc/<pid>/exe`, a kernel-controlled symlink that the
//!   process cannot forge (unlike `/proc/<pid>/comm`).
//! - macOS resolves the peer PID via `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` and
//!   the executable path via `proc_pidpath(2)`, then canonicalizes it.
//!
//! Path resolution is *best-effort*: `uid` is the primary same-user gate and is
//! always required, but a missing `program_path` is not fatal to extraction —
//! it makes the consumer allowlist fail CLOSED for any namespace that configures
//! one (see [`crate::consumer_gate`]).
//!
//! # Unsafe usage
//!
//! This module contains platform-specific `unsafe` blocks, all thin FFI calls:
//! - macOS: `getsockopt(LOCAL_PEERCRED)` (uid), `getsockopt(LOCAL_PEERPID)`
//!   (pid), and `proc_pidpath` (executable path) — none have a safe Rust
//!   wrapper in the current workspace dependency set.
//! - `libc::getuid()` — POSIX guarantee; always safe and infallible.
//!
//! Every block carries a SAFETY comment. Tracked for replacement with `nix`
//! or `rustix` once those crates are added to the workspace dependency set.

use std::io;

/// Peer credentials extracted from the OS at connection accept time.
#[derive(Debug, Clone)]
pub struct PeerCredentials {
    /// Real UID of the connecting process.
    pub uid: u32,
    /// PID of the connecting process (Linux + macOS).
    pub pid: Option<u32>,
    /// Resolved canonical binary path of the connecting process.
    /// Populated on Linux from `/proc/<pid>/exe` and on macOS from
    /// `proc_pidpath(2)`. `None` when the kernel path could not be resolved.
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

    let fd = stream.as_raw_fd();

    // uid is the primary same-user gate: extraction fails (connection dropped)
    // if it cannot be obtained from the kernel.
    let uid = macos_local_peercred(fd)?;

    // pid + executable path are additional inputs for the `allowed_consumers`
    // process allowlist. Resolution is BEST-EFFORT: a failure leaves
    // `program_path = None`, which makes `enforce_consumer_allowlist` fail CLOSED
    // for any namespace that configures an allowlist, while unconfigured
    // namespaces (empty allowlist) keep working. We never fabricate a path.
    let pid = macos_peer_pid(fd).ok();
    let program_path = pid.and_then(macos_proc_path);

    Ok(PeerCredentials {
        uid,
        pid,
        program_path,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn extract_impl(_stream: &tokio::net::UnixStream) -> io::Result<PeerCredentials> {
    // No verified peer-credential source is implemented for this platform.
    // Fail CLOSED — never fabricate `current_uid()` here: doing so would make
    // `verify()` trivially pass for *any* connecting process, a complete
    // authentication bypass of the same-UID invariant. Denying is the only
    // safe default until a kernel-backed credential source is wired.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer-credential authentication is not supported on this platform",
    ))
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
    #[expect(
        unsafe_code,
        reason = "getsockopt(LOCAL_PEERCRED) has no safe Rust wrapper; \
        blocked on adding nix/rustix to the workspace dependency set."
    )]
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
// macOS LOCAL_PEERPID + proc_pidpath helpers
// ---------------------------------------------------------------------------

/// Resolve the connecting peer's PID via `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`.
///
/// `libc::LOCAL_PEERPID` (`0x002`) and `libc::proc_pidpath` are both present in
/// the pinned `libc` (0.2), so no locally defined constant is required.
#[cfg(target_os = "macos")]
fn macos_peer_pid(fd: std::os::unix::io::RawFd) -> io::Result<u32> {
    // SOL_LOCAL=0 on macOS (from <sys/socket.h>); LOCAL_PEERPID comes from libc.
    const SOL_LOCAL: libc::c_int = 0;

    let mut pid: libc::pid_t = 0;
    // size_of::<pid_t>() is 4, which always fits socklen_t (u32).
    let mut len: libc::socklen_t = u32::try_from(size_of::<libc::pid_t>()).unwrap_or(4);

    // SAFETY: `fd` is a valid, open AF_UNIX socket descriptor from a live
    // `tokio::net::UnixStream`. `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` writes a
    // single `pid_t` into `pid` and updates `len`. `pid` and `len` are locally
    // owned scalars, so there is no aliasing or data-race risk. `&raw mut` is
    // used to avoid the `borrow_as_ptr` lint.
    #[expect(
        unsafe_code,
        reason = "getsockopt(LOCAL_PEERPID) has no safe Rust wrapper; \
        blocked on adding nix/rustix to the workspace dependency set."
    )]
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut len,
        )
    };

    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // A valid pid is non-negative; a negative value fails closed via the error.
    u32::try_from(pid).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "LOCAL_PEERPID returned a negative pid",
        )
    })
}

/// Resolve the canonical executable path of `pid` via `proc_pidpath(2)`.
///
/// Returns `None` on any failure (dead process, unreadable path, non-UTF-8
/// bytes that fail canonicalization), so the caller fails closed.
#[cfg(target_os = "macos")]
fn macos_proc_path(pid: u32) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;

    let pid_c = libc::pid_t::try_from(pid).ok()?;
    // PROC_PIDPATHINFO_MAXSIZE is 4096 on macOS; the kernel never writes more.
    let mut buf = [0u8; 4096];
    let buf_len = u32::try_from(buf.len()).ok()?;

    // SAFETY: `proc_pidpath` writes at most `buf_len` bytes into `buf` and
    // returns the number of bytes written (>0) or <=0 on failure. `buf` is a
    // locally owned, correctly sized stack buffer and `pid_c` is a plain scalar,
    // so there is no aliasing or lifetime concern.
    #[expect(
        unsafe_code,
        reason = "proc_pidpath has no safe Rust wrapper; \
        blocked on adding nix/rustix to the workspace dependency set."
    )]
    let written = unsafe { libc::proc_pidpath(pid_c, buf.as_mut_ptr().cast(), buf_len) };

    if written <= 0 {
        return None;
    }

    // The kernel NUL-terminates the path; slice up to the first NUL so we never
    // depend on the exact return-length semantics.
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if end == 0 {
        return None;
    }

    let path = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..end]));
    // Canonicalize (symlink-resolve) so the path matches the form the Linux
    // branch produces and that `AllowedConsumers` globs are written against.
    std::fs::canonicalize(path).ok()
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
    #[expect(
        unsafe_code,
        reason = "libc::getuid() is infallible; no safe Rust wrapper exists \
        without nix/rustix in the workspace."
    )]
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
/// TEST-ONLY: confined to `#[cfg(test)]` so the production serve path can never
/// fabricate a passing identity. Real connections always carry credentials
/// extracted from the kernel by [`crate::serve_with_peer_cred`].
#[cfg(test)]
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
        assert!(
            verify(&foreign).is_err(),
            "foreign UID should fail verification"
        );
    }
}
