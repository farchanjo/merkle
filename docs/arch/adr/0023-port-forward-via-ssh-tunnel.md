---
status: accepted
date: 2026-05-23
deciders: [farchanjo]
consulted: [Architecture]
informed: [Engineering, SRE, Security]
---

# 0023. Port Forward via SSH Tunnel Subprocess

## Context and Problem Statement

The `PortForwardCommand` in `merkle-application` has returned
`AppError::NotImplemented` since Phase 5 with an audit entry recording
`op=port_forward, outcome=deny`. The audit entry exists; the actual TCP tunnel
does not.

The `#ProxyOperation` enum in `proxy_executor.cue` already declares
`"ssh.port_forward"` as a valid operation, and the closed `AuditOp` enum in
`merkle-types` already carries the `PortForward` variant. The schema contract
is complete; only the application-layer implementation is absent.

Port-forwarding requires a long-lived background process that remains alive for
the duration of the operator's session. A pure Rust SSH library (libssh2 or
russh) can issue a `direct-tcpip` channel request, but that path requires
the vault agent to own a persistent async task and an in-memory session map
with unique session identifiers. The equivalent `ssh -L` subprocess approach
delegates the tunnel lifecycle to the system SSH binary, reduces the in-process
attack surface for key material (the key is passed via a `mode 0600` tempfile
that is reaped on session end), and is consistent with the approach already
used by `SshExecCommand` (which injects key material via `ExternalServices`).

The question is: what is the simplest, safety-preserving implementation that
delivers a working TCP tunnel while keeping the Phase-scope surface minimal?

## Decision Drivers

* **Minimal new infrastructure**: reuse the existing `Write Tempfile`
  machinery for key material, and the existing `AppContext` extension point
  for active-session tracking.
* **Prompt injection resistance (ADR-0011)**: port-forwarding a high-sensitivity
  SSH key (a bastion private key, for example) must require the same
  slash-command gate that governs Reveals for `sensitivity=high` secrets.
* **Audit continuity (ADR-0009)**: every attempt — allow or deny — must append
  an `AuditEntry`. The current placeholder already does so on deny; the
  implementation must record allow on success.
* **Revocation path**: a spawned `ssh -L` child process must be trackable
  so it can be terminated on explicit revoke or agent shutdown.
* **Cross-ref ADR-0011**: slash-command gate applies for `sensitivity=high`
  SSH keys exactly as for Reveals.
* **Cross-ref ADR-0015 Amendment**: peer-credential socket handshake is the
  transport for Companion Socket commands, including future `revoke_port_forward`
  invocations. The implementation must not assume a direct caller; all paths
  go through the port.

## Considered Options

* **Option A**: Pure Rust SSH library (`russh` direct-tcpip channel) — full
  in-process tunnel, no subprocess.
* **Option B**: `ssh -L` subprocess via `tokio::process::Command` — delegates
  tunnel management to the system SSH binary; key material via tempfile.
* **Option C**: Continue returning `NotImplemented` — keep Phase 6 deferral.

## Decision Outcome

Chosen option: **Option B — `ssh -L` subprocess**.

The system SSH binary handles the `direct-tcpip` channel, keepalive, and
reconnection. The vault agent holds the `Child` handle in a session map
(`Arc<RwLock<HashMap<UuidV7, tokio::process::Child>>>`) stored on `AppContext`.
Key material is written to a tempfile with `mode 0600`, the path is passed via
`-i`, and the tempfile is revoked when the tunnel closes.

Option A requires a persistent async task per tunnel and a full SSH handshake
state machine in the vault process — more attack surface with no security
advantage over Option B for the Phase scope.

Option C unblocks no use case and leaves the audit record misleading
(`outcome=deny` on every attempt even when the operator is authorized).

### Consequences

* Good, because `ssh -L` subprocess reuses the existing system SSH binary with
  its own known-hosts verification and cipher negotiation, which is already
  trusted by the OS.
* Good, because the `Child` handle is held in `AppContext` and drops (SIGKILL)
  automatically when the context is freed at agent shutdown.
* Good, because the `UuidV7` session id returned to the caller enables a future
  `RevokePortForward` command to target the specific tunnel.
* Good, because the slash-command gate for `sensitivity=high` keys is enforced
  before the subprocess is spawned, maintaining the ADR-0011 guarantee.
* Bad, because the system SSH binary must exist on the agent host path —
  not universally available in minimal container images. This is acceptable
  for Phase 6 targets (bare-metal and macOS installs).
* Bad, because the tempfile lifetime is tied to the `PortForwardSession`
  and a crash between spawn and revoke can orphan the tempfile. The existing
  `RevokeOrphanTempfiles` boot-time sweep mitigates this.
* Neutral, because the `ExternalServices` port is not extended by this change;
  the subprocess is spawned directly via `tokio::process::Command` inside the
  application layer, consistent with `SpawnCommand` precedent.

## Implementation Notes

1. **Policy gate**: if `operator_confirmation.slash_command == false` and the
   SSH key has `sensitivity=high`, the command returns
   `AppError::PolicyDenied("missing_slash_command")` with `outcome=deny`.
2. **Key tempfile**: written to `$TMPDIR/merkle-pf-<uuid>.key` with
   `tokio::fs::File` and `mode 0600` via `std::os::unix::fs::PermissionsExt`.
3. **Subprocess**: `tokio::process::Command::new("ssh")` with args
   `["-i", key_path, "-N", "-L", "<local_port>:<remote_host>:<remote_port>", "<ssh_target>"]`.
   The `Child` is NOT awaited; it runs as a background process.
4. **Session registry**: `AppContext.active_port_forwards` is
   `Arc<RwLock<HashMap<UuidV7, tokio::process::Child>>>`. Inserted on success;
   removed and killed by `RevokePortForwardCommand` (Phase 7+).
5. **Audit**: `op=PortForward, outcome=Allow` on success;
   `op=PortForward, outcome=Deny, denial_reason="missing_slash_command"` on
   policy rejection.

## Validation

- `cargo clippy --all-features --all-targets --workspace -- -D warnings` exits 0.
- `cargo nextest run --all-features` exits 0.
- BDD scenario `proxy_ssh_exec.feature` (jump-host) + new `port_forward.feature`
  scenarios run green.
- `spec validate --lane full` exits 0 with 14/14 validators — `lint_madr`
  must include ADR-0023.

## More Information

* [ADR-0011](0011-slash-only-reveal-with-oob-for-high-sensitivity.md) — slash-command
  gate that applies to `sensitivity=high` SSH key port-forwards.
* [ADR-0015](0015-rust-keyring-crate-for-multi-os-keychain.md) — Amendment 3
  peer-credential socket contract for Companion Socket callers, including
  future `RevokePortForward` invocations.
* [ADR-0009](0009-merkle-style-audit-hash-chain.md) — audit chain that every
  port-forward attempt (allow or deny) must extend.
* `docs/arch/schemas/access_mediation/proxy_executor.cue` — CUE schema that
  already declares `"ssh.port_forward"` in `#ProxyOperation`.
* `crates/merkle-application/src/commands/port_forward.rs` — implementation
  of `PortForwardCommand` specified by this ADR.
