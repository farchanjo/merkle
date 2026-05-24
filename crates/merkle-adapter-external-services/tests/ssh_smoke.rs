//! SSH smoke tests — require an actual `ssh` binary and a reachable host.
//!
//! All tests are marked `#[ignore]` and must be run manually:
//!
//! ```bash
//! cargo test -p merkle-adapter-external-services --test ssh_smoke -- --ignored
//! ```
//!
//! Set environment variables to configure the target:
//!
//! - `SSH_SMOKE_TARGET` — `user@host` (default: `localhost`)
//! - `SSH_SMOKE_KEY` — path to an Ed25519/RSA private key file readable by the
//!   current user (default: `~/.ssh/id_ed25519`)

use std::env;
use std::path::PathBuf;

use merkle_adapter_external_services::ExternalServicesAdapter;
use merkle_ports::ExternalServices;

fn smoke_target() -> String {
    env::var("SSH_SMOKE_TARGET").unwrap_or_else(|_| "localhost".to_owned())
}

fn smoke_key_material() -> Vec<u8> {
    let path = env::var("SSH_SMOKE_KEY").map_or_else(
        |_| {
            let home = env::var("HOME").expect("HOME not set");
            PathBuf::from(home).join(".ssh").join("id_ed25519")
        },
        PathBuf::from,
    );
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("cannot read SSH key at {}: {e}", path.display()))
}

#[tokio::test]
#[ignore = "requires real ssh host; set SSH_SMOKE_TARGET and SSH_SMOKE_KEY"]
async fn ssh_exec_echo_succeeds() {
    let adapter = ExternalServicesAdapter::new();
    let target = smoke_target();
    let key = smoke_key_material();

    let output = adapter
        .ssh_exec(&target, &key, "echo 'merkle-smoke-ok'")
        .await
        .expect("ssh exec should succeed");

    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("merkle-smoke-ok"),
        "unexpected stdout: {stdout}"
    );
}

#[tokio::test]
#[ignore = "requires real ssh host; set SSH_SMOKE_TARGET and SSH_SMOKE_KEY"]
async fn ssh_exec_nonzero_exit_code_propagated() {
    let adapter = ExternalServicesAdapter::new();
    let target = smoke_target();
    let key = smoke_key_material();

    let output = adapter
        .ssh_exec(&target, &key, "exit 42")
        .await
        .expect("ssh exec should complete (non-zero exit is not an Err)");

    assert_eq!(output.exit_code, 42);
}
