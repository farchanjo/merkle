# merkle-e2e

Black-box end-to-end integration tests for the Merkle Vault stack. Each test spawns a real `merkle-agent` process against an isolated temp SQLite database and temp socket path, drives the full operator lifecycle via `merkle` CLI subcommands, and verifies audit chain integrity — including deliberate tamper detection.

## How to run

```sh
# Build all binaries first (required — tests locate them via the test-exe path).
cargo build --bins

# Run the e2e tests (all are #[ignore] by default).
cargo test -p merkle-e2e -- --ignored --nocapture
```
