# merkle-bdd

BDD acceptance test harness for the Merkle vault, wiring `cucumber` (cucumber-rs) against the `merkle-application` layer via in-memory adapters. Feature files are consumed in-place from `docs/arch/specs/features/` — they are never copied or modified.

## How to run

```bash
# From the workspace root
cargo test -p merkle-bdd

# With verbose cucumber output
RUST_LOG=info cargo test -p merkle-bdd -- --nocapture
```
