set shell := ["bash", "-uc"]
set dotenv-load

# Default: list all available recipes
default:
    @just --list

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

# Build all workspace crates (debug)
build:
    cargo build --workspace

# Check all workspace crates and targets without producing binaries
check:
    cargo check --workspace --all-targets

# Build all workspace crates in release mode
build-release:
    cargo build --release --workspace

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

# Run all workspace tests (lib + bins + doc tests)
test:
    cargo test --workspace

# Run lib and bin tests only (faster, skips doc tests)
test-fast:
    cargo test --workspace --lib --bins

# Run doc tests only
test-doc:
    cargo test --workspace --doc

# ---------------------------------------------------------------------------
# Code quality
# ---------------------------------------------------------------------------

# Run Clippy with -D warnings (mirrors CI)
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Format all sources in-place
fmt:
    cargo fmt --all

# Check formatting without modifying files (mirrors CI)
fmt-check:
    cargo fmt --check --all

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

# Run cargo-deny license + bans + advisory + sources checks
deny:
    cargo deny check

# Run cargo-audit advisory check against RustSec DB
audit:
    cargo audit

# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

# Generate HTML coverage report (opens browser on macOS/Linux)
cov:
    cargo llvm-cov --workspace --html
    @echo "Coverage report: target/llvm-cov/html/index.html"

# Generate LCOV coverage report (for CI artifact upload)
cov-lcov:
    cargo llvm-cov --workspace --lcov --output-path coverage.lcov

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

# Run all workspace benchmarks
bench:
    cargo bench --workspace

# ---------------------------------------------------------------------------
# Spec validation (ADR-0018)
# ---------------------------------------------------------------------------

# Run full spec validation lane — all 14 validators (CI gate)
spec:
    ~/bin/spec validate --lane full

# Run fast spec validation lane (~1.5 s) — CUE, DDD headers, OpenAPI, Gherkin
spec-fast:
    ~/bin/spec validate --lane fast

# Run medium spec validation lane (~10 s) — fast + Structurizr + markdownlint
spec-medium:
    ~/bin/spec validate

# ---------------------------------------------------------------------------
# Doctor
# ---------------------------------------------------------------------------

# Full health check: check + clippy + test + spec validate --lane full
doctor:
    cargo check --workspace --all-targets
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    ~/bin/spec validate --lane full

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

# Start the Vault Agent daemon
agent:
    cargo run -p merkle-agent --

# Run the Merkle CLI (pass args: just cli -- vault list)
cli args="":
    cargo run -p merkle-cli -- {{args}}

# ---------------------------------------------------------------------------
# Release dry-run
# ---------------------------------------------------------------------------

# Release dry-run: release build + deny + audit (no publish)
release-dry:
    cargo build --release --workspace
    cargo deny check
    cargo audit

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

# Remove build artifacts and spec report cache
clean:
    cargo clean
    rm -rf .spec-reports docs/arch/formal/states
