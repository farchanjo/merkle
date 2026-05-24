---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: []
informed: []
---

# 0001. Use Rust as the Implementation Language

## Context and Problem Statement

Merkle must implement a local-first secret vault that: runs as a
background daemon holding decrypted key material in memory (mlocked),
embeds cryptographic primitives (XChaCha20-Poly1305, Argon2id, age,
BLAKE3), integrates with OS keychain APIs on macOS, Linux, and
Windows, exposes an MCP stdio adapter, and ships as a single static
binary that end users can install without a runtime.

The implementation language determines which cryptographic crates are
available without FFI overhead, whether safe memory handling (mlock,
zeroize) is ergonomic, how easily the official MCP Rust SDK (`rmcp`)
integrates, and the operational complexity of the distribution story.

A wrong choice here is expensive to reverse: the language touches
every layer of the stack from the domain core to the OS keychain
adapter. The decision must be made before any other implementation
detail is settled.

## Decision Drivers

* Memory safety without a garbage collector (no GC pause while key
  material sits in mlocked memory).
* First-class availability of battle-tested cryptographic crates:
  `chacha20poly1305`, `argon2`, `blake3`, `age`, `keyring`.
* Official MCP Rust SDK (`rmcp`) exists and is maintained by the
  MCP specification authors.
* `mlock` / `mprotect` / `zeroize` are trivially callable from Rust;
  the `secrecy` and `zeroize` crates make secrets-in-memory safe by
  default.
* Static binary distribution: no runtime installation requirement for
  the operator.
* 2024 edition (1.85+) brings `async fn` in traits as stable, which
  is required by `rmcp`'s trait surface.
* Strong type system enforces handle / plaintext distinction at
  compile time.

## Considered Options

* Option A: Rust 2024 edition (1.85+)
* Option B: Go 1.22+
* Option C: TypeScript (Deno or Bun runtime)
* Option D: Python 3.12+

## Decision Outcome

Chosen option: "Option A: Rust 2024 edition (1.85+)", because it is
the only option that satisfies all decision drivers simultaneously:
memory safety without GC, zero-cost mlock/zeroize integration, the
complete cryptographic crate ecosystem needed, and the official
`rmcp` SDK. The 2024 edition's stable `async fn` in traits is
specifically required for `rmcp` ergonomics.

### Consequences

* Good, because the compiler enforces handle/plaintext separation at
  the type level, eliminating an entire class of accidental exposure
  bugs.
* Good, because `chacha20poly1305`, `argon2`, `blake3`, `age`, and
  `keyring` are all pure-Rust crates audited by the broader
  community, with no C FFI in the hot path.
* Good, because `mlock` / `zeroize` integration is idiomatic and
  enforced by the `secrecy` crate; key material is zeroed on drop
  automatically.
* Good, because a single `cargo build --release` produces a
  self-contained binary for macOS (arm64 and x86_64), Linux
  (x86_64), and Windows (x86_64) via cross-compilation.
* Bad, because Rust has a steeper onboarding curve than Go or Python,
  particularly around async lifetimes and ownership in trait objects.
* Bad, because compile times are longer than Go or TypeScript, which
  adds friction to iterative development. Mitigated by `cargo-nextest`
  and incremental compilation.

## Pros and Cons of the Options

### Option A: Rust 2024 edition (1.85+)

* Good: memory safety without GC; no pause risk near mlocked key material.
* Good: `rmcp` (official MCP Rust SDK) integrates natively.
* Good: full cryptographic crate ecosystem; no FFI overhead.
* Good: `zeroize` / `secrecy` make safe-memory discipline automatic.
* Good: static binaries; zero runtime dependency.
* Bad: steeper learning curve; longer compile times.

### Option B: Go 1.22+

* Good: fast compilation; good concurrency primitives.
* Good: `mlock` accessible via `syscall` package.
* Bad: no official MCP Go SDK at the time of this decision.
* Bad: cryptographic library ecosystem is thinner; age and Argon2id
  bindings exist but are maintained by smaller communities.
* Bad: GC pauses are non-deterministic; key material in heap cannot
  be reliably mlocked across GC moves.

### Option C: TypeScript (Deno or Bun runtime)

* Good: fastest prototyping; broad ecosystem.
* Bad: GC-managed runtime; `mlock` requires native addon or FFI.
* Bad: no reliable way to zeroize heap strings; secrets leak into GC
  heap pages.
* Bad: distribution requires bundling the runtime; not truly static.
* Bad: `@modelcontextprotocol/sdk` exists but is JavaScript-first;
  type safety for MCP contracts is thinner.

### Option D: Python 3.12+

* Good: fastest initial development velocity; mature `cryptography`
  library (wraps libssl via FFI).
* Bad: GC-managed; secrets cannot be reliably zeroed in CPython
  memory.
* Bad: no `mlock` without ctypes or cffi boilerplate.
* Bad: distribution story (virtual environments, pyinstaller) adds
  significant operational friction.
* Bad: no official MCP Python SDK at decision time that covers the
  full MCP 2025-11-25 specification.

## Validation

* CI builds the release binary on all three target platforms via
  `cross` or GitHub Actions matrix; zero runtime dependency confirmed
  by `ldd` (Linux) and `otool -L` (macOS).
* `cargo audit` runs on every pull request to verify the crate supply
  chain.
* Memory-safety invariants are tested with `cargo test --sanitizer
  address` in CI.
* The `rmcp` integration smoke test verifies all declared MCP tools
  are callable over stdio before merge.

## More Information

* RFC 8439 — AEAD Algorithms (ChaCha20-Poly1305 base).
* RFC 9106 — Argon2 Memory-Hard Function.
* `rmcp` crate: `https://crates.io/crates/rmcp`.
* `keyring` crate: `https://crates.io/crates/keyring`.
* `secrecy` crate: `https://crates.io/crates/secrecy`.
* Related: [0002-adopt-agent-plus-mcp-adapter-topology.md](0002-adopt-agent-plus-mcp-adapter-topology.md)
* Related: [0016-rmcp-official-rust-sdk-for-mcp.md](0016-rmcp-official-rust-sdk-for-mcp.md)
* See also: [0018-full-coverage-validation-as-architectural-contract.md](0018-full-coverage-validation-as-architectural-contract.md) — this ADR's
  TLA+ and OpenAPI contracts must be consistent with the Rust implementation
  language choice recorded here.
