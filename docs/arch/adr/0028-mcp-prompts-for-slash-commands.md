---
status: accepted
date: 2026-05-24
deciders: farchanjo
consulted: []
informed: []
---

# ADR-0028 — MCP Prompts as canonical surface for `/merkle-*` slash commands

## Context and Problem Statement

The wiring guide at
[`docs/arch/integrations/claude-code-wiring.md`](../integrations/claude-code-wiring.md)
specifies four operator-facing slash commands — `/merkle-reveal`,
`/merkle-show`, `/merkle-rollback`, `/merkle-doctor` — but the merkle MCP
adapter only advertises the **tools** server capability
(`ServerCapabilities::builder().enable_tools()`), so an MCP client such as
Claude Code never calls `prompts/list` and the four slash commands fail to
appear in the client UI.

Operators currently work around the gap by hand-crafting per-client
wrappers under `~/.claude/commands/merkle-*.md`. This duplicates spec
content, fragments across every client install, drifts as the wiring spec
evolves, and offers nothing to non-Claude-Code clients.

## Decision Drivers

- Spec-as-source-of-truth: slash commands defined in `claude-code-wiring.md`
  must be discoverable directly from the MCP server, not from per-client
  wrappers.
- Hexagonal boundary preservation: prompt definitions live in the driving
  adapter (`merkle-adapter-mcp`) — they are an MCP-surface concern, not a
  domain concern. Application and domain layers stay untouched.
- Server-side single source: every MCP client (Claude Code today, Cursor /
  Continue / Goose tomorrow) discovers the same slash literals on connect.
- Operator Confirmation invariant: `operator_confirmation: true` must
  continue to be honored only when the slash-originated `_meta` flag is
  set, never from LLM-generated tool arguments.

## Considered Options

1. **Per-client markdown wrappers** under `~/.claude/commands/merkle-*.md`
   (the current state). Rejected: client-specific, spec drift, no reuse.
2. **MCP prompts capability** — advertise `prompts` in
   `ServerCapabilities` and answer `prompts/list` + `prompts/get` from the
   adapter. Chosen.
3. **Custom JSON-RPC method** outside the MCP spec. Rejected: breaks
   interop with every conformant MCP client.

## Decision Outcome

Chosen option: **option 2 — expose the four slash commands as MCP prompts**.

The adapter advertises the `prompts` capability and registers a static
catalog (`MerklePrompts`) in
`crates/merkle-adapter-mcp/src/prompts.rs`. Each prompt is keyed by name,
declares its required + optional `PromptArgument`s, and renders a single
user-role `PromptMessage` whose text instructs the consuming LLM to chain
the corresponding `vault_*` tool calls with the spec-defined arguments
(`vault_doctor`, `vault_describe`, `vault_reveal`, `vault_history` +
`vault_rotate`).

`prompts/list` and `prompts/get` are wired through `ServerHandler` on
`MerkleMcpServer` and delegate to `MerklePrompts::list` /
`MerklePrompts::get`. Unknown prompt names and missing required arguments
return `ErrorData::invalid_params`.

This decision does NOT touch the Operator Confirmation invariant. The
`_meta` slash-origin flag continues to be enforced where it was before —
the prompts only surface the slash literal in the client UI; the
`operator_confirmation: true` field in the prompt body is informational
and is rejected at the MCP Adapter layer unless the originating call
carried the slash-context `_meta` flag.

### Consequences

- ✅ Slash commands now appear as `/mcp__merkle__merkle-*` in any
  conformant MCP client, sourced from the spec.
- ✅ Per-client wrappers under `~/.claude/commands/` can be removed.
- ✅ Adding a new operator slash command is a one-file change in
  `prompts.rs` + a wiring-doc update; no client config touches.
- ⚠️ Bumps the MCP capability surface; existing MCP clients tolerate
  added capabilities gracefully (negotiated at handshake), but very old
  clients that hard-code an "tools only" expectation may need updates.
- ⚠️ Prompt bodies must stay in sync with `claude-code-wiring.md`. A
  follow-up should add a CI check that the four prompt names + argument
  lists match the wiring-doc table.

## Implementation Notes

- New module: `crates/merkle-adapter-mcp/src/prompts.rs`.
- `lib.rs` patch: `mod prompts;`, `pub use prompts::MerklePrompts;`,
  `.enable_prompts()` in `ServerCapabilities`, and override
  `list_prompts` + `get_prompt` in the `ServerHandler` impl.
- Unit tests cover: list shape (4 prompts), per-prompt body inlining,
  default-purpose fallback on `merkle-reveal`, missing-argument errors on
  `merkle-show` and `merkle-rollback`, unknown-prompt error.
- No domain or application code changes. No CUE schema changes. No
  Companion-Socket API changes.

## Related

- [`docs/arch/integrations/claude-code-wiring.md`](../integrations/claude-code-wiring.md) — operator-facing spec for the four slash commands.
- ADR-0016 — rmcp official Rust SDK for MCP.
- ADR-0024 — MCP Adapter consumes Companion Socket client.
