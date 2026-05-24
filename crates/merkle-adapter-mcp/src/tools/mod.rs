//! Tool module registry.
//!
//! Each sub-module groups semantically related tools. The `MerkleMcpServer`
//! struct defined in `lib.rs` owns the `ToolRouter` and delegates all
//! `call_tool` / `list_tools` calls into it via `#[tool_handler]`.

pub mod audit;
pub mod backup;
pub mod diagnostics;
pub mod identity;
pub mod proxy;
pub mod reveal;
pub mod secrets;
pub mod use_token;
