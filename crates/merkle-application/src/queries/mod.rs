//! Query handlers — read-side of the CQRS split.
//!
//! Queries never mutate state; they may append read-only audit entries.

pub mod agent_status;
pub mod doctor;
pub mod list_backups;
pub mod list_namespaces;
pub mod query_audit;
pub mod verify_chain;
