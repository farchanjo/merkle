//! BDD acceptance test entry point.
//!
//! Cucumber loads `.feature` files from `docs/arch/specs/features/` at the
//! workspace root and dispatches each step to the matching definition in the
//! `steps` module.
//!
//! Run with:
//! ```text
//! cargo test -p merkle-bdd
//! ```

mod steps;

use cucumber::World as _;

pub use steps::MerkleWorld;

#[tokio::main]
async fn main() {
    // The relative path resolves from the workspace root.
    // When `cargo test` runs the test binary, the CWD is the workspace root,
    // so `../../docs/arch/specs/features/` from `crates/merkle-bdd/` points
    // to `docs/arch/specs/features/` at the workspace root.
    // We use CARGO_MANIFEST_DIR at build time to construct an absolute path.
    let features_dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/arch/specs/features/"
    );
    MerkleWorld::cucumber()
        .fail_on_skipped()
        .run(features_dir)
        .await;
}
