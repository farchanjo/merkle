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

/// Acceptance steps must assert observable behavior.  A no-op step can turn a
/// scenario green even though the requirement it names has no implementation.
/// Keep this check in the executable harness (rather than a unit test) because
/// this target deliberately uses Cucumber's custom, `harness = false` runner.
fn reject_empty_step_definitions() {
    const STEP_FILES: [(&str, &str); 3] = [
        ("given.rs", include_str!("steps/given.rs")),
        ("when.rs", include_str!("steps/when.rs")),
        ("then.rs", include_str!("steps/then.rs")),
    ];

    let mut empty_steps = Vec::new();
    for (file_name, source) in STEP_FILES {
        for (line_number, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("async fn ") && trimmed.ends_with("{}") {
                empty_steps.push(format!("{file_name}:{}: {trimmed}", line_number + 1));
            }
        }
    }

    assert!(
        empty_steps.is_empty(),
        "BDD step definitions must assert behavior or fail explicitly; empty definitions found:\n{}",
        empty_steps.join("\n")
    );
}

#[tokio::main]
async fn main() {
    reject_empty_step_definitions();

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
        .run_and_exit(features_dir)
        .await;
}
