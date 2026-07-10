//! Per-namespace process-allowlist enforcement (gap #6).
//!
//! The domain models a per-namespace `allowed_consumers` glob allowlist
//! ([`merkle_domain_policy_permissions::AllowedConsumers`]) that authorizes
//! which local processes may reach a namespace over the Companion Socket. Until
//! now that value object was persisted but never checked on the request path —
//! peer authentication was UID-only. This module closes that gap by composing
//! the kernel-verified peer program path
//! ([`crate::peer_cred::PeerCredentials::program_path`]) with the namespace's
//! allowlist at each namespace-scoped chokepoint.
//!
//! # Enforcement policy (opt-in, fail-closed)
//!
//! The domain's *documented* default is "empty allowlist = deny all". Enforcing
//! that literally would prevent a newly bound namespace from being used before
//! its operator can configure a consumer allowlist. The socket adapter therefore
//! treats an empty allowlist as opt-in: process-level gating begins only after a
//! namespace has a configured allowlist, which is then enforced fail-closed.
//!
//! | allowlist    | `program_path`      | decision |
//! |--------------|---------------------|----------|
//! | empty        | any (incl. `None`)  | ALLOW — check skipped (unconfigured namespace) |
//! | non-empty    | `Some` + glob match | ALLOW |
//! | non-empty    | `Some` + no match   | DENY (403) |
//! | non-empty    | `None` (unresolved) | DENY (403) — fail-closed |
//!
//! This is *additional* to — never a replacement for — the same-UID peer check
//! enforced in [`crate::peer_cred::verify`].

use std::path::Path;

use merkle_application::AppError;
use merkle_domain_policy_permissions::NamespacePolicy;
use merkle_types::NamespaceId;

use crate::peer_cred::PeerCredentials;
use crate::problem::{Problem, app_error_to_problem};

use crate::AppContext;

/// Decide whether `peer` may access a namespace governed by `policy`.
///
/// Pure function (no I/O) implementing the opt-in / fail-closed policy documented
/// at the module level. Returns `Ok(())` when access is permitted and a 403
/// [`Problem`] (via [`AppError::PolicyDenied`]) when denied.
#[expect(
    clippy::result_large_err,
    reason = "Problem is the canonical error type across this adapter; boxing would fragment the error surface"
)]
pub(crate) fn enforce_consumer_allowlist(
    policy: &NamespacePolicy,
    peer: &PeerCredentials,
) -> Result<(), Problem> {
    if policy.allowed_consumers.globs.is_empty() {
        return Ok(());
    }

    // Allowlist is configured → the peer's program path MUST resolve and match.
    // A missing path (kernel resolution failed, non-UTF-8, or an unsupported
    // platform) FAILS CLOSED — we never allow an unidentifiable consumer past a
    // configured allowlist.
    match peer.program_path.as_deref().and_then(Path::to_str) {
        Some(path) if policy.allowed_consumers.matches(path) => Ok(()),
        Some(path) => Err(deny(format!(
            "consumer program '{path}' is not authorized for this namespace by its allowed_consumers policy"
        ))),
        None => Err(deny(
            "peer program path could not be resolved; denying because this namespace \
             has a consumer allowlist configured (fail-closed)"
                .to_owned(),
        )),
    }
}

/// Load the namespace policy and enforce the consumer allowlist against `peer`.
///
/// An absent policy row is treated as an empty allowlist (allow). A storage
/// error fails closed because the allowlist cannot be determined.
pub(crate) async fn check(
    ctx: &AppContext,
    namespace_id: &NamespaceId,
    peer: &PeerCredentials,
) -> Result<(), Problem> {
    match ctx.storage.get_namespace_policy(namespace_id).await {
        // Policy present: apply the allowlist decision.
        Ok(Some(policy)) => enforce_consumer_allowlist(&policy, peer),
        Ok(None) => Ok(()),
        // Cannot read the policy → cannot know the allowlist → fail closed.
        Err(e) => Err(app_error_to_problem(AppError::Storage(e))),
    }
}

/// Build the canonical 403 denial [`Problem`] for a rejected consumer.
fn deny(reason: String) -> Problem {
    app_error_to_problem(AppError::PolicyDenied(reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_domain_policy_permissions::allowed_consumers::AllowedConsumers;
    use merkle_types::SecurityProfile;
    use std::path::PathBuf;

    /// Build a policy whose `allowed_consumers` globs are exactly `globs`.
    fn policy_with(globs: Vec<String>) -> NamespacePolicy {
        let mut p = NamespacePolicy::defaults_for(SecurityProfile::Balanced);
        p.allowed_consumers = AllowedConsumers { globs };
        p
    }

    /// Build peer credentials carrying `program_path`.
    fn peer_with(program_path: Option<&str>) -> PeerCredentials {
        PeerCredentials {
            uid: 501,
            pid: Some(1234),
            program_path: program_path.map(PathBuf::from),
        }
    }

    #[test]
    fn empty_allowlist_allows_even_without_path() {
        let policy = policy_with(vec![]);
        let peer = peer_with(None);
        assert!(enforce_consumer_allowlist(&policy, &peer).is_ok());
    }

    #[test]
    fn nonempty_allowlist_matching_path_allows() {
        let policy = policy_with(vec!["/usr/local/bin/merkle*".to_owned()]);
        let peer = peer_with(Some("/usr/local/bin/merkle"));
        assert!(enforce_consumer_allowlist(&policy, &peer).is_ok());
    }

    #[test]
    fn nonempty_allowlist_mismatching_path_denies() {
        let policy = policy_with(vec!["/usr/local/bin/merkle*".to_owned()]);
        let peer = peer_with(Some("/usr/bin/curl"));
        let problem = enforce_consumer_allowlist(&policy, &peer)
            .expect_err("mismatched program path must be denied");
        assert_eq!(problem.status, 403, "denial must be HTTP 403");
    }

    #[test]
    fn nonempty_allowlist_unresolved_path_denies_fail_closed() {
        // Configured allowlist + no resolvable program path → fail closed.
        let policy = policy_with(vec!["/usr/local/bin/merkle*".to_owned()]);
        let peer = peer_with(None);
        let problem = enforce_consumer_allowlist(&policy, &peer)
            .expect_err("unresolved program path must fail closed");
        assert_eq!(problem.status, 403, "fail-closed denial must be HTTP 403");
    }
}
