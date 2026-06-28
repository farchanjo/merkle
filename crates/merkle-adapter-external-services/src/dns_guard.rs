//! Connect-time DNS guard that re-applies the egress denylist (anti-rebinding).
//!
//! [`DestinationPolicy::validate`](crate::DestinationPolicy) screens a
//! destination **before** the vault credential is attached, by resolving the
//! host and rejecting any forbidden (loopback / link-local / private /
//! metadata / ULA …) address. But `reqwest` performs its *own*, independent DNS
//! lookup at connect time. An attacker who controls a hostname with a
//! short-TTL record can answer the pre-flight lookup with a public IP (passing
//! validation) and then rebind to `169.254.169.254` / RFC-1918 before the
//! connect lookup — a TOCTOU DNS-rebinding SSRF that would ship the
//! vault-injected `Authorization` credential to an internal target.
//!
//! [`ValidatingDnsResolver`] closes that gap. Installed via
//! [`reqwest::ClientBuilder::dns_resolver`], it is the resolver `reqwest`
//! consults for every hostname connect, and it returns **only** addresses that
//! pass [`is_forbidden_ip`] — the very same predicate `validate` uses. A host
//! that rebinds to an internal address therefore yields an empty address set
//! and `reqwest` fails closed, never connecting.
//!
//! IP-literal destinations (e.g. `https://93.184.216.34/…`) never reach this
//! resolver: the connector dials the literal directly, and `validate` has
//! already screened it pre-flight. Literals cannot rebind, so there is no
//! second resolution to guard.

use std::net::{SocketAddr, ToSocketAddrs as _};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::destination_policy::is_forbidden_ip;

/// Boxed error type expected by [`reqwest::dns::Resolve`] (`reqwest`'s own
/// `Resolving` future resolves to `Result<Addrs, Box<dyn Error + Send + Sync>>`).
type GuardError = Box<dyn std::error::Error + Send + Sync>;

/// A [`reqwest::dns::Resolve`] implementation that resolves a hostname on the
/// blocking pool and yields only addresses accepted by [`is_forbidden_ip`].
///
/// Sharing [`is_forbidden_ip`] with the pre-flight policy is the whole point:
/// the IP `reqwest` actually connects to is screened by the same denylist that
/// validation used, so a rebinding host fails closed at connect time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ValidatingDnsResolver;

impl Resolve for ValidatingDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(resolve_and_screen(host))
    }
}

/// Resolve `host` off the async runtime, drop every forbidden address, and box
/// the survivors as the iterator `reqwest` expects.
async fn resolve_and_screen(host: String) -> Result<Addrs, GuardError> {
    let safe = tokio::task::spawn_blocking(move || screen(&host))
        .await
        .map_err(into_guard_error)??;
    let addrs: Addrs = Box::new(safe.into_iter());
    Ok(addrs)
}

/// Blocking system resolution + denylist filter. Returns the permitted
/// addresses, or an error if the host resolves to nothing permitted (fail
/// closed). The port is irrelevant here — `reqwest` overrides it from the URL.
fn screen(host: &str) -> Result<Vec<SocketAddr>, GuardError> {
    let resolved = (host, 0).to_socket_addrs().map_err(into_guard_error)?;
    let permitted: Vec<SocketAddr> = resolved.filter(|sa| !is_forbidden_ip(sa.ip())).collect();
    if permitted.is_empty() {
        return Err(into_guard_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("host {host:?} did not resolve to any permitted public address"),
        )));
    }
    Ok(permitted)
}

/// Box a concrete error as the trait object `reqwest` requires, without an
/// `as` cast.
fn into_guard_error<E>(err: E) -> GuardError
where
    E: std::error::Error + Send + Sync + 'static,
{
    Box::new(err)
}

#[cfg(test)]
mod tests {
    use super::screen;

    /// Each forbidden address is filtered out by the resolver path, leaving an
    /// empty permitted set, so screening fails closed — proving the resolver
    /// enforces the same denylist (`is_forbidden_ip`) as pre-flight validation.
    /// IP literals resolve deterministically (no DNS), so this is hermetic.
    #[test]
    fn screen_rejects_forbidden_addresses() {
        for host in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            let err = screen(host).expect_err("forbidden address must be refused");
            assert!(
                err.to_string().contains("permitted public address"),
                "{host} should fail closed via the shared denylist, got: {err}"
            );
        }
    }

    /// A public IP literal survives the filter and is returned — the resolver
    /// only removes forbidden addresses, never public ones.
    #[test]
    fn screen_keeps_public_address() {
        let permitted = screen("93.184.216.34").expect("public address must survive screening");
        assert_eq!(permitted.len(), 1);
        assert_eq!(permitted[0].ip().to_string(), "93.184.216.34");
    }

    /// End-to-end on the real DNS path: `localhost` resolves only to loopback
    /// addresses, so the resolver filters them all and fails closed. This
    /// exercises the actual `to_socket_addrs` lookup, not just literals.
    #[test]
    fn screen_rejects_localhost_via_dns() {
        let err = screen("localhost").expect_err("loopback-only host must be refused");
        assert!(
            err.to_string().contains("permitted public address"),
            "{err}"
        );
    }
}
