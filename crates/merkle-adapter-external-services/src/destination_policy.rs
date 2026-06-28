//! Outbound HTTP destination policy (SSRF guard).
//!
//! The HTTP Bridge injects a vault-managed credential as the `Authorization`
//! header before issuing a request to a caller-supplied URL.  Without a
//! destination allowlist this is a classic SSRF primitive: a caller could
//! point the request at `http://169.254.169.254/…` (cloud metadata),
//! `http://127.0.0.1/…` (loopback) or any RFC-1918 internal host and have the
//! vault attach a real secret to it.
//!
//! [`DestinationPolicy`] enforces, in strict mode:
//!
//! * scheme is `https` only (no `http`, `file`, `gopher`, …);
//! * the host (or every address it resolves to) is a public, routable unicast
//!   address — loopback, link-local (incl. `169.254.169.254`), private,
//!   shared/CGNAT, multicast, broadcast, unspecified and IPv6 ULA ranges are
//!   rejected.
//!
//! Validation runs **before** the credential is attached, so a rejected
//! destination never sees the secret.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use merkle_ports::ExternalError;
use reqwest::Url;

/// Egress destination policy for the HTTP Bridge.
#[derive(Debug, Clone, Copy)]
pub struct DestinationPolicy {
    /// When `true`, enforce https-only + public-host. When `false`, accept any
    /// destination — intended exclusively for local mock-server tests, never
    /// for production wiring (production uses [`DestinationPolicy::strict`]).
    enforce: bool,
}

impl DestinationPolicy {
    /// Production policy: https-only, public-host-only.
    #[must_use]
    pub const fn strict() -> Self {
        Self { enforce: true }
    }

    /// Test/dev-only policy that performs no validation.
    ///
    /// Exposed so local integration tests can drive a plain-`http` loopback
    /// mock server (e.g. `wiremock`). **Never** use this in production wiring;
    /// it disables the SSRF guard entirely.
    #[doc(hidden)]
    #[must_use]
    pub const fn permissive() -> Self {
        Self { enforce: false }
    }

    /// Validate `url` against this policy.
    ///
    /// # Errors
    ///
    /// Returns [`ExternalError::OperationFailed`] if the URL is malformed, uses
    /// a non-https scheme, has no host, or resolves to a non-public address.
    pub async fn validate(&self, url: &str) -> Result<(), ExternalError> {
        if !self.enforce {
            return Ok(());
        }
        let parsed = Url::parse(url)
            .map_err(|e| ExternalError::OperationFailed(format!("invalid request URL: {e}")))?;
        Self::check_scheme(&parsed)?;
        Self::check_host(&parsed).await
    }

    fn check_scheme(url: &Url) -> Result<(), ExternalError> {
        if url.scheme() != "https" {
            return Err(ExternalError::OperationFailed(format!(
                "scheme {:?} rejected: only https destinations are permitted",
                url.scheme()
            )));
        }
        Ok(())
    }

    async fn check_host(url: &Url) -> Result<(), ExternalError> {
        let host = url
            .host_str()
            .ok_or_else(|| ExternalError::OperationFailed("request URL has no host".to_owned()))?;
        let bare = host.trim_start_matches('[').trim_end_matches(']');

        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Self::reject_if_forbidden(ip);
        }

        let port = url.port_or_known_default().unwrap_or(443);
        for ip in resolve(bare, port).await? {
            Self::reject_if_forbidden(ip)?;
        }
        Ok(())
    }

    fn reject_if_forbidden(ip: IpAddr) -> Result<(), ExternalError> {
        if is_forbidden_ip(ip) {
            return Err(ExternalError::OperationFailed(format!(
                "destination address {ip} is not a permitted public host"
            )));
        }
        Ok(())
    }
}

impl Default for DestinationPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

/// Resolve `host:port` to its candidate addresses on the blocking pool (DNS is
/// blocking; never run it on the async runtime thread).
async fn resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, ExternalError> {
    use std::net::ToSocketAddrs as _;

    let target = host.to_owned();
    let resolved = tokio::task::spawn_blocking(move || {
        (target.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.map(|sa| sa.ip()).collect::<Vec<_>>())
    })
    .await
    .map_err(|e| ExternalError::Backend(format!("DNS resolution task failed: {e}")))?
    .map_err(|e| ExternalError::ConnectFailed(format!("could not resolve host {host:?}: {e}")))?;

    if resolved.is_empty() {
        return Err(ExternalError::ConnectFailed(format!(
            "host {host:?} resolved to no addresses"
        )));
    }
    Ok(resolved)
}

/// `true` if `ip` is any non-public / internal / special-use address that the
/// HTTP Bridge must refuse to target.
///
/// This is the **single source of truth** for the egress IP denylist. It is
/// consulted both by the pre-flight [`DestinationPolicy::validate`] (above) and
/// by the connect-time [`crate::dns_guard::ValidatingDnsResolver`], so the two
/// can never drift: every IP the request might actually reach is screened
/// through exactly this predicate. Closing the TOCTOU DNS-rebinding gap depends
/// on both call sites sharing this function.
pub(crate) fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| is_forbidden_v6(v6), is_forbidden_v4),
    }
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()        // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254.0.0/16 (incl. 169.254.169.254 metadata)
        || ip.is_multicast()    // 224.0.0.0/4
        || ip.is_broadcast()    // 255.255.255.255
        || ip.is_unspecified()  // 0.0.0.0
        || ip.is_documentation()
        || is_shared_v4(ip) // 100.64.0.0/10 CGNAT
}

/// 100.64.0.0/10 — RFC 6598 shared address space (carrier-grade NAT).
fn is_shared_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

fn is_forbidden_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()        // ::1
        || ip.is_multicast()    // ff00::/8
        || ip.is_unspecified()  // ::
        || is_ula_v6(ip)        // fc00::/7 unique-local
        || is_link_local_v6(ip) // fe80::/10
}

/// `fc00::/7` — unique local addresses (RFC 4193).
fn is_ula_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// `fe80::/10` — link-local unicast.
fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback_v4() {
        assert!(is_forbidden_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_metadata_link_local() {
        assert!(is_forbidden_ip("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn rejects_private_ranges() {
        for ip in ["10.0.0.1", "172.16.5.4", "192.168.1.1"] {
            assert!(
                is_forbidden_ip(ip.parse().unwrap()),
                "{ip} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_shared_cgnat() {
        assert!(is_forbidden_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_forbidden_ip("100.63.255.255".parse().unwrap()));
        assert!(!is_forbidden_ip("100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_v6_loopback_ula_and_linklocal() {
        assert!(is_forbidden_ip("::1".parse().unwrap()));
        assert!(is_forbidden_ip("fc00::1".parse().unwrap()));
        assert!(is_forbidden_ip("fd12:3456::1".parse().unwrap()));
        assert!(is_forbidden_ip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn rejects_v4_mapped_loopback() {
        assert!(is_forbidden_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn allows_public_addresses() {
        assert!(!is_forbidden_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_forbidden_ip("93.184.216.34".parse().unwrap()));
        assert!(!is_forbidden_ip("2606:2800:220:1::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn validate_rejects_non_https_scheme() {
        let err = DestinationPolicy::strict()
            .validate("http://93.184.216.34/x")
            .await
            .unwrap_err();
        assert!(matches!(err, ExternalError::OperationFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn validate_rejects_loopback_literal() {
        let err = DestinationPolicy::strict()
            .validate("https://127.0.0.1/x")
            .await
            .unwrap_err();
        assert!(matches!(err, ExternalError::OperationFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn validate_rejects_metadata_literal() {
        let err = DestinationPolicy::strict()
            .validate("https://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(matches!(err, ExternalError::OperationFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn validate_rejects_ipv6_loopback_literal() {
        let err = DestinationPolicy::strict()
            .validate("https://[::1]/x")
            .await
            .unwrap_err();
        assert!(matches!(err, ExternalError::OperationFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn validate_allows_public_ip_literal() {
        DestinationPolicy::strict()
            .validate("https://93.184.216.34/x")
            .await
            .expect("public https destination must pass");
    }

    #[tokio::test]
    async fn permissive_allows_loopback_http() {
        DestinationPolicy::permissive()
            .validate("http://127.0.0.1:8080/x")
            .await
            .expect("permissive policy performs no validation");
    }
}
