//! HTTP request implementation using `reqwest` with rustls (no OpenSSL).
//!
//! Auth material (`Bearer` token or `Basic` credentials) is injected as an
//! `Authorization` header inside the agent process. The plaintext credential
//! never crosses the MCP transport or appears in log output (tracing spans
//! record only the auth variant, not the value).
//!
//! Egress is constrained by [`DestinationPolicy`] (SSRF guard): the destination
//! is validated **before** the credential is attached, the body is drained
//! under a hard ceiling, and the whole exchange is wrapped in a watchdog
//! timeout on top of the client-level request/connect timeouts.

use std::time::Duration;

use base64::Engine as _;
use reqwest::{Client, Method, Response, header};
use tracing::{debug, instrument, warn};

use merkle_ports::{ExternalError, HttpAuth, HttpRequestSpec, HttpResponse};

use crate::destination_policy::DestinationPolicy;

/// Hard ceiling on the response body the bridge will buffer (8 MiB).
///
/// Both the advertised `Content-Length` and the actually streamed bytes are
/// checked against this, so a lying/absent `Content-Length` cannot be used to
/// exhaust memory.
pub(crate) const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Watchdog timeout wrapping the entire send + drain. Defense in depth on top
/// of the client's per-request `.timeout()`; set slightly higher so the
/// client-level timeout normally fires first with a cleaner error.
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(35);

/// Strip the query string from a URL for logging: query parameters routinely
/// carry secrets (tokens, signatures) that must never reach the log.
fn redact_url(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

/// Execute an HTTP request described by `spec`, applying `auth` as the
/// `Authorization` header.
///
/// The `client` is expected to be pre-built with `rustls`, connection pooling,
/// explicit timeouts and `redirect::Policy::none()` (see
/// `ExternalServicesAdapter`). `policy` gates the destination before any
/// credential is attached.
#[instrument(skip(client, policy, spec, auth), fields(method = %spec.method, url = %redact_url(&spec.url)))]
pub(crate) async fn http_request(
    client: &Client,
    policy: &DestinationPolicy,
    spec: HttpRequestSpec,
    auth: HttpAuth,
) -> Result<HttpResponse, ExternalError> {
    // SSRF guard: validate the destination BEFORE the secret is attached, so a
    // rejected (loopback / metadata / private / non-https) URL never sees it.
    policy.validate(&spec.url).await?;

    let method = spec.method.parse::<Method>().map_err(|e| {
        ExternalError::OperationFailed(format!("invalid HTTP method {:?}: {e}", spec.method))
    })?;

    let mut builder = client.request(method, &spec.url);

    // Apply caller-supplied headers, but NEVER let a caller inject their own
    // Authorization header: reqwest appends rather than replaces, so a
    // caller-supplied `Authorization` would be sent alongside the
    // vault-managed one and could subvert which credential the server honours.
    // The vault is the only source of the Authorization header.
    for (name, value) in &spec.headers {
        if name.eq_ignore_ascii_case("authorization") {
            warn!("dropping caller-supplied Authorization header; vault manages auth");
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }

    builder = apply_auth(builder, auth);

    // Apply optional body.
    if let Some(body) = spec.body {
        builder = builder.body(body);
    }

    // Watchdog around the full exchange (defense in depth atop client timeout).
    tokio::time::timeout(WATCHDOG_TIMEOUT, send_and_drain(builder))
        .await
        .map_err(|_| ExternalError::ConnectFailed("HTTP request timed out".to_owned()))?
}

/// Attach the vault-managed credential. The value is never logged.
fn apply_auth(builder: reqwest::RequestBuilder, auth: HttpAuth) -> reqwest::RequestBuilder {
    match auth {
        HttpAuth::Bearer(token) => {
            debug!(auth_variant = "bearer", "applying auth header");
            builder.header(header::AUTHORIZATION, format!("Bearer {token}"))
        }
        HttpAuth::Basic { user, pass } => {
            debug!(auth_variant = "basic", "applying auth header");
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            builder.header(header::AUTHORIZATION, format!("Basic {encoded}"))
        }
        HttpAuth::None => {
            debug!(auth_variant = "none", "no auth header applied");
            builder
        }
    }
}

/// Send the request and collect a length-bounded response.
async fn send_and_drain(builder: reqwest::RequestBuilder) -> Result<HttpResponse, ExternalError> {
    let response = builder.send().await.map_err(|e| {
        if e.is_connect() || e.is_timeout() {
            ExternalError::ConnectFailed(format!("HTTP connect failed: {e}"))
        } else {
            ExternalError::Backend(format!("HTTP request error: {e}"))
        }
    })?;

    let status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_owned(), v.to_owned()))
        })
        .collect();

    let body = read_capped_body(response).await?;
    debug!(status, body_bytes = body.len(), "HTTP response received");

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// Drain the response body, aborting if it exceeds [`MAX_BODY_BYTES`].
///
/// Checks the advertised `Content-Length` for a fast reject, then enforces the
/// same ceiling while streaming so an absent or dishonest `Content-Length`
/// cannot bypass the limit.
async fn read_capped_body(mut response: Response) -> Result<Vec<u8>, ExternalError> {
    if let Some(len) = response.content_length() {
        if len > MAX_BODY_BYTES as u64 {
            return Err(ExternalError::OperationFailed(format!(
                "response Content-Length {len} exceeds limit of {MAX_BODY_BYTES} bytes"
            )));
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ExternalError::Backend(format!("failed to read HTTP response body: {e}")))?
    {
        if buf.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(ExternalError::OperationFailed(format!(
                "response body exceeds limit of {MAX_BODY_BYTES} bytes"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::{MAX_BODY_BYTES, http_request};
    use crate::build_http_client;
    use crate::destination_policy::DestinationPolicy;
    use merkle_ports::{ExternalError, HttpAuth, HttpRequestSpec};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn get_spec(url: String) -> HttpRequestSpec {
        HttpRequestSpec {
            method: "GET".to_owned(),
            url,
            headers: vec![],
            body: None,
        }
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; MAX_BODY_BYTES + 1]))
            .mount(&server)
            .await;

        let err = http_request(
            &build_http_client(),
            &DestinationPolicy::permissive(),
            get_spec(format!("{}/big", server.uri())),
            HttpAuth::None,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ExternalError::OperationFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn within_limit_body_is_accepted() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello".to_vec()))
            .mount(&server)
            .await;

        let resp = http_request(
            &build_http_client(),
            &DestinationPolicy::permissive(),
            get_spec(format!("{}/ok", server.uri())),
            HttpAuth::None,
        )
        .await
        .expect("small body accepted");

        assert_eq!(resp.body, b"hello");
    }

    #[tokio::test]
    async fn strict_policy_blocks_loopback_before_request() {
        // Strict policy must reject the loopback mock server URL outright,
        // proving validation happens before any request (and any credential) is
        // sent. The server therefore receives nothing.
        let server = MockServer::start().await;
        let err = http_request(
            &build_http_client(),
            &DestinationPolicy::strict(),
            get_spec(format!("{}/blocked", server.uri())),
            HttpAuth::Bearer("super-secret".to_owned()),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ExternalError::OperationFailed(_)), "{err:?}");
    }
}
