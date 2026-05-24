//! HTTP request implementation using `reqwest` with rustls (no OpenSSL).
//!
//! Auth material (`Bearer` token or `Basic` credentials) is injected as an
//! `Authorization` header inside the agent process. The plaintext credential
//! never crosses the MCP transport or appears in log output (tracing spans
//! record only the auth variant, not the value).

use base64::Engine as _;
use reqwest::{Client, Method, header};
use tracing::{debug, instrument};

use merkle_ports::{ExternalError, HttpAuth, HttpRequestSpec, HttpResponse};

/// Execute an HTTP request described by `spec`, applying `auth` as the
/// `Authorization` header.
///
/// The `client` is expected to be pre-built with `rustls` and connection
/// pooling; callers should share a single instance (see `ExternalServicesAdapter`).
#[instrument(skip(client, spec, auth), fields(method = %spec.method, url = %spec.url))]
pub(crate) async fn http_request(
    client: &Client,
    spec: HttpRequestSpec,
    auth: HttpAuth,
) -> Result<HttpResponse, ExternalError> {
    let method = spec.method.parse::<Method>().map_err(|e| {
        ExternalError::OperationFailed(format!("invalid HTTP method {:?}: {e}", spec.method))
    })?;

    let mut builder = client.request(method, &spec.url);

    // Apply caller-supplied headers.
    for (name, value) in &spec.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }

    // Apply auth — value is NOT logged.
    builder = match auth {
        HttpAuth::Bearer(token) => {
            debug!(auth_variant = "bearer", "applying auth header");
            builder.header(
                header::AUTHORIZATION,
                format!("Bearer {token}"),
            )
        }
        HttpAuth::Basic { user, pass } => {
            debug!(auth_variant = "basic", "applying auth header");
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(format!("{user}:{pass}"));
            builder.header(
                header::AUTHORIZATION,
                format!("Basic {encoded}"),
            )
        }
        HttpAuth::None => {
            debug!(auth_variant = "none", "no auth header applied");
            builder
        }
    };

    // Apply optional body.
    if let Some(body) = spec.body {
        builder = builder.body(body);
    }

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

    let body = response.bytes().await.map_err(|e| {
        ExternalError::Backend(format!("failed to read HTTP response body: {e}"))
    })?;

    debug!(status, body_bytes = body.len(), "HTTP response received");

    Ok(HttpResponse {
        status,
        headers,
        body: body.into(),
    })
}
