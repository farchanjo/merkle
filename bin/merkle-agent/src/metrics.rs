//! Prometheus metrics registry and HTTP `/metrics` endpoint.
//!
//! Declares the core metrics catalog from
//! `docs/arch/operations/observability.md` Section 2, "Core Metrics".
//!
//! ## Design
//!
//! - A single `prometheus::Registry` is created at agent start.
//! - Each adapter/module that increments a counter or sets a gauge imports
//!   the handle from this module via [`core()`].
//! - The `/metrics` HTTP endpoint encodes the registry in the Prometheus
//!   text exposition format and serves it on localhost only.
//!
//! For Phase 4, we declare the registry and the full core metrics catalog.
//! Per-operation wiring (incrementing on each request) is Phase 5 polish.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::Context as _;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounterVec,
    Opts, Registry,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::MetricsConfig;

// ---------------------------------------------------------------------------
// Global registry + core metrics
// ---------------------------------------------------------------------------

static REGISTRY: OnceLock<Registry> = OnceLock::new();
static CORE_METRICS: OnceLock<CoreMetrics> = OnceLock::new();

/// Return the global Prometheus registry, initialised by [`init`].
///
/// # Panics
///
/// Panics if called before [`init`].
pub fn registry() -> &'static Registry {
    REGISTRY
        .get()
        .expect("metrics registry not initialised; call metrics::init() first")
}

/// Return `true` when the metrics registry has been successfully initialised.
///
/// Use this guard before calling [`core`] in background tasks that should
/// run even when metrics are disabled.
pub fn is_enabled() -> bool {
    REGISTRY.get().is_some()
}

/// Return the global `CoreMetrics` handles, initialised by [`init`].
///
/// # Panics
///
/// Panics if called before [`init`].
pub fn core() -> &'static CoreMetrics {
    CORE_METRICS
        .get()
        .expect("core metrics not initialised; call metrics::init() first")
}

// ---------------------------------------------------------------------------
// Core metrics catalog
// ---------------------------------------------------------------------------

/// Handles to all core metrics declared in the observability catalog.
///
/// Each field corresponds to one entry in the core metrics catalog from
/// `docs/arch/operations/observability.md` §2. Adapters and handlers
/// increment these handles in Phase 5.
// All fields are registered in the Prometheus registry at init() time.
// Phase 5 wires the increment calls from each handler.
#[expect(
    dead_code,
    reason = "Phase 5 wires per-operation increment calls from adapters"
)]
pub struct CoreMetrics {
    /// Count of live Secrets per namespace and category.
    pub secrets_total: GaugeVec,
    /// Cumulative Audit Entries written since agent start.
    pub audit_entries_total: Counter,
    /// Cumulative Use Tokens issued.
    pub use_tokens_issued_total: Counter,
    /// Cumulative Use Tokens resolved via Companion Socket.
    pub use_tokens_consumed_total: Counter,
    /// Use Tokens that expired without being consumed.
    pub use_tokens_expired_total: Counter,
    /// Reveal operations by sensitivity and outcome.
    pub reveals_total: CounterVec,
    /// Seconds since the last successful backup.
    pub backup_age_seconds: Gauge,
    /// Chain verifications by outcome (`ok` | `broken`).
    pub chain_verifications_total: CounterVec,
    /// Rate limit rejections by class.
    pub rate_limit_denials_total: CounterVec,
    /// Companion Socket connection attempts by outcome.
    pub companion_socket_connects_total: CounterVec,
    /// 1 if last chain verification passed, 0 otherwise.
    pub chain_integrity_ok: Gauge,
    /// RPC requests by op and outcome.
    pub rpc_requests_total: IntCounterVec,
    /// RPC errors by op and error_type.
    pub rpc_errors_total: IntCounterVec,
    /// RPC duration histogram by op.
    pub rpc_duration_seconds: HistogramVec,
    /// Restore operations by outcome.
    pub restore_total: CounterVec,
    /// Unseal attempts by outcome.
    pub unseal_total: CounterVec,
    /// Restore duration histogram.
    pub restore_duration_seconds: Histogram,
    /// 1 if WAL durability invariants passed, 0 otherwise.
    pub durability_invariants_ok: Gauge,
    /// 1 if OOB notifier is healthy, 0 otherwise.
    pub oob_notifier_available: Gauge,
}

// ---------------------------------------------------------------------------
// Initialiser
// ---------------------------------------------------------------------------

/// Initialise the Prometheus registry and register all core metrics.
///
/// Call once at process startup before spawning any tasks that emit metrics.
///
/// # Errors
///
/// Returns an error if a metric cannot be registered (name collision, invalid
/// label cardinality).
pub fn init(cfg: &MetricsConfig) -> anyhow::Result<()> {
    if !cfg.enabled {
        tracing::debug!("metrics disabled by config; skipping registry init");
        return Ok(());
    }

    let registry =
        Registry::new_custom(None, None).context("failed to create prometheus registry")?;

    let metrics =
        register_counters_and_gauges(&registry).context("failed to register counters/gauges")?;
    let metrics =
        register_histograms(registry, metrics).context("failed to register histograms")?;

    REGISTRY
        .set(metrics.0)
        .map_err(|_| anyhow::anyhow!("metrics registry already initialised"))?;
    CORE_METRICS
        .set(metrics.1)
        .map_err(|_| anyhow::anyhow!("core metrics already initialised"))?;

    info!(port = cfg.port, "metrics registry initialised");
    Ok(())
}

// ---------------------------------------------------------------------------
// Registration helpers (split to keep functions within the 100-line limit)
// ---------------------------------------------------------------------------

/// Standard duration buckets for RPC operations (1 ms … 5 s).
const RPC_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Duration buckets for restore operations (1 s … 120 s, SLO < 60 s).
const RESTORE_BUCKETS: &[f64] = &[1.0, 5.0, 10.0, 20.0, 30.0, 45.0, 60.0, 120.0];

/// Intermediate builder — holds the registry + all counter/gauge handles.
struct MetricsBuilder {
    registry: Registry,
    secrets_total: GaugeVec,
    audit_entries_total: Counter,
    use_tokens_issued_total: Counter,
    use_tokens_consumed_total: Counter,
    use_tokens_expired_total: Counter,
    reveals_total: CounterVec,
    backup_age_seconds: Gauge,
    chain_verifications_total: CounterVec,
    rate_limit_denials_total: CounterVec,
    companion_socket_connects_total: CounterVec,
    chain_integrity_ok: Gauge,
    rpc_requests_total: IntCounterVec,
    rpc_errors_total: IntCounterVec,
    restore_total: CounterVec,
    unseal_total: CounterVec,
    durability_invariants_ok: Gauge,
    oob_notifier_available: Gauge,
}

/// Secret + Use-Token lifecycle metrics (5 entries from the catalog).
#[expect(
    clippy::struct_field_names,
    reason = "field names mirror Prometheus metric names from observability.md \
              §2; the shared `_total` postfix is the standard counter convention"
)]
struct SecretTokenMetrics {
    secrets_total: GaugeVec,
    audit_entries_total: Counter,
    use_tokens_issued_total: Counter,
    use_tokens_consumed_total: Counter,
    use_tokens_expired_total: Counter,
}

/// Reveal + chain + companion-socket metrics (6 entries from the catalog).
struct RevealChainMetrics {
    reveals_total: CounterVec,
    backup_age_seconds: Gauge,
    chain_verifications_total: CounterVec,
    rate_limit_denials_total: CounterVec,
    companion_socket_connects_total: CounterVec,
    chain_integrity_ok: Gauge,
}

/// Operational / RPC + recovery metrics (6 entries from the catalog).
struct OperationalMetrics {
    rpc_requests_total: IntCounterVec,
    rpc_errors_total: IntCounterVec,
    restore_total: CounterVec,
    unseal_total: CounterVec,
    durability_invariants_ok: Gauge,
    oob_notifier_available: Gauge,
}

/// Register one metric into the registry and return the handle on success.
///
/// Generic helper that captures the `register → clone → return` pattern
/// used by every entry in the catalog so the per-subset functions stay
/// declarative.
fn reg<M>(r: &Registry, metric: M, name: &str) -> anyhow::Result<M>
where
    M: prometheus::core::Collector + Clone + 'static,
{
    r.register(Box::new(metric.clone()))
        .with_context(|| format!("register {name}"))?;
    Ok(metric)
}

fn register_secret_token_metrics(r: &Registry) -> anyhow::Result<SecretTokenMetrics> {
    let secrets_total = reg(
        r,
        GaugeVec::new(
            Opts::new(
                "merkle_secrets_total",
                "Live Secrets per namespace and category",
            ),
            &["namespace", "category"],
        )?,
        "merkle_secrets_total",
    )?;
    let audit_entries_total = reg(
        r,
        Counter::with_opts(Opts::new(
            "merkle_audit_entries_total",
            "Cumulative Audit Entries written since agent start",
        ))?,
        "merkle_audit_entries_total",
    )?;
    let use_tokens_issued_total = reg(
        r,
        Counter::with_opts(Opts::new(
            "merkle_use_tokens_issued_total",
            "Cumulative Use Tokens issued",
        ))?,
        "merkle_use_tokens_issued_total",
    )?;
    let use_tokens_consumed_total = reg(
        r,
        Counter::with_opts(Opts::new(
            "merkle_use_tokens_consumed_total",
            "Cumulative Use Tokens resolved via Companion Socket",
        ))?,
        "merkle_use_tokens_consumed_total",
    )?;
    let use_tokens_expired_total = reg(
        r,
        Counter::with_opts(Opts::new(
            "merkle_use_tokens_expired_total",
            "Use Tokens that expired without being consumed",
        ))?,
        "merkle_use_tokens_expired_total",
    )?;

    Ok(SecretTokenMetrics {
        secrets_total,
        audit_entries_total,
        use_tokens_issued_total,
        use_tokens_consumed_total,
        use_tokens_expired_total,
    })
}

fn register_reveal_chain_metrics(r: &Registry) -> anyhow::Result<RevealChainMetrics> {
    let reveals_total = reg(
        r,
        CounterVec::new(
            Opts::new(
                "merkle_reveals_total",
                "Reveal operations by sensitivity and outcome",
            ),
            &["sensitivity", "outcome"],
        )?,
        "merkle_reveals_total",
    )?;
    let backup_age_seconds = reg(
        r,
        Gauge::with_opts(Opts::new(
            "merkle_backup_age_seconds",
            "Seconds since the last successful backup",
        ))?,
        "merkle_backup_age_seconds",
    )?;
    let chain_verifications_total = reg(
        r,
        CounterVec::new(
            Opts::new(
                "merkle_chain_verifications_total",
                "Chain verifications run by outcome",
            ),
            &["outcome"],
        )?,
        "merkle_chain_verifications_total",
    )?;
    let rate_limit_denials_total = reg(
        r,
        CounterVec::new(
            Opts::new(
                "merkle_rate_limit_denials_total",
                "Rate limit rejections per class",
            ),
            &["class"],
        )?,
        "merkle_rate_limit_denials_total",
    )?;
    let companion_socket_connects_total = reg(
        r,
        CounterVec::new(
            Opts::new(
                "merkle_companion_socket_connects_total",
                "Companion Socket connection attempts by outcome",
            ),
            &["outcome"],
        )?,
        "merkle_companion_socket_connects_total",
    )?;
    let chain_integrity_ok = reg(
        r,
        Gauge::with_opts(Opts::new(
            "merkle_chain_integrity_ok",
            "1 if last chain verification passed, 0 if broken or unknown",
        ))?,
        "merkle_chain_integrity_ok",
    )?;
    // Default: unknown → 0 until the first background verification pass.
    chain_integrity_ok.set(0.0);

    Ok(RevealChainMetrics {
        reveals_total,
        backup_age_seconds,
        chain_verifications_total,
        rate_limit_denials_total,
        companion_socket_connects_total,
        chain_integrity_ok,
    })
}

fn register_operational_metrics(r: &Registry) -> anyhow::Result<OperationalMetrics> {
    let rpc_requests_total = reg(
        r,
        IntCounterVec::new(
            Opts::new(
                "merkle_rpc_requests_total",
                "Total RPC requests by op and outcome",
            ),
            &["op", "outcome"],
        )?,
        "merkle_rpc_requests_total",
    )?;
    let rpc_errors_total = reg(
        r,
        IntCounterVec::new(
            Opts::new("merkle_rpc_errors_total", "RPC errors by op and error_type"),
            &["op", "error_type"],
        )?,
        "merkle_rpc_errors_total",
    )?;
    let restore_total = reg(
        r,
        CounterVec::new(
            Opts::new("merkle_restore_total", "Restore operations by outcome"),
            &["outcome"],
        )?,
        "merkle_restore_total",
    )?;
    let unseal_total = reg(
        r,
        CounterVec::new(
            Opts::new("merkle_unseal_total", "Unseal attempts by outcome"),
            &["outcome"],
        )?,
        "merkle_unseal_total",
    )?;
    let durability_invariants_ok = reg(
        r,
        Gauge::with_opts(Opts::new(
            "merkle_durability_invariants_ok",
            "1 if all WAL durability invariants passed",
        ))?,
        "merkle_durability_invariants_ok",
    )?;
    let oob_notifier_available = reg(
        r,
        Gauge::with_opts(Opts::new(
            "merkle_oob_notifier_available",
            "1 if the OOB Notifier is reachable and healthy",
        ))?,
        "merkle_oob_notifier_available",
    )?;

    Ok(OperationalMetrics {
        rpc_requests_total,
        rpc_errors_total,
        restore_total,
        unseal_total,
        durability_invariants_ok,
        oob_notifier_available,
    })
}

fn register_counters_and_gauges(r: &Registry) -> anyhow::Result<MetricsBuilder> {
    let secret_token = register_secret_token_metrics(r)?;
    let reveal_chain = register_reveal_chain_metrics(r)?;
    let operational = register_operational_metrics(r)?;

    Ok(MetricsBuilder {
        registry: r.clone(),
        secrets_total: secret_token.secrets_total,
        audit_entries_total: secret_token.audit_entries_total,
        use_tokens_issued_total: secret_token.use_tokens_issued_total,
        use_tokens_consumed_total: secret_token.use_tokens_consumed_total,
        use_tokens_expired_total: secret_token.use_tokens_expired_total,
        reveals_total: reveal_chain.reveals_total,
        backup_age_seconds: reveal_chain.backup_age_seconds,
        chain_verifications_total: reveal_chain.chain_verifications_total,
        rate_limit_denials_total: reveal_chain.rate_limit_denials_total,
        companion_socket_connects_total: reveal_chain.companion_socket_connects_total,
        chain_integrity_ok: reveal_chain.chain_integrity_ok,
        rpc_requests_total: operational.rpc_requests_total,
        rpc_errors_total: operational.rpc_errors_total,
        restore_total: operational.restore_total,
        unseal_total: operational.unseal_total,
        durability_invariants_ok: operational.durability_invariants_ok,
        oob_notifier_available: operational.oob_notifier_available,
    })
}

fn register_histograms(r: Registry, b: MetricsBuilder) -> anyhow::Result<(Registry, CoreMetrics)> {
    macro_rules! reg {
        ($metric:expr) => {{
            let m = $metric;
            b.registry
                .register(Box::new(m.clone()))
                .context(concat!("register ", stringify!($metric)))?;
            m
        }};
    }

    let rpc_duration_seconds = reg!(HistogramVec::new(
        HistogramOpts::new(
            "merkle_rpc_duration_seconds",
            "RPC duration histogram per op"
        )
        .buckets(RPC_BUCKETS.to_vec()),
        &["op"],
    )?);
    let restore_duration_seconds = reg!(Histogram::with_opts(
        HistogramOpts::new(
            "merkle_restore_duration_seconds",
            "Restore duration histogram (SLI: RTO < 60 s)",
        )
        .buckets(RESTORE_BUCKETS.to_vec()),
    )?);

    let metrics = CoreMetrics {
        secrets_total: b.secrets_total,
        audit_entries_total: b.audit_entries_total,
        use_tokens_issued_total: b.use_tokens_issued_total,
        use_tokens_consumed_total: b.use_tokens_consumed_total,
        use_tokens_expired_total: b.use_tokens_expired_total,
        reveals_total: b.reveals_total,
        backup_age_seconds: b.backup_age_seconds,
        chain_verifications_total: b.chain_verifications_total,
        rate_limit_denials_total: b.rate_limit_denials_total,
        companion_socket_connects_total: b.companion_socket_connects_total,
        chain_integrity_ok: b.chain_integrity_ok,
        rpc_requests_total: b.rpc_requests_total,
        rpc_errors_total: b.rpc_errors_total,
        rpc_duration_seconds,
        restore_total: b.restore_total,
        unseal_total: b.unseal_total,
        restore_duration_seconds,
        durability_invariants_ok: b.durability_invariants_ok,
        oob_notifier_available: b.oob_notifier_available,
    };

    Ok((r, metrics))
}

// ---------------------------------------------------------------------------
// HTTP `/metrics` server
// ---------------------------------------------------------------------------

/// Shared handler state — carries the optional bearer token guarding access.
#[derive(Clone)]
struct MetricsState {
    /// `Some` enforces `Authorization: Bearer <token>` on every request.
    token: Option<Arc<str>>,
}

/// Resolve and validate the metrics bind address.
///
/// The Prometheus registry exposes namespace labels and live secret counts, so
/// it must never be reachable off-host without authentication. A non-loopback
/// host (e.g. `0.0.0.0`) is therefore only permitted when an explicit
/// `auth_token` is configured.
///
/// # Errors
///
/// Returns an error if `host:port` does not parse, or if the address is
/// non-loopback while no `auth_token` is set.
fn resolve_listen_addr(cfg: &MetricsConfig) -> anyhow::Result<SocketAddr> {
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port)
        .parse()
        .with_context(|| format!("invalid metrics bind address {}:{}", cfg.host, cfg.port))?;

    if !addr.ip().is_loopback() && cfg.auth_token.is_none() {
        anyhow::bail!(
            "refusing to bind metrics endpoint to non-loopback host {} without \
             an auth token: the registry leaks namespace labels and secret \
             counts. Set [metrics] auth_token, or bind 127.0.0.1.",
            addr.ip()
        );
    }
    Ok(addr)
}

/// Serve Prometheus `/metrics` on `cfg.host:cfg.port` until `shutdown` fires.
///
/// No-op when `cfg.enabled` is `false`. Binds loopback-only unless an
/// `auth_token` is configured (see [`resolve_listen_addr`]); when a token is
/// set it is enforced on every request.
///
/// # Errors
///
/// Returns an error if the bind address is rejected, the TCP listener cannot be
/// bound, or `axum::serve` exits with an I/O error.
pub async fn serve_task(cfg: MetricsConfig, shutdown: CancellationToken) -> anyhow::Result<()> {
    if !cfg.enabled {
        tracing::debug!("metrics server disabled; task exiting");
        shutdown.cancelled().await;
        return Ok(());
    }

    let addr = resolve_listen_addr(&cfg)?;

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot bind metrics server on {addr}"))?;

    info!(
        addr = %addr,
        auth = cfg.auth_token.is_some(),
        "metrics HTTP server listening"
    );

    let state = MetricsState {
        token: cfg.auth_token.as_deref().map(Arc::from),
    };
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("metrics HTTP server error")?;

    Ok(())
}

/// Constant-time byte comparison to avoid leaking the token via response timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Return `true` when no token is required, or when the request presents the
/// matching `Authorization: Bearer <token>` header.
fn is_authorized(headers: &HeaderMap, token: Option<&str>) -> bool {
    let Some(expected) = token else {
        return true;
    };
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|presented| constant_time_eq(presented.as_bytes(), expected.as_bytes()))
}

async fn metrics_handler(
    State(state): State<MetricsState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    use prometheus::Encoder as _;

    if !is_authorized(&headers, state.token.as_deref()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let encoder = prometheus::TextEncoder::new();
    let mut buf = Vec::new();

    match encoder.encode(&registry().gather(), &mut buf) {
        Ok(()) => (StatusCode::OK, buf).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to encode prometheus metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod register_refactor_tests {
    use super::{
        Registry, register_operational_metrics, register_reveal_chain_metrics,
        register_secret_token_metrics,
    };

    // Note: `Registry::gather()` only emits a MetricFamily for *Vec collectors
    // once at least one label set has been observed. Each test touches every
    // Vec it expects to see so the count assertion reflects all registered
    // collectors, not just the always-present plain Counters/Gauges.

    #[test]
    fn secret_token_metrics_register_five_into_registry() {
        let r = Registry::new();
        let m = register_secret_token_metrics(&r).expect("secret/token metrics register");
        m.secrets_total.with_label_values(&["t", "t"]);
        // 5 metrics: secrets_total, audit_entries_total, use_tokens (×3).
        assert_eq!(r.gather().len(), 5);
    }

    #[test]
    fn reveal_chain_metrics_register_six_into_registry() {
        let r = Registry::new();
        let m = register_reveal_chain_metrics(&r).expect("reveal/chain metrics register");
        m.reveals_total.with_label_values(&["t", "t"]);
        m.chain_verifications_total.with_label_values(&["t"]);
        m.rate_limit_denials_total.with_label_values(&["t"]);
        m.companion_socket_connects_total.with_label_values(&["t"]);
        // 6 metrics: reveals, backup_age, chain_verif, rate_limit, companion, integrity.
        assert_eq!(r.gather().len(), 6);
    }

    #[test]
    fn operational_metrics_register_six_into_registry() {
        let r = Registry::new();
        let m = register_operational_metrics(&r).expect("operational metrics register");
        m.rpc_requests_total.with_label_values(&["t", "t"]);
        m.rpc_errors_total.with_label_values(&["t", "t"]);
        m.restore_total.with_label_values(&["t"]);
        m.unseal_total.with_label_values(&["t"]);
        // 6 metrics: rpc_req, rpc_err, restore, unseal, durability, oob.
        assert_eq!(r.gather().len(), 6);
    }

    #[test]
    fn full_counter_gauge_catalog_has_seventeen_entries() {
        let r = Registry::new();
        let st = register_secret_token_metrics(&r).expect("secret/token metrics register");
        let rc = register_reveal_chain_metrics(&r).expect("reveal/chain metrics register");
        let op = register_operational_metrics(&r).expect("operational metrics register");
        st.secrets_total.with_label_values(&["t", "t"]);
        rc.reveals_total.with_label_values(&["t", "t"]);
        rc.chain_verifications_total.with_label_values(&["t"]);
        rc.rate_limit_denials_total.with_label_values(&["t"]);
        rc.companion_socket_connects_total.with_label_values(&["t"]);
        op.rpc_requests_total.with_label_values(&["t", "t"]);
        op.rpc_errors_total.with_label_values(&["t", "t"]);
        op.restore_total.with_label_values(&["t"]);
        op.unseal_total.with_label_values(&["t"]);
        // 5 + 6 + 6 = 17 counter/gauge entries from observability.md §2.
        assert_eq!(r.gather().len(), 17);
    }
}

#[cfg(test)]
mod metrics_security_tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{constant_time_eq, is_authorized, resolve_listen_addr};
    use crate::config::MetricsConfig;

    fn cfg(host: &str, auth_token: Option<&str>) -> MetricsConfig {
        MetricsConfig {
            enabled: true,
            port: 9117,
            host: host.to_owned(),
            auth_token: auth_token.map(str::to_owned),
        }
    }

    #[test]
    fn loopback_default_binds() {
        let addr = resolve_listen_addr(&cfg("127.0.0.1", None)).expect("loopback must bind");
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn ipv6_loopback_binds() {
        // IPv6 literals are bracketed in the `host:port` form.
        let addr = resolve_listen_addr(&cfg("[::1]", None)).expect("ipv6 loopback must bind");
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn non_loopback_without_token_is_refused() {
        // GAP-001: never expose the registry off-host without auth.
        let err = resolve_listen_addr(&cfg("0.0.0.0", None))
            .expect_err("0.0.0.0 without token must be refused");
        assert!(err.to_string().contains("non-loopback"), "got: {err}");
    }

    #[test]
    fn non_loopback_with_token_is_allowed() {
        let addr =
            resolve_listen_addr(&cfg("0.0.0.0", Some("tok"))).expect("token unlocks non-loopback");
        assert!(!addr.ip().is_loopback());
    }

    #[test]
    fn authorization_required_when_token_set() {
        let mut headers = HeaderMap::new();
        // No header → unauthorized.
        assert!(!is_authorized(&headers, Some("s3cret")));
        // Wrong token → unauthorized.
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer nope"),
        );
        assert!(!is_authorized(&headers, Some("s3cret")));
        // Correct token → authorized.
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer s3cret"),
        );
        assert!(is_authorized(&headers, Some("s3cret")));
    }

    #[test]
    fn no_token_means_open_on_loopback() {
        let headers = HeaderMap::new();
        assert!(is_authorized(&headers, None));
    }

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
