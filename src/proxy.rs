use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::{Method, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

use tracing::Instrument;

use crate::segment::{self, BoxBody};
use crate::state::Shared;

/// Process-wide request counter so concurrent downloads of the same URL
/// stay distinguishable in logs.
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Percent-decode `%XX` (raw bytes) plus form `+` → space, decoded as UTF-8
/// lossily so non-ASCII URLs survive instead of becoming mojibake chars.
fn percent_decode(src: &str) -> Vec<u8> {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hi = (b[i + 1] as char).to_digit(16);
                let lo = (b[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4 | l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn fetch_query_target(path_and_query: &str) -> Option<Uri> {
    let q = path_and_query.split_once('?')?.1;
    for pair in q.split('&') {
        if let Some(v) = pair.strip_prefix("url=") {
            let raw = percent_decode(v);
            let target: Uri = String::from_utf8_lossy(&raw).parse().ok()?;
            // Same privilege as the forward proxy, but refuse non-HTTP
            // schemes outright (no file://, gopher://, ...).
            match target.scheme_str() {
                Some("http") | Some("https")
                    if !target
                        .authority()
                        .is_some_and(|authority| authority.as_str().contains('@')) =>
                {
                    return Some(target);
                }
                _ => return None,
            }
        }
    }
    None
}

/// Split a CONNECT authority into URI-safe host (brackets kept for IPv6),
/// bare host for cert SANs, port, and origin scheme (http only for :80).
fn split_authority(authority: &http::uri::Authority) -> (String, String, u16, &'static str) {
    let host = authority.host();
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let port = authority.port_u16().unwrap_or(443);
    let scheme = if port == 80 { "http" } else { "https" };
    (host.to_owned(), bare.to_owned(), port, scheme)
}

/// Logging-only redaction for CONNECT authorities: strip possible
/// `user:pass@` so credentials never land in spans or logs. Dialing always
/// uses the full authority.
fn redact_authority(authority: &str) -> String {
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("[redacted]@{host}"),
        None => authority.to_owned(),
    }
}

fn bad_request() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(segment::empty_body())
        .unwrap()
}

fn method_not_allowed() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(
            http::header::ALLOW,
            "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
        )
        .body(segment::empty_body())
        .unwrap()
}

fn forbidden() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(segment::empty_body())
        .unwrap()
}

/// GET requests carry no meaningful body for this proxy, but an unread one
/// forces hyper to close an otherwise reusable downstream connection. Drain
/// a bounded prefix in the background; the response path never waits for it.
fn drain_get_body(body: Incoming, shared: &Shared) {
    let timeout = Duration::from_secs(shared.cfg.timeout_secs.max(1));
    tokio::spawn(segment::drain_limited(body, timeout, 8192));
}

fn overloaded() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(http::header::RETRY_AFTER, "5")
        .body(segment::empty_body())
        .unwrap()
}

/// One downstream connection. Always returns a well-formed HTTP response so
/// the client socket stays clean; origin trouble becomes 502/truncation.
pub async fn handle(
    req: Request<Incoming>,
    shared: Shared,
) -> Result<Response<BoxBody>, std::convert::Infallible> {
    if req.method() == Method::TRACE {
        return Ok(method_not_allowed());
    }
    if req.method() == Method::CONNECT {
        let raw = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        // Normalize before any dial, cert, or log line ever sees the raw
        // value: refuse userinfo (credentials must never route) and empty
        // hosts. The normalized `host:port` form flows downstream so the
        // tunnel dial and the MITM target rebuild agree byte-for-byte.
        let parsed: http::uri::Authority = match raw.parse() {
            Ok(a) => a,
            Err(_) => return Ok(bad_request()),
        };
        if parsed.host().is_empty() || raw.contains('@') {
            return Ok(bad_request());
        }
        let port: u16 = parsed.port_u16().unwrap_or(443);
        let authority = if parsed.port_u16().is_some() {
            parsed.to_string()
        } else {
            format!("{parsed}:{port}")
        };
        if !shared.allowed_ports.contains(&port) {
            let n = shared.metrics.refused.fetch_add(1, Ordering::Relaxed) + 1;
            if crate::state::sample_hit(n, 100) {
                tracing::warn!(
                    authority = %redact_authority(&authority),
                    total = n,
                    "CONNECT port denied"
                );
            }
            return Ok(forbidden());
        }
        // Bound CONNECT sessions independently from active downloads.
        let Ok(tunnel_permit) = shared.tunnels.clone().try_acquire_owned() else {
            shared.metrics.refused.fetch_add(1, Ordering::Relaxed);
            return Ok(overloaded());
        };
        let req_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let span =
            tracing::debug_span!("connect", req_id, authority = %redact_authority(&authority));
        // `hyper::upgrade::on` takes the whole request; spawn so we can
        // answer 200 immediately and work on the upgraded stream.
        shared.upgrades.spawn(
            connect_task(req, shared.clone(), authority, port, tunnel_permit).instrument(span),
        );
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(segment::empty_body())
            .unwrap());
    }

    let (parts, body) = req.into_parts();
    let uri = parts.uri.clone();

    // Operator endpoint, only for requests addressed to the proxy itself
    // (origin-form, no scheme). Absolute-form proxy traffic is never hijacked.
    if parts.method == Method::GET && uri.scheme().is_none() && uri.path() == "/__stats" {
        let json = shared.metrics.render_json_with_egress(
            shared.started.elapsed().as_secs(),
            &shared.origin.egress_json(),
        );
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(segment::string_body(json))
            .unwrap());
    }

    // Reverse-proxy helper: `GET http://127.0.0.1:8080/__fetch?url=<https://...>`
    // No CONNECT, no certs. Useful when client certificate verification is
    // inconvenient.
    if parts.method == Method::GET && uri.scheme().is_none() && uri.path() == "/__fetch" {
        if let Some(target) = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .and_then(fetch_query_target)
        {
            if segment::has_ambiguous_framing(&parts.headers) {
                return Ok(bad_request());
            }
            // Global download cap: fail fast with a retryable 503 rather
            // than queueing unboundedly.
            let Ok(permit) = shared.downloads.clone().try_acquire_owned() else {
                shared.metrics.refused.fetch_add(1, Ordering::Relaxed);
                return Ok(overloaded());
            };
            let req_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
            let span =
                tracing::debug_span!("download", req_id, target = %segment::redact_uri(&target));
            let range = parts.headers.get(http::header::RANGE).cloned();
            drain_get_body(body, &shared);
            let cancel = CancellationToken::new();
            let response = segment::serve_get_with_cancel(
                shared,
                target,
                parts.headers,
                range,
                cancel.clone(),
            )
            .instrument(span)
            .await;
            return Ok(segment::guard_response(response, permit, cancel));
        }
        return Ok(bad_request());
    }

    if uri.scheme().is_some() {
        if uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Ok(bad_request());
        }
        // Forward-proxy absolute-form: `GET http://host/path`.
        if segment::has_ambiguous_framing(&parts.headers) {
            return Ok(bad_request());
        }
        let Ok(permit) = shared.downloads.clone().try_acquire_owned() else {
            shared.metrics.refused.fetch_add(1, Ordering::Relaxed);
            return Ok(overloaded());
        };
        if parts.method == Method::GET {
            let req_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
            let span = tracing::debug_span!("download", req_id, target = %segment::redact_uri(&uri), method = "GET");
            let range = parts.headers.get(http::header::RANGE).cloned();
            drain_get_body(body, &shared);
            let cancel = CancellationToken::new();
            let response =
                segment::serve_get_with_cancel(shared, uri, parts.headers, range, cancel.clone())
                    .instrument(span)
                    .await;
            return Ok(segment::guard_response(response, permit, cancel));
        }
        let headers = segment::passthrough_headers(&parts.headers);
        let response = segment::serve_other(shared, parts.method, uri, headers, body.boxed()).await;
        return Ok(segment::guard_response(
            response,
            permit,
            CancellationToken::new(),
        ));
    }

    Ok(bad_request())
}

async fn connect_task(
    req: Request<Incoming>,
    shared: Shared,
    authority: String,
    port: u16,
    conn_permit: OwnedSemaphorePermit,
) {
    // Failure warns are sampled: permits bound concurrency but not flip
    // rate, so a fast-failing loop must not fill the disk.
    macro_rules! sampled_fail {
        ($metrics:expr, $authority:expr, $e:expr, $what:literal) => {{
            let n = $metrics
                .connect_errors
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            if crate::state::sample_hit(n, 100) {
                tracing::warn!(
                    authority = %redact_authority($authority),
                    error = %$e,
                    total = n,
                    concat!($what, " failed")
                );
            }
        }};
    }
    // MITM only where TLS is expected: for other allowed ports the proxy
    // cannot know whether the origin speaks TLS or plaintext, so a plain
    // tunnel is the safe default (works for both).
    if !shared.cfg.tunnel_only
        && shared.mitm_ports.contains(&port)
        && let Some(ca) = shared.ca.clone()
    {
        let metrics = shared.metrics.clone();
        if let Err(e) = mitm(req, &authority, shared, &ca, conn_permit).await {
            sampled_fail!(metrics, &authority, e, "mitm");
        }
        return;
    }
    if let Err(e) = tunnel(req, &authority, &shared, conn_permit).await {
        sampled_fail!(shared.metrics, &authority, e, "tunnel");
    }
}

fn connect_timeout(shared: &Shared) -> Duration {
    Duration::from_secs(shared.cfg.connect_timeout_secs.max(1))
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
async fn connect_origin_socket(
    authority: &str,
    interface: Option<&str>,
) -> std::io::Result<tokio::net::TcpStream> {
    let Some(interface) = interface else {
        return tokio::net::TcpStream::connect(authority).await;
    };
    let mut last_error = None;
    for addr in tokio::net::lookup_host(authority).await? {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        };
        let socket = match socket {
            Ok(socket) => socket,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        if let Err(error) = socket.bind_device(Some(interface.as_bytes())) {
            last_error = Some(error);
            continue;
        }
        match socket.connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no origin address")
    }))
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
async fn connect_origin_socket(
    authority: &str,
    interface: Option<&str>,
) -> std::io::Result<tokio::net::TcpStream> {
    // `hyper-util` supports additional interface-binding platforms, but
    // Tokio's raw socket API used for CONNECT currently exposes bind_device
    // only on the targets above. Refuse an explicitly requested route rather
    // than silently sending the tunnel through a different interface.
    if let Some(interface) = interface {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("CONNECT interface binding is unsupported on this platform: {interface}"),
        ));
    }
    tokio::net::TcpStream::connect(authority).await
}

/// Plain TCP tunnel for CONNECT when MITM is disabled. The dial has the
/// same timeout as origin exchanges so blackholed routes fail fast.
async fn tunnel(
    req: Request<Incoming>,
    authority: &str,
    shared: &Shared,
    _permit: OwnedSemaphorePermit,
) -> std::io::Result<()> {
    use hyper_util::rt::TokioIo;
    let upgraded = tokio::time::timeout(connect_timeout(shared), hyper::upgrade::on(req))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "CONNECT upgrade timeout"))?
        .map_err(std::io::Error::other)?;
    let mut up = TokioIo::new(upgraded);
    let mut origin_permit = tokio::time::timeout(
        connect_timeout(shared),
        shared.origin.acquire_for(authority),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "origin permit timeout"))?
    .map_err(|error| std::io::Error::other(format!("origin permit: {error:?}")))?;
    let interface = origin_permit.interface().map(str::to_owned);
    let mut origin = match tokio::time::timeout(
        connect_timeout(shared),
        connect_origin_socket(authority, interface.as_deref()),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            origin_permit.mark_failure();
            return Err(std::io::Error::other(error));
        }
        Err(error) => {
            origin_permit.mark_failure();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("origin connect timeout: {error}"),
            ));
        }
    };
    origin_permit.mark_success();
    tokio::io::copy_bidirectional(&mut up, &mut origin).await?;
    Ok(())
}

/// MITM: answer CONNECT, TLS-handshake with a CA-signed leaf for the host,
/// serve the decrypted HTTP with the same segmented engine, re-originate
/// over verified TLS.
async fn mitm(
    req: Request<Incoming>,
    authority: &str,
    shared: Shared,
    ca: &crate::cert::CaAuthority,
    _permit: OwnedSemaphorePermit,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use hyper_util::rt::TokioIo;
    use tokio_rustls::TlsAcceptor;

    let parsed: http::uri::Authority = authority.parse()?;
    let (_uri_host, cert_host, _port, _scheme) = split_authority(&parsed);
    let scheme = "https";
    let upgraded = tokio::time::timeout(connect_timeout(&shared), hyper::upgrade::on(req))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "CONNECT upgrade timeout")
        })??;
    let tls_cfg = ca
        .leaf_config(&cert_host)
        .map_err(|e| std::io::Error::other(format!("cert: {e}")))?;
    let acceptor = TlsAcceptor::from(tls_cfg);
    let tls = tokio::time::timeout(
        connect_timeout(&shared),
        acceptor.accept(TokioIo::new(upgraded)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timeout"))??;
    let io = TokioIo::new(tls);

    let header_timeout = Duration::from_secs(shared.cfg.header_timeout_secs);
    let header_secs = shared.cfg.header_timeout_secs;
    let svc = hyper::service::service_fn(move |inner: Request<Incoming>| {
        let shared = shared.clone();
        let authority = authority.to_owned();
        let scheme = scheme;
        async move {
            if inner.method() == Method::TRACE {
                return Ok::<_, std::convert::Infallible>(method_not_allowed());
            }
            let (parts, body) = inner.into_parts();
            let path = parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            // Rebuild the absolute origin URI from the CONNECT authority
            // verbatim, preserving brackets and the port.
            let target: Uri = match format!("{scheme}://{authority}{path}").parse() {
                Ok(u) => u,
                Err(_) => {
                    return Ok::<_, std::convert::Infallible>(bad_request());
                }
            };
            // Inner requests get their own body-lifetime permit. The outer
            // CONNECT still bounds the number of TLS connections.
            if parts.method == Method::GET {
                let Ok(permit) = shared.downloads.clone().try_acquire_owned() else {
                    return Ok::<_, std::convert::Infallible>(overloaded());
                };
                let req_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
                let span = tracing::debug_span!("download", req_id, target = %segment::redact_uri(&target), method = "GET");
                let range = parts.headers.get(http::header::RANGE).cloned();
                drain_get_body(body, &shared);
                let cancel = CancellationToken::new();
                let response = segment::serve_get_with_cancel(
                    shared,
                    target,
                    parts.headers,
                    range,
                    cancel.clone(),
                )
                .instrument(span)
                .await;
                Ok(segment::guard_response(response, permit, cancel))
            } else {
                if segment::has_ambiguous_framing(&parts.headers) {
                    return Ok::<_, std::convert::Infallible>(bad_request());
                }
                let Ok(permit) = shared.downloads.clone().try_acquire_owned() else {
                    return Ok::<_, std::convert::Infallible>(overloaded());
                };
                let headers = segment::passthrough_headers(&parts.headers);
                let response =
                    segment::serve_other(shared, parts.method, target, headers, body.boxed()).await;
                Ok(segment::guard_response(
                    response,
                    permit,
                    CancellationToken::new(),
                ))
            }
        }
    });
    let mut http = hyper::server::conn::http1::Builder::new();
    // Same slow-loris bound as the outer listener; hyper panics if a read
    // timeout is set without a timer.
    http.timer(hyper_util::rt::TokioTimer::new());
    if header_secs > 0 {
        http.header_read_timeout(header_timeout);
    }
    http.serve_connection(io, svc).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::{Metrics, Origin, ProbeCache, parse_connect_ports};
    use bytes::Bytes;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::Semaphore;

    use crate::segment::build_client;

    /// Loopback proxy listener for tests: real sockets through `handle()`.
    async fn serve_on(shared: Shared) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let shared = shared.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let shared = shared.clone();
                        handle(req, shared)
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        (addr, server)
    }

    fn test_shared() -> Shared {
        let mut ports = HashSet::new();
        ports.insert(443);
        ports.insert(80);
        Shared {
            cfg: Arc::new(Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                workers: 4,
                min_segment: 65536,
                timeout_secs: 5,
                connect_timeout_secs: 5,
                max_slice_retries: 5,
                slice_bytes: 65536,
                adaptive_slices: false,
                slice_min_bytes: 4096,
                dlt_rounds: 0,
                dlt_round_ms: 250,
                body_buffer: 8,
                no_hedge: true,
                tunnel_only: false,
                ca_out: None,
                max_connections: 32,
                max_tunnels: 8,
                max_downloads: 4,
                max_origin_connections: 8,
                max_origin_per_host: 8,
                egress_routes: String::new(),
                egress_max_connections: 0,
                egress_failure_threshold: 2,
                egress_cooldown_secs: 30,
                egress_retry_budget: 2,
                header_timeout_secs: 5,
                probe_cache_ttl_secs: 0,
                probe_cache_entries: 8,
                origin_ca_bundle: None,
                allow_connect_ports: "443,80".to_owned(),
                mitm_ports: "443,80".to_owned(),
                shutdown_grace_secs: 1,
                max_upload_bytes: 1 << 20,
            }),
            origin: Origin::new(build_client(None, 8).unwrap(), 8),
            ca: None,
            downloads: Arc::new(Semaphore::new(4)),
            connections: Arc::new(Semaphore::new(32)),
            tunnels: Arc::new(Semaphore::new(8)),
            upgrades: Arc::new(tokio_util::task::TaskTracker::new()),
            allowed_ports: Arc::new(ports.clone()),
            mitm_ports: Arc::new(ports),
            metrics: Arc::new(Metrics::default()),
            probe_cache: Arc::new(ProbeCache::new(0, 8)),
            started: Instant::now(),
        }
    }

    #[test]
    fn decodes_utf8_urls() {
        // "é" as UTF-8 percent-encoding must round-trip, not become mojibake.
        let out = percent_decode("http%3A%2F%2Fh%2F%C3%A9");
        assert_eq!(String::from_utf8_lossy(&out), "http://h/é");
    }

    #[test]
    fn rejects_non_http_fetch_targets() {
        assert!(fetch_query_target("/__fetch?url=file%3A%2F%2F%2Fetc%2Fpasswd").is_none());
        assert!(fetch_query_target("/__fetch?url=https%3A%2F%2Fh%2Fv").is_some());
    }

    #[test]
    fn splits_authorities() {
        let a: http::uri::Authority = "example.com:443".parse().unwrap();
        let (uri_host, bare, port, scheme) = split_authority(&a);
        assert_eq!(
            (uri_host.as_str(), bare.as_str(), port, scheme),
            ("example.com", "example.com", 443, "https")
        );
        let a: http::uri::Authority = "[::1]:443".parse().unwrap();
        let (uri_host, bare, port, scheme) = split_authority(&a);
        assert_eq!(
            (uri_host.as_str(), bare.as_str(), port, scheme),
            ("[::1]", "::1", 443, "https")
        );
        let a: http::uri::Authority = "example.com:80".parse().unwrap();
        let (_, _, port, scheme) = split_authority(&a);
        assert_eq!((port, scheme), (80, "http"));
    }

    #[test]
    fn parses_ports() {
        assert_eq!(parse_connect_ports("443,80").unwrap().len(), 2);
    }

    #[test]
    fn redacts_connect_userinfo() {
        assert_eq!(redact_authority("user:pass@h:443"), "[redacted]@h:443");
        assert_eq!(redact_authority("h:443"), "h:443");
    }

    #[tokio::test]
    async fn serves_stats_rejects_trace_and_denies_ports() {
        use http_body_util::{BodyExt, Empty};
        use hyper_util::rt::TokioExecutor;

        let shared = test_shared();
        let (addr, server) = serve_on(shared).await;

        // /__stats operator endpoint.
        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let client =
            hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(connector);
        let resp = client
            .get(format!("http://{addr}/__stats").parse().unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json = String::from_utf8(body.to_vec()).unwrap();
        assert!(json.contains("\"downloads\"") && json.contains("\"uptime_secs\""));

        // TRACE is refused without touching any origin.
        let trace = Request::builder()
            .method(Method::TRACE)
            .uri(format!("http://{addr}/x"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = client.request(trace).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // CONNECT to a non-allowlisted port is refused before any dial.
        let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        raw.write_all(b"CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 64];
        let n = raw.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 403"));

        server.abort();
    }

    #[tokio::test]
    async fn absolute_fetch_path_is_forwarded_not_hijacked() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            use hyper_util::rt::TokioIo;
            loop {
                let Ok((stream, _)) = origin.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(
                        |req: Request<hyper::body::Incoming>| async move {
                            let path = req.uri().path().to_owned();
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(http::header::CONTENT_LENGTH, path.len())
                                    .body(http_body_util::Full::new(Bytes::from(path)))
                                    .unwrap(),
                            )
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        let (addr, server) = serve_on(test_shared()).await;
        let target = format!("http://{origin_addr}/__fetch?url=http://{origin_addr}/real");
        let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
        raw.write_all(
            format!("GET {target} HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = String::new();
        raw.read_to_string(&mut response).await.unwrap();
        assert!(response.contains("/__fetch"), "{response}");
        assert!(!response.contains("/real"), "{response}");
        server.abort();
    }

    #[tokio::test]
    async fn get_with_body_still_proxies() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Fixed origin: ignores Range, serves a 5-byte 200.
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            use hyper_util::rt::TokioIo;
            loop {
                let Ok((stream, _)) = origin.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|_req| async {
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(hyper::StatusCode::OK)
                                .header(hyper::header::CONTENT_LENGTH, "5")
                                .body(http_body_util::Full::new(bytes::Bytes::from_static(
                                    b"hello",
                                )))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        let shared = test_shared();
        let (addr, server) = serve_on(shared).await;
        // Absolute-form GET carrying a body, as a quirky client would send
        // it. The body must not corrupt routing or framing.
        let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
        raw.write_all(
            format!(
                "GET http://{origin_addr}/f HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            raw.read_to_end(&mut out),
        )
        .await
        .unwrap()
        .unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.ends_with("hello"), "{text}");
        server.abort();
    }

    #[tokio::test]
    async fn refuses_when_downloads_exhausted() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let shared = test_shared();
        // Hold every download permit: the next proxied fetch must 503.
        let mut holds = Vec::new();
        for _ in 0..4 {
            holds.push(shared.downloads.clone().try_acquire_owned().unwrap());
        }
        let (addr, server) = serve_on(shared).await;
        // Absolute-form request, as a forward-proxy client would send it
        // (a hyper client would normalize to origin-form here).
        let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
        raw.write_all(format!("GET http://{addr}/x HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = vec![0u8; 128];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), raw.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);
        assert!(head.starts_with("HTTP/1.1 503"), "{head}");
        assert!(head.to_lowercase().contains("retry-after"));
        drop(holds);
        server.abort();
    }

    #[tokio::test]
    async fn tunnel_relays_bytes_opaquely() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Plain TCP echo origin (no HTTP involved past CONNECT).
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = echo.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.into_split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let mut shared = test_shared();
        Arc::get_mut(&mut shared.cfg).unwrap().tunnel_only = true;
        Arc::get_mut(&mut shared.allowed_ports)
            .unwrap()
            .insert(echo_addr.port());
        let (addr, server) = serve_on(shared).await;
        let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
        raw.write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: x\r\n\r\n",
                echo_addr.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut head = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), raw.read(&mut head))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
        raw.write_all(b"ping-tunnel").await.unwrap();
        let mut echo_back = vec![0u8; 11];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            raw.read_exact(&mut echo_back),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&echo_back, b"ping-tunnel");
        server.abort();
    }

    #[tokio::test]
    async fn mitm_terminates_and_proxies_with_valid_chain() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // TLS origin whose chain the proxy verifies via a bundle file,
        // using production cert issuance on both ends.
        let origin_ca = crate::cert::CaAuthority::generate().unwrap();
        let srv_tls = origin_ca.leaf_config("127.0.0.1").unwrap();
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(srv_tls);
        tokio::spawn(async move {
            use hyper_util::rt::TokioIo;
            loop {
                let Ok((stream, _)) = origin.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let svc = hyper::service::service_fn(|_req| async {
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(hyper::StatusCode::OK)
                                .header(hyper::header::CONTENT_LENGTH, "10")
                                .body(http_body_util::Full::new(bytes::Bytes::from_static(
                                    b"hello-mitm",
                                )))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        // Trust bundle the proxy will verify the origin against.
        let bundle =
            std::env::temp_dir().join(format!("proxy-test-origin-{}.pem", std::process::id()));
        std::fs::write(&bundle, origin_ca.ca_pem()).unwrap();
        let mut shared = test_shared();
        shared.origin = crate::state::Origin::new(build_client(Some(&bundle), 8).unwrap(), 8);
        let mitm_ca = std::sync::Arc::new(crate::cert::CaAuthority::generate().unwrap());
        // Trust bundle the test client will verify the MITM leaf against.
        let mut mitm_roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(std::io::Cursor::new(
            mitm_ca.ca_pem().into_bytes(),
        ))) {
            mitm_roots.add(cert.unwrap()).unwrap();
        }
        let client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(mitm_roots)
            .with_no_client_auth();
        shared.ca = Some(mitm_ca);
        Arc::get_mut(&mut shared.allowed_ports)
            .unwrap()
            .insert(origin_addr.port());
        // Opt this non-standard port into MITM (defaults cover 443 only).
        Arc::get_mut(&mut shared.mitm_ports)
            .unwrap()
            .insert(origin_addr.port());
        let (addr, server) = serve_on(shared).await;
        // Raw CONNECT, then a verified TLS handshake, then plain HTTP/1.1.
        let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
        raw.write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: x\r\n\r\n",
                origin_addr.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut head = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), raw.read(&mut head))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_tls));
        let mut tls = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connector.connect(
                rustls::pki_types::ServerName::IpAddress(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)).into(),
                ),
                raw,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        tls.write_all(b"GET /p HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tls.read_to_end(&mut out),
        )
        .await
        .unwrap()
        .unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("hello-mitm"), "{text}");
        let _ = std::fs::remove_file(&bundle);
        server.abort();
    }
}
