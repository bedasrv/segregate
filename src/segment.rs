use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use http_body::Frame;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use tokio::sync::{OwnedSemaphorePermit, watch};
use tokio_util::sync::CancellationToken;

use tracing::Instrument;

use crate::state::{
    Metrics, Origin, OriginError, OriginPermit, ProbeSnapshot, Shared, cache_key, sample_hit,
};

pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;
pub type ProxyClient =
    hyper_util::client::legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody>;

/// One configured origin client. The route name is an interface name for
/// normal entries; the special `default` name uses the system-selected route.
pub struct EgressClient {
    pub name: String,
    pub interface: Option<String>,
    pub weight: u32,
    pub client: ProxyClient,
}

/// Split time budget: time-to-first-byte (dial, TLS, headers) versus idle
/// gaps between body chunks. One knob for both either false-retries
/// slow-but-moving links or stalls handshakes; two knobs separate them.
#[derive(Debug, Clone, Copy)]
struct Timeouts {
    first_byte: Duration,
    chunk: Duration,
}

impl Timeouts {
    fn new(connect_secs: u64, chunk_secs: u64) -> Self {
        Self {
            first_byte: Duration::from_secs(connect_secs.max(1)),
            chunk: Duration::from_secs(chunk_secs.max(1)),
        }
    }
}

/// Shared origin client.
///
/// HTTP/1.1 only, on purpose: segmented downloading wants one TCP
/// connection per segment, while HTTP/2 would multiplex all segments onto
/// a single connection (defeating fan-out). It also keeps the origin
/// fingerprint to plain HTTP/1.1, which picky WAFs handle best.
///
/// Trust: system native roots plus `--origin-ca-bundle` when given.
///
/// Idle keep-alive sockets are capped per host: the origin semaphore bounds
/// *active* exchanges, but without this the pool would retain an unbounded
/// number of idle FDs across many distinct origins.
pub fn build_client(
    ca_bundle: Option<&std::path::Path>,
    pool_max_idle_per_host: usize,
) -> Result<ProxyClient, String> {
    build_client_on_interface(ca_bundle, pool_max_idle_per_host, None)
}

/// Build a client whose sockets are optionally bound to one interface.
///
/// Interface binding is platform-specific inside `hyper-util`; on Linux it
/// uses `SO_BINDTODEVICE` and may therefore require elevated privileges.
pub fn build_client_on_interface(
    ca_bundle: Option<&std::path::Path>,
    _pool_max_idle_per_host: usize,
    interface: Option<&str>,
) -> Result<ProxyClient, String> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    let mut loaded = 0usize;
    for cert in native.certs {
        roots.add(cert).map_err(|e| format!("native root: {e:?}"))?;
        loaded += 1;
    }
    if !native.errors.is_empty() {
        tracing::warn!(
            ignored = native.errors.len(),
            "some native certificates ignored"
        );
    }
    if let Some(path) = ca_bundle {
        let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut reader = std::io::BufReader::new(file);
        let mut n = 0usize;
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| format!("{}: {e:?}", path.display()))?;
            roots.add(cert).map_err(|e| format!("root: {e:?}"))?;
            n += 1;
        }
        if n == 0 {
            return Err(format!("no certificates in {}", path.display()));
        }
        tracing::info!(path = %path.display(), certs = n, "loaded origin CA bundle");
        loaded += n;
    }
    if loaded == 0 {
        return Err("no trusted certificates loaded".to_owned());
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut http = HttpConnector::new();
    // The HTTPS wrapper accepts both `http` and `https` URIs; the low-level
    // connector must therefore not reject HTTPS before the wrapper sees it.
    http.enforce_http(false);
    if let Some(interface) = interface {
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        {
            http.set_interface(interface);
        }
        #[cfg(not(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        )))]
        {
            return Err(format!(
                "origin interface binding is unsupported on this platform: {interface}"
            ));
        }
    }
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    Ok(
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            // No idle pool: Hyper's pool budget is per authority, while this
            // proxy accepts untrusted authority cardinality. Active exchanges
            // remain bounded by Origin::get; completed sockets are not kept.
            .pool_timer(hyper_util::rt::TokioTimer::new())
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build(connector),
    )
}

/// Parse the compact weighted route syntax used by `--egress-routes`.
///
/// Empty input keeps the ordinary system-route client. `default=weight` is
/// also accepted when an operator wants an explicitly weighted single route.
pub fn parse_egress_routes(routes: &str) -> Result<Vec<(String, u32)>, String> {
    if routes.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = HashSet::new();
    let mut parsed = Vec::new();
    for raw in routes.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            return Err("egress route list contains an empty entry".to_owned());
        }
        let (name, weight) = entry
            .split_once('=')
            .ok_or_else(|| format!("invalid egress route {entry:?}; expected NAME=WEIGHT"))?;
        let name = name.trim();
        if name.is_empty() {
            return Err("egress route name cannot be empty".to_owned());
        }
        if name
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '=')
        {
            return Err(format!("invalid egress route name {name:?}"));
        }
        if !seen.insert(name.to_owned()) {
            return Err(format!("duplicate egress route {name:?}"));
        }
        let weight = weight
            .trim()
            .parse::<u32>()
            .map_err(|_| format!("invalid weight for egress route {name:?}"))?;
        if !(1..=1000).contains(&weight) {
            return Err(format!("egress route {name:?} weight must be 1..=1000"));
        }
        parsed.push((name.to_owned(), weight));
    }
    Ok(parsed)
}

/// Build one origin client per weighted interface route. An empty route list
/// intentionally returns no clients so startup can use the legacy single
/// client path.
pub fn build_egress_clients(
    ca_bundle: Option<&std::path::Path>,
    pool_max_idle_per_host: usize,
    routes: &str,
) -> Result<Vec<EgressClient>, String> {
    parse_egress_routes(routes)?
        .into_iter()
        .map(|(name, weight)| {
            let interface = (name != "default").then_some(name.as_str());
            let client = build_client_on_interface(ca_bundle, pool_max_idle_per_host, interface)?;
            Ok(EgressClient {
                interface: interface.map(str::to_owned),
                name,
                weight,
                client,
            })
        })
        .collect()
}

/// Empty body with the proxy's error type (`Empty::boxed()` is `Infallible`).
pub fn empty_body() -> BoxBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// 502 for origin-side failures that happen before any origin bytes exist.
/// The builder inputs are constants, so this cannot fail.
fn bad_gateway() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(empty_body())
        .unwrap()
}

/// Small in-memory body (operator endpoints like `/__stats`).
pub fn string_body(s: String) -> BoxBody {
    http_body_util::Full::new(Bytes::from(s))
        .map_err(|never| match never {})
        .boxed()
}

/// Streaming body fed by the coordinator task. Never errors: origin
/// failures truncate the stream (EOF) so the downstream socket stays a
/// clean HTTP framing; clients resume with Range.
struct PipeBody {
    rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, hyper::Error>>,
}

impl http_body::Body for PipeBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        Pin::new(&mut this.rx).poll_recv(cx)
    }
}

/// Response body guard: keeps the download permit and cancellation token
/// alive for exactly as long as Hyper can still be streaming the response.
struct GuardedBody {
    inner: BoxBody,
    _permit: OwnedSemaphorePermit,
    cancel: CancellationToken,
}

impl http_body::Body for GuardedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for GuardedBody {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Attach a download permit and cancellation scope to a response body.
pub fn guard_response(
    response: Response<BoxBody>,
    permit: OwnedSemaphorePermit,
    cancel: CancellationToken,
) -> Response<BoxBody> {
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        GuardedBody {
            inner: body,
            _permit: permit,
            cancel,
        }
        .boxed(),
    )
}

/// Logging-only redaction: strip possible `user:pass@` so credentials never
/// land in spans or logs. Routing always uses the full URI.
pub fn redact_uri(uri: &Uri) -> String {
    let s = uri.to_string();
    let Some((scheme, rest)) = s.split_once("://") else {
        return s.split('?').next().unwrap_or(&s).to_owned();
    };
    let authz_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authz_end);
    let suffix = suffix.split('?').next().unwrap_or("");
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://[redacted]@{host}{suffix}"),
        None => format!("{scheme}://{authority}{suffix}"),
    }
}

/// Drop framing/hop-by-hop response headers before replaying origin headers
/// downstream (or from cache). `Date` is dropped too: hyper stamps a fresh
/// one, which also keeps cached replays from serving stale dates.
fn scrub_response_headers(headers: &mut HeaderMap) {
    const DROP: [&str; 9] = [
        "connection",
        "proxy-connection",
        "keep-alive",
        "trailer",
        "transfer-encoding",
        "te",
        "upgrade",
        "proxy-authenticate",
        "date",
    ];
    let mut listed: Vec<String> = Vec::new();
    for value in headers.get_all(http::header::CONNECTION).iter() {
        if let Ok(value) = value.to_str() {
            listed.extend(
                value
                    .split(',')
                    .map(|token| token.trim().to_lowercase())
                    .filter(|token| !token.is_empty()),
            );
        }
    }
    for name in DROP {
        headers.remove(name);
    }
    for token in listed {
        if let Ok(name) = token.parse::<HeaderName>() {
            headers.remove(name);
        }
    }
}

/// Headers forwarded to the origin for bodyless (segmented) requests.
/// `Accept-Encoding` is stripped so the origin serves identity bytes, which
/// stay rangeable; lengths are recomputed downstream anyway.
pub fn segment_headers(src: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    forward_headers(src, false, true)
}

/// Headers forwarded with a request body (POST/PUT/...): keeps
/// `Content-Length` and `Accept-Encoding` for a transparent tunnel.
pub fn passthrough_headers(src: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    forward_headers(src, !has_transfer_encoding(src), false)
}

/// Whether a request contains ambiguous HTTP/1 framing.
pub fn has_ambiguous_framing(src: &HeaderMap) -> bool {
    has_transfer_encoding(src) && src.contains_key(http::header::CONTENT_LENGTH)
}

fn has_transfer_encoding(src: &HeaderMap) -> bool {
    src.get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .any(|value| {
            value.to_str().ok().is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
            })
        })
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    const HOP: [&str; 9] = [
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    let n = name.as_str();
    HOP.iter().any(|h| n.eq_ignore_ascii_case(h))
}

/// True if `name` appears in the `Connection` header token list.
/// Allocation-free: scans `&str` slices, no per-header `to_lowercase`.
fn connection_listed(list: &str, name: &str) -> bool {
    list.split(',').any(|t| t.trim().eq_ignore_ascii_case(name))
}

fn forward_headers(
    src: &HeaderMap,
    preserve_content_length: bool,
    strip_encoding: bool,
) -> Vec<(HeaderName, HeaderValue)> {
    let connections: Vec<&str> = src
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    src.iter()
        .filter(|(n, _)| !is_hop_by_hop(n))
        .filter(|(n, _)| {
            !connections
                .iter()
                .any(|connection| connection_listed(connection, n.as_str()))
        })
        // Range / content framing are set per-request, never forwarded blindly.
        // `Host` is dropped too: hyper sets it from the target URI, and a
        // forwarded client Host breaks virtual-host routing (notably for
        // /__fetch, where it would be the proxy's own address).
        .filter(|(n, _)| {
            *n != http::header::RANGE
                && *n != http::header::HOST
                && *n != http::header::TRANSFER_ENCODING
                && *n != http::header::CONTENT_RANGE
                && (preserve_content_length || *n != http::header::CONTENT_LENGTH)
                && (!strip_encoding || *n != http::header::ACCEPT_ENCODING)
        })
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect()
}

/// Classifies the origin `Vary` for caching: `Vary: *` is uncacheable;
/// a `Vary` naming `User-Agent` pins the entry to this request's UA
/// (checked on lookup). `Accept-Encoding` is safe to ignore (segment
/// fetches normalize it away) and `Cookie`/`Authorization` are already
/// part of the cache key; any other dimension is uncacheable rather than
/// risking a wrong length. Returns (storable, pinned_ua).
fn vary_policy(probe_headers: &HeaderMap, req_ua: Option<&str>) -> (bool, Option<String>) {
    let mut saw_ua = false;
    for v in probe_headers.get_all(http::header::VARY) {
        let Ok(s) = v.to_str() else {
            continue;
        };
        for token in s.split(',').map(|t| t.trim()) {
            if token.eq_ignore_ascii_case("*") {
                return (false, None);
            }
            if token.eq_ignore_ascii_case("user-agent") {
                saw_ua = true;
            } else if !(token.eq_ignore_ascii_case("accept-encoding")
                || token.eq_ignore_ascii_case("cookie")
                || token.eq_ignore_ascii_case("authorization"))
            {
                return (false, None);
            }
        }
    }
    (true, saw_ua.then(|| req_ua.unwrap_or_default().to_owned()))
}

/// Drop validators that only make sense for the probe's single request;
/// segment sub-requests re-derive freshness from the probe instead.
fn strip_conditionals(headers: &mut Vec<(HeaderName, HeaderValue)>) {
    headers.retain(|(n, _)| {
        *n != http::header::IF_MATCH
            && *n != http::header::IF_NONE_MATCH
            && *n != http::header::IF_RANGE
            && *n != http::header::IF_MODIFIED_SINCE
            && *n != http::header::IF_UNMODIFIED_SINCE
    });
}

fn build_origin_request(
    method: &Method,
    uri: &Uri,
    headers: &[(HeaderName, HeaderValue)],
    range: Option<(u64, u64)>,
) -> Result<Request<BoxBody>, http::Error> {
    let mut b = Request::builder().method(method).uri(uri);
    for (n, v) in headers {
        b = b.header(n, v);
    }
    if let Some((s, e)) = range {
        // ~20-byte value per segment request; negligible next to the body.
        if let Ok(hv) = HeaderValue::from_str(&format!("bytes={s}-{e}")) {
            b = b.header(http::header::RANGE, hv);
        }
    }
    // Builder input always comes from hyper-parsed requests/URIs, so this
    // only fails on internal misuse; callers map it to a fetch failure.
    b.body(empty_body())
}

/// Downstream range request: single ranges plus suffix ranges.
/// Multi-range (`bytes=a-b,c-d`) returns `None` → served as full 200,
/// which RFC 7233 permits (server MAY ignore the Range header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientRange {
    Absolute { start: u64, end: Option<u64> },
    Suffix(u64),
}

fn parse_client_range(v: &HeaderValue) -> Option<ClientRange> {
    let s = v.to_str().ok()?.strip_prefix("bytes=")?;
    if s.contains(',') {
        return None;
    }
    let (a, b) = s.split_once('-')?;
    if a.trim().is_empty() {
        // Suffix range: `bytes=-N` = last N bytes.
        let n: u64 = b.trim().parse().ok()?;
        if n == 0 {
            return None;
        }
        return Some(ClientRange::Suffix(n));
    }
    let start: u64 = a.trim().parse().ok()?;
    if b.trim().is_empty() {
        return Some(ClientRange::Absolute { start, end: None });
    }
    let end: u64 = b.trim().parse().ok()?;
    if end < start {
        return None;
    }
    Some(ClientRange::Absolute {
        start,
        end: Some(end),
    })
}

/// Parse `bytes <s>-<e>/<total>` from the origin probe.
fn parse_content_range(v: &HeaderValue) -> Option<(u64, u64, u64)> {
    let s = v.to_str().ok()?;
    let rest = s.strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (a, b) = range.split_once('-')?;
    Some((
        a.trim().parse().ok()?,
        b.trim().parse().ok()?,
        total.trim().parse().ok()?,
    ))
}

fn content_length(h: &HeaderMap) -> Option<u64> {
    h.get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

async fn origin_fetch(
    origin: &Origin,
    method: &Method,
    uri: &Uri,
    headers: &[(HeaderName, HeaderValue)],
    range: Option<(u64, u64)>,
    timeouts: Timeouts,
) -> Result<(Response<Incoming>, OriginPermit), FetchFail> {
    let req = build_origin_request(method, uri, headers, range).map_err(|e| {
        tracing::debug!(error = ?e, uri = %redact_uri(uri), "origin request build failed");
        FetchFail::Transport
    })?;
    let (resp, permit) = tokio::time::timeout(timeouts.first_byte, origin.get(req))
        .await
        .map_err(|_| FetchFail::Timeout)?
        .map_err(|e| {
            match &e {
                OriginError::PoolClosed => {
                    tracing::warn!("origin pool closed unexpectedly");
                }
                OriginError::Hyper(inner) => {
                    tracing::debug!(error = ?inner, uri = %redact_uri(uri), "origin request failed");
                }
            }
            FetchFail::Transport
        })?;
    Ok((resp, permit))
}

#[derive(Debug)]
enum FetchFail {
    Timeout,
    Transport,
}

struct Probe {
    total: u64,
    range_ok: bool,
    headers: HeaderMap,
}

/// Read at most `limit` bytes then stop. Used for the 1-byte probe body so
/// a pooled connection stays reusable without unbounded buffering, and for
/// draining unexpected GET bodies so hyper can reuse the downstream
/// connection instead of closing it.
/// Consecutive empty frames are capped: an origin dripping zero-length
/// frames must stall out via timeout, not spin the loop forever.
pub(crate) async fn drain_limited(mut body: Incoming, timeout: Duration, mut limit: u64) {
    let deadline = Instant::now() + timeout.saturating_mul(4);
    let mut empty = 0u32;
    while limit > 0 {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match tokio::time::timeout(remaining.min(timeout), body.frame()).await {
            Ok(Some(Ok(frame))) if frame.is_data() => {
                if let Ok(data) = frame.into_data() {
                    let n = data.len() as u64;
                    if n == 0 {
                        empty += 1;
                        if empty > 16 {
                            break;
                        }
                        continue;
                    }
                    empty = 0;
                    limit = limit.saturating_sub(n);
                }
            }
            _ => break,
        }
    }
}

/// HEAD-less probe: single `Range: bytes=0-0` learns length + range support.
/// The body is never buffered unboundedly: a 206 probe body is 1 byte
/// (drained bounded); any other status drops the body unread, sacrificing
/// pool reuse for that one connection to bound memory (a 200 reply to
/// `Range: 0-0` may carry the whole file).
async fn probe(
    origin: &Origin,
    uri: &Uri,
    headers: &[(HeaderName, HeaderValue)],
    timeouts: Timeouts,
) -> Option<Probe> {
    let timeout = timeouts.chunk;
    for attempt in 0..3 {
        match origin_fetch(origin, &Method::GET, uri, headers, Some((0, 0)), timeouts).await {
            Ok((resp, permit)) => {
                let (mut parts, body) = resp.into_parts();
                let _permit = permit;
                // Probe metadata is shared between workers/clients. Session
                // cookies belong to the full exchange, never to a range probe.
                parts.headers.remove(http::header::SET_COOKIE);
                parts.headers.remove("set-cookie2");
                tracing::debug!(attempt, status = %parts.status, uri = %redact_uri(uri), "probe response");
                if parts.status == StatusCode::PARTIAL_CONTENT {
                    drain_limited(body, timeout, 16).await;
                    if let Some(v) = parts.headers.get(http::header::CONTENT_RANGE).cloned()
                        && let Some((start, end, total)) = parse_content_range(&v)
                        && start == 0
                        && end == 0
                        && total > 0
                    {
                        parts.headers.remove(http::header::CONTENT_RANGE);
                        parts.headers.remove(http::header::CONTENT_LENGTH);
                        parts.headers.remove(http::header::TRANSFER_ENCODING);
                        return Some(Probe {
                            total,
                            range_ok: true,
                            headers: parts.headers,
                        });
                    }
                    return None;
                }
                // Never read this body: see doc comment above.
                drop(body);
                if parts.status == StatusCode::OK {
                    if let Some(len) = content_length(&parts.headers) {
                        return Some(Probe {
                            total: len,
                            range_ok: false,
                            headers: parts.headers,
                        });
                    }
                    return Some(Probe {
                        total: 0,
                        range_ok: false,
                        headers: parts.headers,
                    });
                }
                if parts.status.is_client_error() {
                    return None;
                }
                // 5xx: retry probe after releasing the response permit.
                drop(_permit);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => {
                tracing::debug!(attempt, error = ?e, uri = %redact_uri(uri), "probe fetch failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    None
}

fn backoff_next(b: Duration) -> Duration {
    (b * 2).min(Duration::from_secs(5))
}

/// Outcome of racing a stalled connection against a bounded duplicate.
enum HedgeOutcome {
    /// Got bytes; `bool` = true when they came from the hedge.
    Progress(Bytes, bool),
    /// Both sides dead.
    Dead,
    /// The parent download was canceled.
    Cancelled,
}

struct HedgeBytes {
    origin: Origin,
    uri: Uri,
    headers: Vec<(HeaderName, HeaderValue)>,
    cur: u64,
    h_end: u64,
    total: u64,
    validator: Option<HeaderValue>,
    cancel: CancellationToken,
    timeouts: Timeouts,
}

/// Fetch at most the first data chunk of `[cur, h_end]` as a stall hedge.
/// Bounded by construction: one request, headers + first frame timeouts,
/// then the task ends whether or not it delivered.
async fn hedge_first_bytes(ctx: HedgeBytes) -> Option<Bytes> {
    let HedgeBytes {
        origin,
        uri,
        headers,
        cur,
        h_end,
        total,
        validator,
        cancel,
        timeouts,
    } = ctx;
    let req = build_origin_request(&Method::GET, &uri, &headers, Some((cur, h_end))).ok()?;
    let response = tokio::select! {
        _ = cancel.cancelled() => return None,
        response = tokio::time::timeout(timeouts.first_byte, origin.get(req)) => response,
    };
    let (resp, _permit) = response.ok()?.ok()?;
    if resp.status() != StatusCode::PARTIAL_CONTENT
        || !valid_slice_response(resp.headers(), cur, h_end, total, validator.as_ref())
    {
        return None;
    }
    let mut body = resp.into_body();
    let mut trailers = 0u32;
    loop {
        let frame = tokio::select! {
            _ = cancel.cancelled() => return None,
            frame = tokio::time::timeout(timeouts.chunk, body.frame()) => frame,
        };
        match frame {
            Ok(Some(Ok(frame))) if frame.is_data() => {
                match frame.into_data() {
                    // An empty first frame is a stall signal, not data:
                    // fail fast instead of waiting out the budget in a spin.
                    Ok(data) if !data.is_empty() => return Some(data),
                    _ => return None,
                }
            }
            Ok(Some(Ok(_))) => {
                trailers += 1;
                if trailers > 16 {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

struct HedgeRace<'a> {
    origin: &'a Origin,
    uri: &'a Uri,
    headers: &'a [(HeaderName, HeaderValue)],
    old: &'a mut Incoming,
    cur: u64,
    end: u64,
    total: u64,
    validator: Option<&'a HeaderValue>,
    cancel: &'a CancellationToken,
    timeouts: Timeouts,
}

/// Race the stalled `old` body against one bounded duplicate request for the
/// same bytes. `biased` keeps a healthy connection on priority: if the old
/// body delivers within the grace window it wins and the hedge is aborted.
async fn race_hedge(ctx: HedgeRace<'_>) -> HedgeOutcome {
    let HedgeRace {
        origin,
        uri,
        headers,
        old,
        cur,
        end,
        total,
        validator,
        cancel,
        timeouts,
    } = ctx;
    let h_end = cur.saturating_add(256 * 1024 - 1).min(end);
    let hedge_validator = validator.cloned();
    let mut hedge = tokio::spawn(hedge_first_bytes(HedgeBytes {
        origin: origin.clone(),
        uri: uri.clone(),
        headers: headers.to_vec(),
        cur,
        h_end,
        total,
        validator: hedge_validator,
        cancel: cancel.clone(),
        timeouts,
    }));
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            hedge.abort();
            HedgeOutcome::Cancelled
        }
        res = tokio::time::timeout(timeouts.chunk, old.frame()) => {
            hedge.abort();
            match res {
                Ok(Some(Ok(frame))) if frame.is_data() => match frame.into_data() {
                    Ok(data) if !data.is_empty() => HedgeOutcome::Progress(data, false),
                    _ => HedgeOutcome::Dead,
                },
                _ => HedgeOutcome::Dead,
            }
        }
        res = &mut hedge => match res {
            Ok(Some(data)) => HedgeOutcome::Progress(data, true),
            _ => HedgeOutcome::Dead,
        },
    }
}

/// Truncate an origin chunk to the requested `[cur, end]` window so a buggy
/// origin can never corrupt downstream `Content-Length` framing. Returns the
/// bytes to forward (possibly empty when fully skipped).
fn fit_to_window(mut data: Bytes, cur: u64, end: u64) -> Bytes {
    let remaining = end - cur + 1;
    if data.len() as u64 > remaining {
        data.truncate(remaining as usize);
    }
    data
}

/// One slice fetch result: assembled bytes, or `Err` when the slice gave up
/// (coordinator truncates; the client resumes with Range).
type SliceResult = Result<Bytes, ()>;

/// Split `[start, end]` into contiguous slices of at most `slice_bytes`.
/// Refuse absurd ranges instead of silently enlarging slices beyond the
/// configured memory bound; the caller falls back to one full connection.
fn split_slices(start: u64, end: u64, mut slice_bytes: u64) -> Vec<(u64, u64)> {
    const MAX_SLICES: u64 = 1_000_000;
    slice_bytes = slice_bytes.max(1);
    let len = end.saturating_sub(start).saturating_add(1);
    if len == 0 || len.div_ceil(slice_bytes) > MAX_SLICES {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(len.div_ceil(slice_bytes) as usize);
    let mut cur = start;
    while cur <= end {
        let slice_end = cur.saturating_add(slice_bytes - 1).min(end);
        out.push((cur, slice_end));
        if slice_end == end {
            break;
        }
        cur = slice_end + 1;
    }
    out
}

/// Downstream channel depth in frames, bounded in bytes: one frame can hold
/// a whole assembled slice, so a raw frame count does not bound retention.
fn downstream_depth(body_buffer: usize, slice_bytes: u64) -> usize {
    const BYTE_BUDGET: u64 = 16 << 20;
    let per_frame = slice_bytes.max(1);
    (BYTE_BUDGET / per_frame).clamp(1, body_buffer.max(1) as u64) as usize
}

/// Weak entity-tag comparison (RFC 7232 §2.3.2): `W/` prefixes are ignored.
fn etag_eq(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> &str {
        let trimmed = s.trim();
        trimmed.strip_prefix("W/").unwrap_or(trimmed)
    }
    norm(a) == norm(b)
}

/// Strong validator used to pin all range requests to the probe response.
fn strong_validator(headers: &HeaderMap) -> Option<HeaderValue> {
    headers
        .get(http::header::ETAG)
        .filter(|value| {
            value
                .to_str()
                .ok()
                .is_some_and(|value| !value.trim_start().starts_with("W/"))
        })
        .cloned()
        .or_else(|| headers.get(http::header::LAST_MODIFIED).cloned())
}

fn response_validator_matches(headers: &HeaderMap, expected: &HeaderValue) -> bool {
    let Some(expected) = expected.to_str().ok() else {
        return false;
    };
    if expected.trim_start().starts_with("W/") {
        return false;
    }
    if expected.trim_start().starts_with('"') {
        headers
            .get(http::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|actual| etag_eq(actual, expected))
    } else {
        headers
            .get(http::header::LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|actual| actual == expected)
    }
}

fn valid_slice_response(
    headers: &HeaderMap,
    start: u64,
    end: u64,
    total: u64,
    expected_validator: Option<&HeaderValue>,
) -> bool {
    let Some((actual_start, actual_end, actual_total)) = headers
        .get(http::header::CONTENT_RANGE)
        .and_then(parse_content_range)
    else {
        return false;
    };
    if actual_start != start || actual_end != end || actual_total != total {
        return false;
    }
    if let Some(length) = content_length(headers)
        && length != end.saturating_sub(start).saturating_add(1)
    {
        return false;
    }
    expected_validator.is_none_or(|validator| response_validator_matches(headers, validator))
}

/// True when the origin allows this response to be cached: an explicit
/// `no-store` opts out, and we honor it instead of serving stale bytes.
fn probe_shareable(headers: &HeaderMap) -> bool {
    let control: Vec<String> = headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();
    !control
        .iter()
        .any(|token| matches!(token.as_str(), "no-store" | "private" | "no-cache"))
        && !headers.contains_key(http::header::EXPIRES)
}

fn cacheable(headers: &HeaderMap) -> bool {
    let control: Vec<String> = headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();
    if control.iter().any(|token| {
        matches!(
            token.as_str(),
            "no-store" | "private" | "no-cache" | "must-revalidate"
        ) || token.starts_with("max-age=")
            || token.starts_with("s-maxage=")
    }) {
        return false;
    }
    // The probe cache is metadata-only. Without carrying an Expires deadline
    // in the snapshot, an explicit Expires is safer treated as uncacheable.
    !headers.contains_key(http::header::EXPIRES)
}

/// Honor a downstream conditional against the origin validators we already
/// hold: a matching `If-None-Match` short-circuits the whole download with
/// `304` instead of re-fetching bytes the client already has.
fn has_conditional_request(headers: &HeaderMap) -> bool {
    [
        http::header::IF_MATCH,
        http::header::IF_NONE_MATCH,
        http::header::IF_RANGE,
        http::header::IF_MODIFIED_SINCE,
        http::header::IF_UNMODIFIED_SINCE,
    ]
    .iter()
    .any(|name| headers.contains_key(name))
}

fn request_cache_bypass(headers: &HeaderMap) -> bool {
    let no_cache = headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| {
            let token = token.trim();
            token.eq_ignore_ascii_case("no-cache")
                || token.eq_ignore_ascii_case("no-store")
                || token.eq_ignore_ascii_case("max-age=0")
        });
    no_cache
        || headers
            .get_all(http::header::PRAGMA)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| value.trim().eq_ignore_ascii_case("no-cache"))
}

fn check_not_modified(
    origin_headers: &HeaderMap,
    client_headers: &HeaderMap,
    age_secs: Option<u64>,
) -> Option<Response<BoxBody>> {
    let inm = client_headers
        .get(http::header::IF_NONE_MATCH)?
        .to_str()
        .ok()?;
    let etag = origin_headers.get(http::header::ETAG)?.to_str().ok()?;
    let matched = inm.trim() == "*" || inm.split(',').any(|t| etag_eq(t, etag));
    if !matched {
        return None;
    }
    let mut b = Response::builder().status(StatusCode::NOT_MODIFIED);
    if let Ok(hv) = HeaderValue::from_str(etag) {
        b = b.header(http::header::ETAG, hv);
    }
    if let Some(age) = age_secs
        && let Ok(hv) = HeaderValue::from_str(&age.to_string())
    {
        b = b.header(http::header::AGE, hv);
    }
    Some(b.body(empty_body()).unwrap())
}

/// Next unclaimed slice index, or `None` when the worker must wait for the
/// coordinator to advance `need` (bounded lookahead keeps completed-but-
/// unflushed bytes capped).
fn try_claim(next: &AtomicU64, need: u64, window: u64, total: u64) -> Option<u64> {
    let limit = need.saturating_add(window).min(total);
    next.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
        (n < limit).then_some(n + 1)
    })
    .ok()
}

fn claimable(next: &AtomicU64, need: u64, window: u64, total: u64) -> bool {
    next.load(Ordering::SeqCst) < need.saturating_add(window).min(total)
}

/// Download one slice `[start, end]`, resuming from `cur` on every transient
/// failure, assembling bytes into one contiguous buffer. Gives up after
/// `max_retries` consecutive failures without progress and reports `Err`
/// (then the coordinator truncates and the client resumes with Range).
/// Per-slice fetch context: borrowed from the long-lived worker so large
/// downloads do not re-clone `Shared`/`Uri`/headers per slice.
struct SliceFetch<'a> {
    shared: &'a Shared,
    uri: &'a Uri,
    headers: &'a [(HeaderName, HeaderValue)],
    total: u64,
    validator: Option<&'a HeaderValue>,
    cancel: &'a CancellationToken,
    range_ignored: &'a AtomicBool,
    progress: &'a tokio::sync::Notify,
    tx: &'a tokio::sync::mpsc::Sender<(u64, SliceResult)>,
    cache_key: Option<&'a str>,
}

async fn fetch_slice(job: &SliceFetch<'_>, idx: u64, start: u64, end: u64) {
    let SliceFetch {
        shared,
        uri,
        headers,
        total,
        validator,
        cancel,
        range_ignored,
        progress,
        tx,
        cache_key,
    } = job;
    let timeouts = Timeouts::new(shared.cfg.connect_timeout_secs, shared.cfg.timeout_secs);
    let timeout = timeouts.chunk;
    let max_retries = shared.cfg.max_slice_retries;
    let enable_hedge = !shared.cfg.no_hedge;
    let metrics = shared.metrics.clone();
    let mut buf =
        BytesMut::with_capacity(end.saturating_sub(start).saturating_add(1).min(8 << 20) as usize);
    let mut cur = start;
    let mut fails: u32 = 0;
    let mut backoff = Duration::from_millis(200);
    // Reports the slice outcome; the coordinator may already be gone.
    macro_rules! finish {
        ($result:expr) => {{
            tokio::select! {
                _ = cancel.cancelled() => return,
                result = tx.send((idx, $result)) => {
                    let _ = result;
                    return;
                }
            }
        }};
    }
    // Appends one origin chunk (windowed into this slice). An empty frame
    // counts as a stall, not progress, so a pathological empty-frame
    // stream terminates via the retry cap instead of spinning.
    macro_rules! append {
        ($data:expr) => {{
            let data = fit_to_window($data, cur, end);
            if data.is_empty() {
                fails += 1;
                metrics.origin_retries.fetch_add(1, Ordering::Relaxed);
                break;
            }
            buf.extend_from_slice(&data);
            cur += data.len() as u64;
            progress.notify_one();
            fails = 0;
            backoff = Duration::from_millis(200);
            cur > end
        }};
    }
    loop {
        if range_ignored.load(Ordering::Relaxed) {
            finish!(Err(()));
        }
        if cur > end {
            finish!(Ok(buf.freeze()));
        }
        if fails >= max_retries.max(1) {
            let n = metrics.truncations.fetch_add(1, Ordering::Relaxed) + 1;
            if sample_hit(n, 100) {
                tracing::warn!(
                    start,
                    end,
                    cur,
                    fails,
                    total = n,
                    "slice retries exhausted; truncating"
                );
            }
            finish!(Err(()));
        }
        let req = match build_origin_request(&Method::GET, uri, headers, Some((cur, end))) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = ?e, "slice request build failed; retrying");
                fails += 1;
                metrics.origin_retries.fetch_add(1, Ordering::Relaxed);
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = backoff_next(backoff);
                continue;
            }
        };
        let response = tokio::select! {
            _ = cancel.cancelled() => return,
            response = tokio::time::timeout(timeouts.first_byte, shared.origin.get(req)) => response,
        };
        let (resp, permit) = match response {
            Ok(Ok(x)) => x,
            _ => {
                fails += 1;
                metrics.origin_retries.fetch_add(1, Ordering::Relaxed);
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = backoff_next(backoff);
                continue;
            }
        };
        if resp.status() == StatusCode::PARTIAL_CONTENT
            && !valid_slice_response(resp.headers(), cur, end, *total, *validator)
        {
            drop(resp);
            drop(permit);
            fails += 1;
            metrics.origin_retries.fetch_add(1, Ordering::Relaxed);
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = backoff_next(backoff);
            continue;
        }
        if resp.status() == StatusCode::PARTIAL_CONTENT {
            let mut body = resp.into_body();
            let mut hedged = false;
            let mut trailers = 0u32;
            loop {
                if cur > end {
                    finish!(Ok(buf.freeze()));
                }
                let frame = tokio::select! {
                    _ = cancel.cancelled() => return,
                    frame = tokio::time::timeout(timeout, body.frame()) => frame,
                };
                match frame {
                    Ok(Some(Ok(frame))) if frame.is_data() => match frame.into_data() {
                        Ok(data) => {
                            if append!(data) {
                                finish!(Ok(buf.freeze()));
                            }
                            hedged = false;
                        }
                        Err(_) => break,
                    },
                    Ok(Some(Ok(_))) => {
                        trailers += 1;
                        if trailers > 16 {
                            fails += 1;
                            metrics.origin_retries.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                    // Truncated mid-slice or per-chunk timeout.
                    _ => {
                        let remaining = end - cur + 1;
                        if !hedged && enable_hedge && remaining > 65536 {
                            hedged = true;
                            tracing::debug!(cur, end, "stall: racing hedged duplicate");
                            metrics.hedges.fetch_add(1, Ordering::Relaxed);
                            match race_hedge(HedgeRace {
                                origin: &shared.origin,
                                uri,
                                headers,
                                old: &mut body,
                                cur,
                                end,
                                total: *total,
                                validator: *validator,
                                cancel,
                                timeouts,
                            })
                            .await
                            {
                                HedgeOutcome::Progress(data, from_hedge) => {
                                    if append!(data) {
                                        finish!(Ok(buf.freeze()));
                                    }
                                    if from_hedge {
                                        // Stalled body dropped; re-request remainder.
                                        break;
                                    }
                                    // Old body won: keep draining it. No re-arm:
                                    // at most one hedge per body keeps the
                                    // duplicate-connection budget bounded.
                                }
                                HedgeOutcome::Cancelled => return,
                                HedgeOutcome::Dead => {
                                    fails += 1;
                                    metrics.origin_retries.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                            }
                        } else {
                            fails += 1;
                            metrics.origin_retries.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
        } else if resp.status() == StatusCode::OK {
            if validator
                .is_some_and(|validator| !response_validator_matches(resp.headers(), validator))
            {
                drop(resp);
                drop(permit);
                metrics.truncations.fetch_add(1, Ordering::Relaxed);
                finish!(Err(()));
            }
            // A ranged request answered with a full representation. Do not
            // discard a prefix independently for every slice: that turns a
            // range-ignoring origin into quadratic bandwidth amplification.
            range_ignored.store(true, Ordering::Relaxed);
            if let Some(key) = cache_key {
                shared.probe_cache.invalidate(key);
            }
            drop(resp);
            drop(permit);
            metrics.truncations.fetch_add(1, Ordering::Relaxed);
            finish!(Err(()));
        } else {
            // 416: our (possibly cached) length is stale — drop the cache
            // entry so the next attempt re-probes. Anything else 4xx is
            // permanent for this range; 5xx joins the retry loop.
            if resp.status() == StatusCode::RANGE_NOT_SATISFIABLE
                && let Some(k) = cache_key
            {
                shared.probe_cache.invalidate(k);
            }
            if resp.status().is_redirection() || resp.status() == StatusCode::NO_CONTENT {
                metrics.truncations.fetch_add(1, Ordering::Relaxed);
                finish!(Err(()));
            }
            if resp.status().is_client_error()
                && !matches!(
                    resp.status(),
                    StatusCode::REQUEST_TIMEOUT
                        | StatusCode::TOO_EARLY
                        | StatusCode::TOO_MANY_REQUESTS
                )
            {
                metrics.truncations.fetch_add(1, Ordering::Relaxed);
                finish!(Err(()));
            }
            fails += 1;
            metrics.origin_retries.fetch_add(1, Ordering::Relaxed);
        }
        drop(permit);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = backoff_next(backoff);
    }
}

/// Owned per-worker context: moved once into the spawned task instead of
/// nine separate arguments.
struct WorkerCtx {
    shared: Shared,
    uri: Uri,
    headers: Vec<(HeaderName, HeaderValue)>,
    slices: Arc<Vec<(u64, u64)>>,
    next: Arc<AtomicU64>,
    need_rx: watch::Receiver<u64>,
    window: u64,
    total: u64,
    validator: Option<HeaderValue>,
    cancel: CancellationToken,
    range_ignored: Arc<AtomicBool>,
    progress: Arc<tokio::sync::Notify>,
    tx: tokio::sync::mpsc::Sender<(u64, SliceResult)>,
    cache_key: Option<String>,
}

/// One of N long-lived workers: pulls slice indices past the coordinator's
/// `need` pointer (bounded lookahead) and fetches them. Exits when the
/// coordinator is gone; never holds a lock.
async fn slice_worker(ctx: WorkerCtx) {
    let WorkerCtx {
        shared,
        uri,
        headers,
        slices,
        next,
        mut need_rx,
        window,
        total: file_total,
        validator,
        cancel,
        range_ignored,
        progress,
        tx,
        cache_key,
    } = ctx;
    let total_slices = slices.len() as u64;
    loop {
        // Copy out first: the borrow guard must not be held across `await`
        // (it is neither `Send` nor re-entrant).
        let need = *need_rx.borrow();
        if let Some(idx) = try_claim(&next, need, window, total_slices) {
            let (s, e) = slices[idx as usize];
            let job = SliceFetch {
                shared: &shared,
                uri: &uri,
                headers: &headers,
                total: file_total,
                validator: validator.as_ref(),
                cancel: &cancel,
                range_ignored: &range_ignored,
                progress: &progress,
                tx: &tx,
                cache_key: cache_key.as_deref(),
            };
            fetch_slice(&job, idx, s, e).await;
            continue;
        }
        // Window full (or all claimed): sleep until the coordinator advances
        // `need`, or exit when it is gone. `wait_for` re-evaluates the
        // predicate on every send, so no wakeup is ever missed.
        let waited = tokio::select! {
            _ = cancel.cancelled() => return,
            result = need_rx.wait_for(|&n| claimable(&next, n, window, total_slices)) => result,
        };
        if waited.is_err() {
            return;
        }
    }
}
fn payload_too_large() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(empty_body())
        .unwrap()
}

/// Declared upstream body length, if the client sent a parseable one.
fn declared_len(headers: &[(HeaderName, HeaderValue)]) -> Option<u64> {
    headers
        .iter()
        .find(|(n, _)| *n == http::header::CONTENT_LENGTH)?
        .1
        .to_str()
        .ok()?
        .parse()
        .ok()
}

struct UploadState {
    done: AtomicBool,
    overflow: AtomicBool,
    notify: tokio::sync::Notify,
}

/// Client upload body cut off at `remaining` bytes. Overruns end the stream
/// cleanly and set `overflow` so the caller can answer 413 instead of
/// forwarding a silently truncated upload.
struct CappedBody {
    inner: Pin<Box<BoxBody>>,
    remaining: u64,
    state: Arc<UploadState>,
    empty_frames: u32,
}

impl http_body::Body for CappedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) if frame.is_data() => match frame.into_data() {
                Ok(data) => {
                    let n = data.len() as u64;
                    if n == 0 {
                        this.empty_frames += 1;
                        if this.empty_frames > 16 {
                            this.state.done.store(true, Ordering::Relaxed);
                            this.state.notify.notify_one();
                            return Poll::Ready(None);
                        }
                        return Poll::Ready(Some(Ok(Frame::data(data))));
                    }
                    this.empty_frames = 0;
                    if n > this.remaining {
                        this.state.overflow.store(true, Ordering::Relaxed);
                        this.state.done.store(true, Ordering::Relaxed);
                        this.state.notify.notify_one();
                        return Poll::Ready(None);
                    }
                    this.remaining -= n;
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                // Unreachable for data frames; end cleanly rather than spin.
                Err(_) => Poll::Ready(None),
            },
            Poll::Ready(None) => {
                this.state.done.store(true, Ordering::Relaxed);
                this.state.notify.notify_one();
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

/// Pump one origin body into a bounded downstream channel. `abort` (upload
/// cap) and send timeouts (stalled downstream) truncate instead of holding
/// permits and origin streams forever.
fn pump_incoming(
    body: Incoming,
    depth: usize,
    timeout: Duration,
    metrics: Arc<Metrics>,
    permit: OriginPermit,
    abort: Option<Arc<UploadState>>,
) -> tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, hyper::Error>> {
    let (tx, rx) = tokio::sync::mpsc::channel(depth);
    tokio::spawn(async move {
        let _permit = permit; // held for the whole body lifetime
        let mut body = body;
        let mut sent: u64 = 0;
        let deadline = Instant::now() + timeout.saturating_mul(4);
        let mut trailers = 0u32;
        loop {
            if abort
                .as_ref()
                .is_some_and(|state| state.overflow.load(Ordering::Relaxed))
            {
                tracing::warn!(sent, "upload over cap; truncating");
                metrics.truncations.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                metrics.truncations.fetch_add(1, Ordering::Relaxed);
                return;
            };
            match tokio::time::timeout(remaining.min(timeout), body.frame()).await {
                Ok(Some(Ok(frame))) if frame.is_data() => match frame.into_data() {
                    Ok(data) => {
                        let n = data.len() as u64;
                        sent += n;
                        match tokio::time::timeout(timeout, tx.send(Ok(Frame::data(data)))).await {
                            Ok(Ok(())) => {
                                metrics.bytes_out.fetch_add(n, Ordering::Relaxed);
                            }
                            Ok(Err(_)) | Err(_) => {
                                metrics.truncations.fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                    Err(_) => break,
                },
                Ok(Some(Ok(_))) => {
                    trailers += 1;
                    if trailers > 16 {
                        metrics.truncations.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
                Ok(None) => break, // clean end of a finite body
                Ok(Some(Err(_))) => {
                    // Transport died mid-body: downstream sees a short body.
                    metrics.truncations.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(_) => {
                    let n = metrics.truncations.fetch_add(1, Ordering::Relaxed) + 1;
                    if sample_hit(n, 100) {
                        tracing::warn!(sent, total = n, "passthrough origin idle; truncating");
                    }
                    return;
                }
            }
        }
    });
    rx
}

/// Single-connection passthrough. Header failures become 502; a body that
/// goes idle longer than `timeout` truncates (the client resumes with
/// Range) instead of hanging the downstream forever.
async fn passthrough(shared: Shared, origin_req: Request<BoxBody>) -> Response<BoxBody> {
    let timeouts = Timeouts::new(shared.cfg.connect_timeout_secs, shared.cfg.timeout_secs);
    let (resp, permit) =
        match tokio::time::timeout(timeouts.first_byte, shared.origin.get(origin_req)).await {
            Ok(Ok(x)) => x,
            _ => {
                return bad_gateway();
            }
        };
    stream_passthrough(shared, resp, permit)
}

fn stream_passthrough(
    shared: Shared,
    response: hyper::Response<Incoming>,
    permit: OriginPermit,
) -> Response<BoxBody> {
    let timeouts = Timeouts::new(shared.cfg.connect_timeout_secs, shared.cfg.timeout_secs);
    let (mut parts, body) = response.into_parts();
    scrub_response_headers(&mut parts.headers);
    let rx = pump_incoming(
        body,
        shared.cfg.body_buffer.max(1),
        timeouts.chunk,
        shared.metrics.clone(),
        permit,
        None,
    );
    Response::from_parts(parts, PipeBody { rx }.boxed())
}

/// Entry point for one downstream GET. Headers flush as soon as the probe
/// (or cache) resolves; body chunks stream in order as segment 0 produces
/// them.
#[cfg(test)]
pub async fn serve_get(
    shared: Shared,
    uri: Uri,
    req_headers: HeaderMap,
    downstream_range: Option<HeaderValue>,
) -> Response<BoxBody> {
    serve_get_with_cancel(
        shared,
        uri,
        req_headers,
        downstream_range,
        CancellationToken::new(),
    )
    .await
}

pub async fn serve_get_with_cancel(
    shared: Shared,
    uri: Uri,
    req_headers: HeaderMap,
    downstream_range: Option<HeaderValue>,
    cancel: CancellationToken,
) -> Response<BoxBody> {
    shared.metrics.downloads.fetch_add(1, Ordering::Relaxed);
    let timeouts = Timeouts::new(shared.cfg.connect_timeout_secs, shared.cfg.timeout_secs);
    let timeout = timeouts.chunk;
    let fwd_probe = segment_headers(&req_headers);
    let mut fwd_parts = fwd_probe.clone();
    strip_conditionals(&mut fwd_parts);

    // Conditional/If-Range requests need the origin to evaluate the complete
    // precondition set. Do not synthesize a response from probe metadata.
    if has_conditional_request(&req_headers) {
        let headers = passthrough_headers(&req_headers);
        let request = match build_origin_request(&Method::GET, &uri, &headers, None) {
            Ok(request) => request,
            Err(_) => return bad_gateway(),
        };
        return passthrough(shared, request).await;
    }

    // Probe cache: same URI + same session collapses retries/resumes to zero RTT.
    let cache_key_opt = (!shared.probe_cache.disabled() && !request_cache_bypass(&req_headers))
        .then(|| cache_key(&uri, &req_headers));
    let mut cached: Option<ProbeSnapshot> = None;
    if let Some(k) = &cache_key_opt
        && let Some(snap) = shared.probe_cache.get(k)
    {
        // A Vary-pinned entry only serves the UA it was fetched with;
        // anything else re-probes (and overwrites) instead of risking a
        // wrong length.
        let ua_ok = match &snap.vary_ua {
            Some(pinned) => {
                req_headers
                    .get(http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    == pinned
            }
            None => true,
        };
        if ua_ok {
            shared.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            cached = Some(snap);
        }
    }
    let (snap, from_cache): (ProbeSnapshot, bool) = match cached {
        Some(snap) => (snap, true),
        None => match &cache_key_opt {
            Some(k) => {
                // Stampede protection: concurrent downloads of the same
                // uncached URL share one origin probe. The leader stores
                // the snapshot; everyone replays from their own copy.
                let cache = shared.probe_cache.clone();
                let origin = shared.origin.clone();
                let uri2 = uri.clone();
                let hdrs = fwd_probe.clone();
                let k2 = k.clone();
                let cache_put = cache.clone();
                let budget = timeouts.first_byte * 4 + Duration::from_secs(2);
                match cache
                    .get_or_probe(k, budget, || async move {
                        let p = probe(&origin, &uri2, &hdrs, timeouts).await?;
                        if !probe_shareable(&p.headers) {
                            return None;
                        }
                        let req_ua = hdrs
                            .iter()
                            .find(|(n, _)| *n == http::header::USER_AGENT)
                            .and_then(|(_, v)| v.to_str().ok());
                        let (mut storable, vary_ua) = vary_policy(&p.headers, req_ua);
                        storable &= cacheable(&p.headers);
                        let snap = ProbeSnapshot {
                            total: p.total,
                            range_ok: p.range_ok,
                            headers: p.headers,
                            probed_at: Instant::now(),
                            vary_ua,
                        };
                        if storable {
                            cache_put.put(k2.clone(), snap.clone());
                        }
                        Some(snap)
                    })
                    .await
                {
                    Some(snap) => (snap, false),
                    None => {
                        let req = match build_origin_request(&Method::GET, &uri, &fwd_probe, None) {
                            Ok(r) => r,
                            Err(_) => return bad_gateway(),
                        };
                        return passthrough(shared, req).await;
                    }
                }
            }
            None => {
                let Some(p) = probe(&shared.origin, &uri, &fwd_probe, timeouts).await else {
                    let req = match build_origin_request(&Method::GET, &uri, &fwd_probe, None) {
                        Ok(r) => r,
                        Err(_) => return bad_gateway(),
                    };
                    return passthrough(shared, req).await;
                };
                (
                    ProbeSnapshot {
                        total: p.total,
                        range_ok: p.range_ok,
                        headers: p.headers,
                        probed_at: Instant::now(),
                        vary_ua: None,
                    },
                    false,
                )
            }
        },
    };
    // Cached responses report their age; a cached Set-Cookie belongs to an
    // older exchange, never to this one.
    let age_secs = from_cache.then(|| snap.age().as_secs());
    let mut replay_headers = snap.headers;
    if from_cache {
        replay_headers.remove(http::header::SET_COOKIE);
    }
    if let Some(not_modified) = check_not_modified(&replay_headers, &req_headers, age_secs) {
        return not_modified;
    }
    let probe = Probe {
        total: snap.total,
        range_ok: snap.range_ok,
        headers: replay_headers,
    };
    let validator = strong_validator(&probe.headers);
    if probe.range_ok && shared.cfg.workers > 1 && validator.is_none() {
        // Without a strong representation validator, independent ranges
        // cannot be mixed safely. Preserve correctness with one full body.
        let request = match build_origin_request(&Method::GET, &uri, &fwd_probe, None) {
            Ok(request) => request,
            Err(_) => return bad_gateway(),
        };
        return passthrough(shared, request).await;
    }
    if let Some(validator) = validator.as_ref() {
        fwd_parts.push((http::header::IF_RANGE.clone(), validator.clone()));
    }
    if !probe.range_ok || probe.total == 0 || shared.cfg.workers <= 1 {
        let req = match build_origin_request(&Method::GET, &uri, &fwd_probe, None) {
            Ok(r) => r,
            Err(_) => return bad_gateway(),
        };
        return passthrough(shared, req).await;
    }

    let total = probe.total;
    let (eff_start, eff_end) = match downstream_range.as_ref().and_then(parse_client_range) {
        Some(ClientRange::Suffix(n)) => {
            if n >= total {
                (0, total - 1)
            } else {
                (total - n, total - 1)
            }
        }
        Some(ClientRange::Absolute { start, end }) => {
            if start >= total {
                return Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(http::header::CONTENT_RANGE, format!("bytes */{total}"))
                    .body(empty_body())
                    .unwrap();
            }
            (start, end.unwrap_or(total - 1).min(total - 1))
        }
        None => (0, total - 1),
    };

    // Files below the fan-out threshold skip striping: one connection.
    if eff_end - eff_start + 1 < shared.cfg.min_segment.max(1) {
        let range = (eff_start != 0 || eff_end != total - 1).then_some((eff_start, eff_end));
        let req = match build_origin_request(&Method::GET, &uri, &fwd_probe, range) {
            Ok(r) => r,
            Err(_) => return bad_gateway(),
        };
        return passthrough(shared, req).await;
    }
    let slices = split_slices(eff_start, eff_end, shared.cfg.slice_bytes);
    if slices.is_empty() {
        let request = match build_origin_request(&Method::GET, &uri, &fwd_probe, None) {
            Ok(request) => request,
            Err(_) => return bad_gateway(),
        };
        return passthrough(shared, request).await;
    }
    if slices.len() <= 1 {
        // Degenerate single slice reads cleaner as 200 than 206.
        let range = (eff_start != 0 || eff_end != total - 1).then_some((eff_start, eff_end));
        let req = match build_origin_request(&Method::GET, &uri, &fwd_probe, range) {
            Ok(r) => r,
            Err(_) => return bad_gateway(),
        };
        return passthrough(shared, req).await;
    }
    let workers = shared.cfg.workers.max(1).min(slices.len());
    if eff_start == 0 && downstream_range.is_none() && workers > 1 {
        // Validate the first real range before fanning out. If the origin
        // ignores Range, switch to one linear full-body response immediately
        // instead of letting every worker discard a growing prefix.
        let first_end = shared.cfg.slice_bytes.saturating_sub(1).min(eff_end);
        if let Ok(request) =
            build_origin_request(&Method::GET, &uri, &fwd_parts, Some((eff_start, first_end)))
        {
            match tokio::time::timeout(timeouts.first_byte, shared.origin.get(request)).await {
                Ok(Ok((response, permit))) if response.status() == StatusCode::OK => {
                    return stream_passthrough(shared, response, permit);
                }
                Ok(Ok((response, permit))) if response.status() == StatusCode::PARTIAL_CONTENT => {
                    if valid_slice_response(
                        response.headers(),
                        eff_start,
                        first_end,
                        total,
                        validator.as_ref(),
                    ) {
                        let body = response.into_body();
                        drain_limited(body, timeout, first_end - eff_start + 1).await;
                        drop(permit);
                    } else {
                        drop(response);
                        drop(permit);
                    }
                }
                Ok(Ok((response, permit))) => {
                    drop(response);
                    drop(permit);
                }
                _ => {}
            }
        }
    }
    // Completion window: enough in-flight slices to keep every worker busy
    // plus slack for variance. Completed-but-unflushed bytes stay bounded
    // by ~(window + workers) * slice_bytes no matter the file size.
    let window = ((workers * 2).max(8)) as u64;
    tracing::debug!(
        total,
        eff_start,
        eff_end,
        n_slices = slices.len(),
        workers,
        slice_bytes = shared.cfg.slice_bytes,
        uri = %redact_uri(&uri),
        "striped download"
    );
    let slices = Arc::new(slices);
    let next = Arc::new(AtomicU64::new(0));
    let (need_tx, _) = tokio::sync::watch::channel(0u64);
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<(u64, SliceResult)>(window as usize + workers + 8);
    let range_ignored = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(tokio::sync::Notify::new());
    let mut worker_handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        worker_handles.push(tokio::spawn(
            slice_worker(WorkerCtx {
                shared: shared.clone(),
                uri: uri.clone(),
                headers: fwd_parts.clone(),
                slices: slices.clone(),
                next: next.clone(),
                need_rx: need_tx.subscribe(),
                window,
                total,
                validator: validator.clone(),
                cancel: cancel.clone(),
                range_ignored: range_ignored.clone(),
                progress: progress.clone(),
                tx: tx.clone(),
                cache_key: cache_key_opt.clone(),
            })
            .instrument(tracing::debug_span!("worker")),
        ));
    }
    drop(tx);
    // Depth in frames would not bound retention (one frame can hold a whole
    // slice), so derive it from a byte budget.
    let body_buf = downstream_depth(shared.cfg.body_buffer, shared.cfg.slice_bytes);
    let (body_tx, body_rx) =
        tokio::sync::mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(body_buf);
    let metrics = shared.metrics.clone();
    // Watchdog: worker effort per slice is bounded by retry caps, but a
    // panicking worker (or any slot that otherwise never resolves) would
    // strand the coordinator forever. Bound total silence instead, sized
    // above any legitimate single-slot effort.
    let slot_budget = timeouts.first_byte * shared.cfg.max_slice_retries.max(1)
        + timeouts.chunk * shared.cfg.max_slice_retries.max(1)
        + Duration::from_secs(60);
    tokio::spawn(async move {
        let worker_handles = worker_handles;
        let cancel = cancel;
        let mut need = 0u64;
        let total_slices = slices.len() as u64;
        // Completed-but-unflushed bytes currently held; subtracted once on
        // exit so the gauge never leaks, however the task ends.
        let mut held = 0u64;
        let mut pending: HashMap<u64, SliceResult> = HashMap::new();
        enum Wait {
            Progress,
            Received(Option<(u64, SliceResult)>),
            Cancelled,
        }
        loop {
            if need >= total_slices {
                break;
            }
            if let Some(res) = pending.remove(&need) {
                match res {
                    Ok(bytes) => {
                        let n = bytes.len() as u64;
                        // A downstream that stopped reading (but holds the
                        // connection) must not pin permits and origin
                        // streams forever: truncate instead.
                        let sent = tokio::select! {
                            _ = cancel.cancelled() => None,
                            result = tokio::time::timeout(timeout, body_tx.send(Ok(Frame::data(bytes)))) => Some(result),
                        };
                        match sent {
                            Some(Ok(Ok(()))) => {
                                metrics.bytes_out.fetch_add(n, Ordering::Relaxed);
                                metrics.buffered_bytes.fetch_sub(n, Ordering::Relaxed);
                                held = held.saturating_sub(n);
                            }
                            _ => {
                                metrics.buffered_bytes.fetch_sub(n, Ordering::Relaxed);
                                held = held.saturating_sub(n);
                                metrics.truncations.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                        }
                        need += 1;
                        let _ = need_tx.send(need);
                    }
                    Err(()) => break, // slice gave up -> truncate
                }
                continue;
            }
            let received = tokio::time::timeout(slot_budget, async {
                tokio::select! {
                    _ = cancel.cancelled() => Wait::Cancelled,
                    _ = progress.notified() => Wait::Progress,
                    result = rx.recv() => Wait::Received(result),
                }
            })
            .await;
            match received {
                Ok(Wait::Progress) => {}
                Ok(Wait::Received(Some((idx, res)))) => {
                    if let Ok(b) = &res {
                        let n = b.len() as u64;
                        held += n;
                        metrics.buffered_bytes.fetch_add(n, Ordering::Relaxed);
                    }
                    pending.insert(idx, res);
                }
                Ok(Wait::Received(None)) => break,
                Ok(Wait::Cancelled) => break,
                Err(_) => {
                    tracing::warn!(
                        need,
                        total_slices,
                        "slot watchdog fired: no slice progress in budget; truncating"
                    );
                    metrics.truncations.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
        for worker in &worker_handles {
            worker.abort();
        }
        metrics.buffered_bytes.fetch_sub(held, Ordering::Relaxed);
    });
    let is_partial = eff_start != 0 || eff_end != total - 1;
    let mut b = Response::builder().status(if is_partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    });
    // Replay origin headers minus framing (recomputed below) and minus
    // anything hop-by-hop, volatile, or session-specific.
    let mut replay = probe.headers;
    scrub_response_headers(&mut replay);
    for (n, v) in replay {
        if let Some(name) = n {
            if name == http::header::CONTENT_LENGTH || name == http::header::CONTENT_RANGE {
                continue;
            }
            b = b.header(name, v);
        }
    }
    let eff_len = eff_end - eff_start + 1;
    b = b.header(http::header::ACCEPT_RANGES, "bytes");
    if let Ok(hv) = HeaderValue::from_str(&eff_len.to_string()) {
        b = b.header(http::header::CONTENT_LENGTH, hv);
    }
    if let Some(age) = age_secs
        && let Ok(hv) = HeaderValue::from_str(&age.to_string())
    {
        b = b.header(http::header::AGE, hv);
    }
    if is_partial {
        b = b.header(
            http::header::CONTENT_RANGE,
            format!("bytes {eff_start}-{eff_end}/{total}"),
        );
    }
    b.body(PipeBody { rx: body_rx }.boxed()).unwrap()
}

/// Non-GET requests: straight streaming proxy, bounded by the upload cap.
/// A declared overrun is refused with 413 before origin contact; an
/// undeclared stream is cut at the cap (the exchange then fails loudly
/// instead of tying an origin slot forever).
pub async fn serve_other(
    shared: Shared,
    method: Method,
    uri: Uri,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: BoxBody,
) -> Response<BoxBody> {
    let cap = shared.cfg.max_upload_bytes;
    let (body, upload_state) = if cap > 0 {
        if let Some(n) = declared_len(&headers)
            && n > cap
        {
            tracing::warn!(
                limit = cap,
                declared = n,
                "upload declared over cap; refusing"
            );
            drop(body);
            return payload_too_large();
        }
        let state = Arc::new(UploadState {
            done: AtomicBool::new(false),
            overflow: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        });
        let capped = CappedBody {
            inner: Box::pin(body),
            remaining: cap,
            state: state.clone(),
            empty_frames: 0,
        };
        (capped.boxed(), Some(state))
    } else {
        (body, None)
    };
    let mut b = Request::builder().method(method).uri(uri);
    for (n, v) in &headers {
        b = b.header(n, v);
    }
    let req = match b.body(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = ?e, "proxied request build failed");
            return bad_gateway();
        }
    };
    forward_upload(shared, req, upload_state).await
}

/// Forward with an upload-cap tripwire: if the client blew past the cap
/// while origin headers were in flight, answer 413 instead of the origin's
/// response to a truncated upload.
async fn forward_upload(
    shared: Shared,
    origin_req: Request<BoxBody>,
    upload_state: Option<Arc<UploadState>>,
) -> Response<BoxBody> {
    let timeouts = Timeouts::new(shared.cfg.connect_timeout_secs, shared.cfg.timeout_secs);
    let (resp, permit) =
        match tokio::time::timeout(timeouts.first_byte, shared.origin.get(origin_req)).await {
            Ok(Ok(x)) => x,
            _ => {
                return bad_gateway();
            }
        };
    if let Some(state) = &upload_state {
        if state.overflow.load(Ordering::Relaxed) {
            return payload_too_large();
        }
        if !state.done.load(Ordering::Relaxed) {
            let notified = state.notify.notified();
            if tokio::time::timeout(timeouts.first_byte, notified)
                .await
                .is_err()
            {
                return bad_gateway();
            }
        }
        if state.overflow.load(Ordering::Relaxed) {
            return payload_too_large();
        }
    }
    let (mut parts, body) = resp.into_parts();
    scrub_response_headers(&mut parts.headers);
    let rx = pump_incoming(
        body,
        shared.cfg.body_buffer.max(1),
        timeouts.chunk,
        shared.metrics.clone(),
        permit,
        upload_state,
    );
    Response::from_parts(parts, PipeBody { rx }.boxed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_weighted_egress_routes() {
        assert_eq!(
            parse_egress_routes("eth0=4,wg0=1"),
            Ok(vec![("eth0".to_owned(), 4), ("wg0".to_owned(), 1)])
        );
        assert!(parse_egress_routes("eth0=0,wg0=1").is_err());
        assert!(parse_egress_routes("eth0=1,eth0=2").is_err());
        assert!(parse_egress_routes("eth0").is_err());
    }

    #[test]
    fn slices_evenly_with_remainder() {
        assert_eq!(
            split_slices(0, 99, 25),
            vec![(0, 24), (25, 49), (50, 74), (75, 99)]
        );
    }

    #[test]
    fn slices_cover_tail_exactly() {
        let p = split_slices(100, 199, 30);
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], (100, 129));
        assert_eq!(p[3].1, 199);
        // Contiguous, no gaps or overlaps.
        for w in p.windows(2) {
            assert_eq!(w[0].1 + 1, w[1].0);
        }
    }

    #[test]
    fn absurd_lengths_fall_back_without_allocating_slices() {
        let p = split_slices(0, u64::MAX - 1, 1024);
        assert!(p.is_empty());
    }

    #[tokio::test]
    async fn response_guard_retains_download_permit_until_drop() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let cancel = CancellationToken::new();
        let response = guard_response(Response::new(empty_body()), permit, cancel.clone());
        assert_eq!(semaphore.available_permits(), 0);
        drop(response);
        assert_eq!(semaphore.available_permits(), 1);
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn validates_slice_range_and_validator() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_RANGE,
            HeaderValue::from_static("bytes 10-19/100"),
        );
        headers.insert(http::header::ETAG, HeaderValue::from_static("\"v1\""));
        let validator = strong_validator(&headers);
        assert!(valid_slice_response(
            &headers,
            10,
            19,
            100,
            validator.as_ref()
        ));
        assert!(!valid_slice_response(
            &headers,
            11,
            19,
            100,
            validator.as_ref()
        ));
        assert!(!valid_slice_response(
            &headers,
            10,
            19,
            101,
            validator.as_ref()
        ));
    }

    #[test]
    fn scrubs_all_connection_listed_response_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::CONNECTION,
            HeaderValue::from_static("X-First"),
        );
        headers.append(
            http::header::CONNECTION,
            HeaderValue::from_static("X-Second"),
        );
        headers.insert("x-first", HeaderValue::from_static("secret"));
        headers.insert("x-second", HeaderValue::from_static("secret"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        scrub_response_headers(&mut headers);
        assert!(!headers.contains_key("x-first"));
        assert!(!headers.contains_key("x-second"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("proxy-connection"));
    }

    #[test]
    fn downstream_depth_is_byte_bounded() {
        // Default shape unchanged: 16 frames of 1 MiB.
        assert_eq!(downstream_depth(16, 1024 * 1024), 16);
        // A frame can hold a whole slice: giant slices collapse the depth.
        assert_eq!(downstream_depth(16, 1 << 30), 1);
        // Explicit small buffers are honored, never exceeded.
        assert_eq!(downstream_depth(4, 1024 * 1024), 4);
        // Degenerate inputs stay usable.
        assert_eq!(downstream_depth(0, 0), 1);
    }

    #[test]
    fn etag_comparison_ignores_weak_prefix() {
        assert!(etag_eq("\"v1\"", "\"v1\""));
        assert!(etag_eq("W/\"v1\"", "\"v1\""));
        assert!(etag_eq("\"v1\"", "W/\"v1\""));
        assert!(!etag_eq("\"v1\"", "\"v2\""));
    }

    #[test]
    fn conditional_short_circuits_match() {
        let mut origin = HeaderMap::new();
        origin.insert(http::header::ETAG, HeaderValue::from_static("\"v1\""));
        let mut client = HeaderMap::new();
        client.insert(
            http::header::IF_NONE_MATCH,
            HeaderValue::from_static("\"v0\", \"v1\""),
        );
        let resp = check_not_modified(&origin, &client, Some(12)).unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            resp.headers().get(http::header::AGE).unwrap(),
            &HeaderValue::from_static("12")
        );
        let mut client = HeaderMap::new();
        client.insert(
            http::header::IF_NONE_MATCH,
            HeaderValue::from_static("\"other\""),
        );
        assert!(check_not_modified(&origin, &client, None).is_none());
        // Star matches any current representation.
        let mut client = HeaderMap::new();
        client.insert(http::header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(check_not_modified(&origin, &client, None).is_some());
        // No validator, no short-circuit.
        assert!(check_not_modified(&HeaderMap::new(), &client, None).is_none());
    }

    #[test]
    fn window_gates_claims() {
        let next = AtomicU64::new(0);
        assert_eq!(try_claim(&next, 0, 8, 100), Some(0));
        for _ in 0..7 {
            assert!(try_claim(&next, 0, 8, 100).is_some());
        }
        // Window [0, 8) exhausted at need=0.
        assert_eq!(try_claim(&next, 0, 8, 100), None);
        // Coordinator advances: slot 8 becomes claimable.
        assert_eq!(try_claim(&next, 1, 8, 100), Some(8));
        // Exhausted cursor never yields, however wide the window.
        next.store(100, Ordering::SeqCst);
        assert_eq!(try_claim(&next, 90, 8, 100), None);
        assert!(!claimable(&next, 90, 8, 100));
    }

    #[test]
    fn parses_ranges() {
        let v = HeaderValue::from_static("bytes=100-199");
        assert_eq!(
            parse_client_range(&v),
            Some(ClientRange::Absolute {
                start: 100,
                end: Some(199)
            })
        );
        let v = HeaderValue::from_static("bytes=100-");
        assert_eq!(
            parse_client_range(&v),
            Some(ClientRange::Absolute {
                start: 100,
                end: None
            })
        );
        let v = HeaderValue::from_static("bytes=-500");
        assert_eq!(parse_client_range(&v), Some(ClientRange::Suffix(500)));
        let v = HeaderValue::from_static("bytes=0-0,2-3");
        assert_eq!(parse_client_range(&v), None);
        let cr = HeaderValue::from_static("bytes 0-0/12345");
        assert_eq!(parse_content_range(&cr), Some((0, 0, 12345)));
    }

    #[test]
    fn truncates_overshoot_to_window() {
        let data = Bytes::from(vec![9u8; 100]);
        let out = fit_to_window(data, 90, 99);
        assert_eq!(out.len(), 10);
        let data = Bytes::from(vec![9u8; 10]);
        let out = fit_to_window(data, 0, 99);
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn connection_token_match_without_alloc() {
        assert!(connection_listed("keep-alive, Foo-Bar", "foo-bar"));
        assert!(!connection_listed("keep-alive", "close"));
        assert!(!connection_listed("", "close"));
    }

    #[test]
    fn vary_policy_pins_or_skips() {
        let plain = HeaderMap::new();
        assert_eq!(vary_policy(&plain, Some("a")), (true, None));
        let mut star = HeaderMap::new();
        star.insert(http::header::VARY, HeaderValue::from_static("*"));
        assert_eq!(vary_policy(&star, Some("a")), (false, None));
        let mut ua = HeaderMap::new();
        ua.insert(
            http::header::VARY,
            HeaderValue::from_static("Accept-Encoding, User-Agent"),
        );
        assert_eq!(vary_policy(&ua, Some("a")), (true, Some("a".to_owned())));
        assert_eq!(vary_policy(&ua, None), (true, Some(String::new())));
        let mut lang = HeaderMap::new();
        lang.insert(
            http::header::VARY,
            HeaderValue::from_static("Accept-Language"),
        );
        assert_eq!(vary_policy(&lang, Some("a")), (false, None));
        // Cookie/Authorization are already in the cache key, so they stay storable.
        let mut cookie = HeaderMap::new();
        cookie.insert(http::header::VARY, HeaderValue::from_static("Cookie"));
        assert_eq!(vary_policy(&cookie, Some("a")), (true, None));
    }

    #[test]
    fn strips_encoding_and_conditionals() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        headers.insert(http::header::IF_RANGE, HeaderValue::from_static("x"));
        headers.insert(http::header::USER_AGENT, HeaderValue::from_static("y"));
        headers.insert(
            http::header::HOST,
            HeaderValue::from_static("127.0.0.1:8080"),
        );
        let seg = segment_headers(&headers);
        assert!(!seg.iter().any(|(n, _)| *n == http::header::ACCEPT_ENCODING));
        assert!(seg.iter().any(|(n, _)| *n == http::header::USER_AGENT));
        // Hyper sets Host from the target URI; a forwarded client Host
        // would break virtual-host routing.
        assert!(!seg.iter().any(|(n, _)| *n == http::header::HOST));
        let mut seg = seg;
        strip_conditionals(&mut seg);
        assert!(!seg.iter().any(|(n, _)| *n == http::header::IF_RANGE));
        let pass = passthrough_headers(&headers);
        assert!(
            pass.iter()
                .any(|(n, _)| *n == http::header::ACCEPT_ENCODING)
        );
        assert!(!pass.iter().any(|(n, _)| *n == http::header::HOST));
    }

    #[test]
    fn redacts_credentials_from_uris() {
        let uri: Uri = "https://user:pass@h/v?x=1".parse().unwrap();
        let redacted = redact_uri(&uri);
        assert!(!redacted.contains("pass"));
        assert!(redacted.contains("h/v"));
        let plain: Uri = "https://h/v".parse().unwrap();
        assert_eq!(redact_uri(&plain), "https://h/v");
    }

    #[test]
    fn scrubs_replay_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::DATE, HeaderValue::from_static("x"));
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        headers.insert(http::header::ETAG, HeaderValue::from_static("e"));
        scrub_response_headers(&mut headers);
        assert!(!headers.contains_key(http::header::DATE));
        assert!(!headers.contains_key(http::header::CONNECTION));
        assert!(!headers.contains_key("keep-alive"));
        assert!(headers.contains_key(http::header::ETAG));
    }
}

#[cfg(test)]
mod integration {
    use super::*;
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use http_body_util::Full;
    use tokio::sync::Semaphore;

    use crate::config::Config;
    use crate::state::{Metrics, Origin, ProbeCache, ProbeSnapshot, Shared};

    /// Deterministic 1 MiB payload.
    fn payload() -> Bytes {
        Bytes::from(
            (0..1024 * 1024)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>(),
        )
    }

    struct OriginFixture {
        data: Bytes,
        /// Fail this many ranged requests with 500 first (retry test).
        flaky: AtomicUsize,
        /// Answer non-probe ranges with 200 full bodies (ignore-range test).
        full_on_segment: bool,
        ranged_hits: AtomicUsize,
        live: AtomicUsize,
        max_live: AtomicUsize,
        delay_ms: u64,
    }

    async fn run_origin(origin: Arc<OriginFixture>) -> SocketAddr {
        use hyper_util::rt::TokioIo;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let origin = origin.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let origin = origin.clone();
                        async move {
                            let range = req.headers().get(http::header::RANGE).cloned();
                            if let Some(range) = range {
                                origin.ranged_hits.fetch_add(1, Ordering::SeqCst);
                                if origin
                                    .flaky
                                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                                        n.checked_sub(1)
                                    })
                                    .is_ok()
                                {
                                    let body = Full::new(Bytes::from_static(b"flaky"));
                                    return Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .header(http::header::CONTENT_LENGTH, "5")
                                            .body(body)
                                            .unwrap(),
                                    );
                                }
                                let (s, e) = range
                                    .to_str()
                                    .ok()
                                    .and_then(|s| s.strip_prefix("bytes="))
                                    .and_then(|s| s.split_once('-'))
                                    .and_then(|(a, b)| {
                                        Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                                    })
                                    .unwrap_or((0, 0));
                                if origin.full_on_segment && (s, e) != (0, 0) {
                                    // Misbehaving origin: ignores Range.
                                    return Ok(Response::builder()
                                        .status(StatusCode::OK)
                                        .header(http::header::CONTENT_LENGTH, origin.data.len())
                                        .header(http::header::ETAG, "\"fixture-v1\"")
                                        .body(Full::new(origin.data.clone()))
                                        .unwrap());
                                }
                                // Track overlap: sleep while counted live.
                                let cur = origin.live.fetch_add(1, Ordering::SeqCst) + 1;
                                origin.max_live.fetch_max(cur, Ordering::SeqCst);
                                tokio::time::sleep(Duration::from_millis(origin.delay_ms)).await;
                                let e = e.min(origin.data.len() - 1);
                                let chunk = origin.data.slice(s..=e);
                                origin.live.fetch_sub(1, Ordering::SeqCst);
                                return Ok(Response::builder()
                                    .status(StatusCode::PARTIAL_CONTENT)
                                    .header(
                                        http::header::CONTENT_RANGE,
                                        format!("bytes {s}-{e}/{}", origin.data.len()),
                                    )
                                    .header(http::header::CONTENT_LENGTH, chunk.len())
                                    .header(http::header::ACCEPT_RANGES, "bytes")
                                    .header(http::header::ETAG, "\"fixture-v1\"")
                                    .body(Full::new(chunk))
                                    .unwrap());
                            }
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(http::header::CONTENT_LENGTH, origin.data.len())
                                .header(http::header::ETAG, "\"fixture-v1\"")
                                .header(http::header::ACCEPT_RANGES, "bytes")
                                .header(http::header::ETAG, "\"fixture-v1\"")
                                .body(Full::new(origin.data.clone()))
                                .unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        addr
    }

    fn test_shared() -> Shared {
        let cfg = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            workers: 4,
            min_segment: 64 * 1024,
            timeout_secs: 10,
            connect_timeout_secs: 10,
            max_slice_retries: 50,
            slice_bytes: 65536,
            body_buffer: 8,
            no_hedge: false,
            tunnel_only: false,
            ca_out: None,
            max_connections: 32,
            max_tunnels: 8,
            max_downloads: 4,
            max_origin_connections: 32,
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
        };
        let mut ports = HashSet::new();
        ports.insert(443);
        ports.insert(80);
        Shared {
            origin: Origin::new(build_client(None, 32).unwrap(), 32),
            cfg: Arc::new(cfg),
            ca: None,
            downloads: Arc::new(Semaphore::new(4)),
            connections: Arc::new(Semaphore::new(32)),
            tunnels: Arc::new(Semaphore::new(8)),
            upgrades: Arc::new(tokio_util::task::TaskTracker::new()),
            allowed_ports: Arc::new(ports.clone()),
            mitm_ports: Arc::new(ports),
            metrics: Arc::new(Metrics::default()),
            probe_cache: Arc::new(ProbeCache::new(60, 32)),
            started: Instant::now(),
        }
    }

    async fn body_bytes(resp: Response<BoxBody>) -> Bytes {
        resp.into_body().collect().await.unwrap().to_bytes()
    }

    #[tokio::test]
    async fn fans_out_and_recovers_from_flaky_origin() {
        let data = payload();
        let origin = Arc::new(OriginFixture {
            data: data.clone(),
            flaky: AtomicUsize::new(2), // probe retries through these, then segments run clean
            full_on_segment: false,
            ranged_hits: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
            max_live: AtomicUsize::new(0),
            delay_ms: 100,
        });
        let addr = run_origin(origin.clone()).await;
        let shared = test_shared();
        let uri: Uri = format!("http://{addr}/file").parse().unwrap();
        let resp = serve_get(shared, uri, HeaderMap::new(), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, data);
        // Probe retried through the 500s, then 4 segments overlapped.
        assert!(origin.ranged_hits.load(Ordering::SeqCst) >= 2 + 4);
        assert!(origin.max_live.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn suffix_and_resume_ranges() {
        let data = payload();
        let origin = Arc::new(OriginFixture {
            data: data.clone(),
            flaky: AtomicUsize::new(0),
            full_on_segment: false,
            ranged_hits: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
            max_live: AtomicUsize::new(0),
            delay_ms: 0,
        });
        let addr = run_origin(origin.clone()).await;
        let uri: Uri = format!("http://{addr}/file").parse().unwrap();

        let resp = serve_get(
            test_shared(),
            uri.clone(),
            HeaderMap::new(),
            Some(HeaderValue::from_static("bytes=-100")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(&body_bytes(resp).await[..], &data[data.len() - 100..]);

        let resp = serve_get(
            test_shared(),
            uri.clone(),
            HeaderMap::new(),
            Some(HeaderValue::from_static("bytes=1000-")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(&body_bytes(resp).await[..], &data[1000..]);

        let resp = serve_get(
            test_shared(),
            uri,
            HeaderMap::new(),
            Some(HeaderValue::from_static("bytes=99999999-")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[tokio::test]
    async fn tiny_file_uses_single_connection() {
        let data = Bytes::from_static(b"0123456789");
        let origin = Arc::new(OriginFixture {
            data: data.clone(),
            flaky: AtomicUsize::new(0),
            full_on_segment: false,
            ranged_hits: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
            max_live: AtomicUsize::new(0),
            delay_ms: 0,
        });
        let addr = run_origin(origin.clone()).await;
        let uri: Uri = format!("http://{addr}/tiny").parse().unwrap();
        let resp = serve_get(test_shared(), uri, HeaderMap::new(), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, data);
    }

    #[tokio::test]
    async fn recovers_when_origin_ignores_range_midstream() {
        let data = payload();
        let origin = Arc::new(OriginFixture {
            data: data.clone(),
            flaky: AtomicUsize::new(0),
            full_on_segment: true, // probe 206s, segments get 200 full bodies
            ranged_hits: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
            max_live: AtomicUsize::new(0),
            delay_ms: 0,
        });
        let addr = run_origin(origin.clone()).await;
        let uri: Uri = format!("http://{addr}/file").parse().unwrap();
        let resp = serve_get(test_shared(), uri, HeaderMap::new(), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, data);
    }

    /// 8 MiB over 64 KiB slices with an instant origin *and* a slow
    /// consumer (one slice per 15 ms): backlog must build to the completion
    /// window and stop there, proving retention is bounded by the window —
    /// not by file size, part size, or transport frame size.
    #[tokio::test]
    async fn buffer_stays_flat_for_big_slow_files() {
        use std::sync::atomic::AtomicU64;
        let data = Bytes::from(
            (0..8 * 1024 * 1024)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let origin = Arc::new(OriginFixture {
            data: data.clone(),
            flaky: AtomicUsize::new(0),
            full_on_segment: false,
            ranged_hits: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
            max_live: AtomicUsize::new(0),
            delay_ms: 0,
        });
        let addr = run_origin(origin.clone()).await;
        let shared = test_shared();
        let peak = Arc::new(AtomicU64::new(0));
        let sampler = tokio::spawn({
            let metrics = shared.metrics.clone();
            let peak = peak.clone();
            async move {
                loop {
                    let held = metrics.buffered_bytes.load(Ordering::Relaxed);
                    peak.fetch_max(held, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        });
        let uri: Uri = format!("http://{addr}/big").parse().unwrap();
        let resp = serve_get(shared, uri, HeaderMap::new(), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Slow consumer: one assembled slice per 15 ms against an instant
        // origin, forcing backlog up to (but never past) the window.
        let mut body = resp.into_body();
        let mut out = Vec::with_capacity(data.len());
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            if let Ok(chunk) = frame.into_data() {
                out.extend_from_slice(&chunk);
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        assert_eq!(&out[..], &data[..]);
        sampler.abort();
        // 4 workers -> window 8: (8 + 4) slices * 64 KiB, plus slack.
        let bound = (8 + 4) * 65536 + 65536;
        let peak = peak.load(Ordering::Relaxed);
        assert!(peak > 0, "gauge should observe buffering on a slow origin");
        assert!(peak <= bound, "peak {peak} exceeds bound {bound}");
    }

    #[tokio::test]
    async fn refuses_declared_upload_over_cap_without_origin() {
        // 2 MiB declared against a 1 MiB cap, aimed at an unroutable
        // origin: 413 must come from the guard, never from a dial.
        let shared = test_shared();
        let headers = vec![(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("2097152"),
        )];
        let uri: Uri = "http://127.0.0.1:9/unreachable".parse().unwrap();
        let resp = serve_other(shared, Method::POST, uri, headers, empty_body()).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Sink that reads the whole upload, counts bytes, and echoes the count.
    async fn run_upload_sink(received: Arc<AtomicUsize>) -> SocketAddr {
        use http_body_util::BodyExt;
        use hyper_util::rt::TokioIo;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let received = received.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let received = received.clone();
                        async move {
                            let n = req
                                .into_body()
                                .collect()
                                .await
                                .map(|b| b.to_bytes().len())
                                .unwrap_or(0);
                            received.fetch_add(n, Ordering::SeqCst);
                            let body = Bytes::from(n.to_string());
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(http::header::CONTENT_LENGTH, body.len())
                                    .body(http_body_util::Full::new(body))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        addr
    }

    /// Unknown-length body: chunks until exhausted, so hyper sends chunked.
    struct Dribble {
        left: usize,
    }

    impl http_body::Body for Dribble {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            if this.left == 0 {
                return Poll::Ready(None);
            }
            let n = this.left.min(32768);
            this.left -= n;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![7u8; n])))))
        }
    }

    #[tokio::test]
    async fn cuts_undeclared_upload_at_cap() {
        // 2 MiB chunked POST against a 1 MiB cap: the sink must never see
        // past the cap, and the client gets 413 (the sink only responds
        // after reading EOF, so the trip is always observed first).
        let received = Arc::new(AtomicUsize::new(0));
        let addr = run_upload_sink(received.clone()).await;
        let shared = test_shared();
        let uri: Uri = format!("http://{addr}/up").parse().unwrap();
        let body = Dribble {
            left: 2 * 1024 * 1024,
        }
        .map_err(|never| match never {})
        .boxed();
        let resp = serve_other(shared, Method::POST, uri, vec![], body).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            received.load(Ordering::SeqCst) <= 1024 * 1024,
            "origin saw past the cap"
        );
    }

    #[tokio::test]
    async fn conditional_requests_are_revalidated_by_origin() {
        let shared = test_shared();
        // Unroutable on purpose: a cache hit must never dial.
        let uri: Uri = "http://127.0.0.1:9/no-origin".parse().unwrap();
        let mut origin_headers = HeaderMap::new();
        origin_headers.insert(http::header::ETAG, HeaderValue::from_static("\"v1\""));
        shared.probe_cache.put(
            cache_key(&uri, &HeaderMap::new()),
            ProbeSnapshot {
                total: 100,
                range_ok: true,
                headers: origin_headers,
                probed_at: Instant::now(),
                vary_ua: None,
            },
        );
        let mut req_headers = HeaderMap::new();
        req_headers.insert(
            http::header::IF_NONE_MATCH,
            HeaderValue::from_static("\"v1\""),
        );
        let resp = serve_get(shared.clone(), uri.clone(), req_headers, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        // A Range alongside the conditional is forwarded with the full
        // precondition set rather than synthesized from cached metadata.
        let mut req_headers = HeaderMap::new();
        req_headers.insert(
            http::header::IF_NONE_MATCH,
            HeaderValue::from_static("\"v1\""),
        );
        let resp = serve_get(
            shared,
            uri,
            req_headers,
            Some(HeaderValue::from_static("bytes=0-10")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn slow_downstream_truncates_instead_of_pinning() {
        let data = payload();
        let origin = Arc::new(OriginFixture {
            data: data.clone(),
            flaky: AtomicUsize::new(0),
            full_on_segment: false,
            ranged_hits: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
            max_live: AtomicUsize::new(0),
            delay_ms: 0,
        });
        let addr = run_origin(origin.clone()).await;
        let mut shared = test_shared();
        Arc::get_mut(&mut shared.cfg).unwrap().timeout_secs = 1;
        let metrics = shared.metrics.clone();
        let uri: Uri = format!("http://{addr}/file").parse().unwrap();
        let resp = serve_get(shared, uri, HeaderMap::new(), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Never read the body: the coordinator must give up within ~seconds
        // instead of pinning origin streams for as long as the client idles.
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(resp);
        assert!(metrics.truncations.load(Ordering::Relaxed) >= 1);
    }
}
