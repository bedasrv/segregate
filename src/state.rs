use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use http::{HeaderMap, StatusCode, Uri, uri::Authority};
use hyper::body::Incoming;
use hyper::{Request, Response};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::task::TaskTracker;

use crate::cert::CaAuthority;
use crate::config::Config;
use crate::segment::{BoxBody, EgressClient, ProxyClient};

/// Process-wide shared context. Cloned per connection/request; everything
/// inside is either immutable or lock-free, except the probe cache (short
/// `std` lock, never held across `.await`).
#[derive(Clone)]
pub struct Shared {
    pub cfg: Arc<Config>,
    pub origin: Origin,
    pub ca: Option<Arc<CaAuthority>>,
    pub downloads: Arc<Semaphore>,
    pub connections: Arc<Semaphore>,
    pub tunnels: Arc<Semaphore>,
    pub upgrades: Arc<TaskTracker>,
    pub allowed_ports: Arc<HashSet<u16>>,
    pub mitm_ports: Arc<HashSet<u16>>,
    pub metrics: Arc<Metrics>,
    pub probe_cache: Arc<ProbeCache>,
    pub started: Instant,
}

/// Per-authority origin admission. The map is deliberately bounded because
/// the proxy accepts untrusted authority cardinality; the mutex only guards
/// short map operations and is never held across an await.
struct OriginAdmission {
    max_per_host: usize,
    max_entries: usize,
    hosts: Mutex<HashMap<Authority, HostAdmission>>,
}

struct HostAdmission {
    sem: Arc<Semaphore>,
    blocked_until: Option<Instant>,
}

impl OriginAdmission {
    fn new(max_per_host: usize) -> Self {
        let max_per_host = max_per_host.max(1);
        Self {
            max_per_host,
            max_entries: max_per_host.saturating_mul(16).clamp(64, 4096),
            hosts: Mutex::new(HashMap::new()),
        }
    }

    fn snapshot(&self, authority: &Authority) -> (Arc<Semaphore>, Option<Instant>) {
        let mut hosts = self
            .hosts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(host) = hosts.get(authority) {
            return (host.sem.clone(), host.blocked_until);
        }
        if hosts.len() >= self.max_entries
            && let Some(victim) = hosts.keys().next().cloned()
        {
            hosts.remove(&victim);
        }
        let sem = Arc::new(Semaphore::new(self.max_per_host));
        hosts.insert(
            authority.clone(),
            HostAdmission {
                sem: sem.clone(),
                blocked_until: None,
            },
        );
        (sem, None)
    }

    fn blocked_until(&self, authority: &Authority) -> Option<Instant> {
        self.hosts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(authority)
            .and_then(|host| host.blocked_until)
    }

    fn note_retry_after(&self, authority: &Authority, delay: Duration) {
        let until = Instant::now() + delay;
        let mut hosts = self
            .hosts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(host) = hosts.get_mut(authority) {
            host.blocked_until = Some(host.blocked_until.map_or(until, |old| old.max(until)));
        }
    }

    async fn acquire(
        &self,
        authority: Option<&Authority>,
    ) -> Result<Option<OwnedSemaphorePermit>, OriginError> {
        let Some(authority) = authority else {
            return Ok(None);
        };
        let (sem, blocked_until) = self.snapshot(authority);
        loop {
            if let Some(until) = blocked_until
                && until > Instant::now()
            {
                tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
                continue;
            }
            let permit = sem
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| OriginError::PoolClosed)?;
            if self
                .blocked_until(authority)
                .is_some_and(|until| until > Instant::now())
            {
                drop(permit);
                continue;
            }
            return Ok(Some(permit));
        }
    }
}

/// One origin egress. The global semaphore bounds all active origin streams;
/// each route additionally has its own active-stream quota.
struct EgressRoute {
    name: String,
    interface: Option<String>,
    weight: u32,
    client: ProxyClient,
    sem: Arc<Semaphore>,
    health: Mutex<RouteHealth>,
    requests: AtomicU64,
    errors: AtomicU64,
    retries: AtomicU64,
    bytes: AtomicU64,
    rate_bps: AtomicU64,
    rtt_us: AtomicU64,
    inflight: AtomicU64,
    failure_threshold: u32,
    cooldown: Duration,
    retry_budget: u32,
}

#[derive(Clone, Copy)]
struct RouteHealth {
    healthy: bool,
    consecutive_failures: u32,
    retry_tokens: u32,
    last_failure: Option<Instant>,
}

impl EgressRoute {
    fn new(
        client: EgressClient,
        max_connections: usize,
        failure_threshold: u32,
        cooldown: Duration,
        retry_budget: u32,
    ) -> Self {
        let retry_budget = retry_budget.max(1);
        Self {
            name: client.name,
            interface: client.interface,
            weight: client.weight.max(1),
            client: client.client,
            sem: Arc::new(Semaphore::new(max_connections.max(1))),
            health: Mutex::new(RouteHealth {
                healthy: true,
                consecutive_failures: 0,
                retry_tokens: retry_budget,
                last_failure: None,
            }),
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            rate_bps: AtomicU64::new(0),
            rtt_us: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            failure_threshold: failure_threshold.max(1),
            cooldown,
            retry_budget,
        }
    }

    fn health(&self) -> std::sync::MutexGuard<'_, RouteHealth> {
        self.health
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Cooldown recovery is deliberately passive: a route becomes eligible
    /// again after a quiet period, and the next exchange verifies it by
    /// succeeding. A route with a recent transport failure is temporarily
    /// removed from selection even if it has not yet reached the unhealthy
    /// threshold, which makes the next bounded retry prefer a different path.
    /// No background probe can consume origin permits or send unrequested
    /// traffic.
    fn available(&self) -> bool {
        let mut health = self.health();
        if let Some(last) = health.last_failure {
            if last.elapsed() < self.cooldown {
                return false;
            }
            health.healthy = true;
            health.consecutive_failures = 0;
            health.retry_tokens = self.retry_budget;
            health.last_failure = None;
        }
        health.healthy
    }

    fn mark_success(&self) {
        let mut health = self.health();
        let was_healthy = health.healthy;
        health.healthy = true;
        health.consecutive_failures = 0;
        health.retry_tokens = self.retry_budget;
        health.last_failure = None;
        if !was_healthy {
            tracing::info!(egress = %self.name, "egress recovered");
        }
    }

    fn mark_failure(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        let mut health = self.health();
        if health.consecutive_failures > 0 {
            self.retries.fetch_add(1, Ordering::Relaxed);
        }
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        health.retry_tokens = health.retry_tokens.saturating_sub(1);
        health.last_failure = Some(Instant::now());
        if health.consecutive_failures >= self.failure_threshold || health.retry_tokens == 0 {
            if health.healthy {
                tracing::warn!(
                    egress = %self.name,
                    consecutive_failures = health.consecutive_failures,
                    cooldown_secs = self.cooldown.as_secs(),
                    "egress entered cooldown"
                );
            }
            health.healthy = false;
        }
    }

    fn is_healthy(&self) -> bool {
        self.health().healthy
    }

    fn record_rtt(&self, elapsed: Duration) {
        let sample = elapsed.as_micros().min(u64::MAX as u128) as u64;
        self.rtt_us
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(if old == 0 {
                    sample
                } else {
                    old.saturating_mul(7) / 8 + sample / 8
                })
            })
            .ok();
    }

    fn record_bytes(&self, bytes: u64, elapsed: Duration) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        let nanos = elapsed.as_nanos();
        if nanos == 0 {
            return;
        }
        let sample =
            ((bytes as u128).saturating_mul(1_000_000_000) / nanos).min(u64::MAX as u128) as u64;
        self.rate_bps
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(if old == 0 {
                    sample
                } else {
                    old.saturating_mul(7) / 8 + sample / 8
                })
            })
            .ok();
    }

    fn completion_cost(&self, bytes: u64) -> u64 {
        let rate = self.rate_bps.load(Ordering::Relaxed);
        if rate == 0 {
            return u64::MAX / 4;
        }
        let transfer_ns = ((bytes as u128).saturating_mul(1_000_000_000) / rate as u128)
            .min(u64::MAX as u128) as u64;
        let rtt_ns = self.rtt_us.load(Ordering::Relaxed).saturating_mul(1_000);
        let queue_ns = self
            .inflight
            .load(Ordering::Relaxed)
            .saturating_mul(250_000);
        rtt_ns.saturating_add(transfer_ns).saturating_add(queue_ns)
    }

    fn estimated_rate(&self) -> u64 {
        self.rate_bps.load(Ordering::Relaxed)
    }
}

/// A global origin permit plus the selected egress quota. Dropping an
/// unsettled permit marks a transport failure, which covers callers whose
/// outer timeout cancels an in-flight `Origin::get` future.
pub struct OriginPermit {
    _global: OwnedSemaphorePermit,
    _authority: Option<OwnedSemaphorePermit>,
    route: Arc<EgressRoute>,
    _route: OwnedSemaphorePermit,
    settled: bool,
    request_started: Option<Instant>,
    sample_started: Instant,
    sample_bytes: u64,
    rtt_recorded: bool,
}

impl OriginPermit {
    pub fn interface(&self) -> Option<&str> {
        self.route.interface.as_deref()
    }

    pub fn estimated_rate(&self) -> u64 {
        self.route.estimated_rate()
    }

    pub fn record_bytes(&mut self, bytes: u64) {
        self.sample_bytes = self.sample_bytes.saturating_add(bytes);
        if self.sample_bytes >= 256 * 1024
            || self.sample_started.elapsed() >= Duration::from_millis(250)
        {
            self.flush_sample();
        }
    }

    fn flush_sample(&mut self) {
        if self.sample_bytes == 0 {
            self.sample_started = Instant::now();
            return;
        }
        self.route
            .record_bytes(self.sample_bytes, self.sample_started.elapsed());
        self.sample_bytes = 0;
        self.sample_started = Instant::now();
    }

    pub fn mark_success(&mut self) {
        if !self.rtt_recorded {
            let started = self.request_started.unwrap_or(self.sample_started);
            self.route.record_rtt(started.elapsed());
            self.rtt_recorded = true;
        }
        if !self.settled {
            self.route.mark_success();
            self.settled = true;
        }
    }

    pub fn mark_failure(&mut self) {
        if !self.settled {
            self.route.mark_failure();
            self.settled = true;
        }
    }
}

impl Drop for OriginPermit {
    fn drop(&mut self) {
        self.flush_sample();
        self.route.inflight.fetch_sub(1, Ordering::Relaxed);
        if !self.settled {
            self.route.mark_failure();
        }
    }
}

/// Origin client pool with a process-wide cap and optional weighted egresses.
/// Permits are held for the whole body lifetime, so the count tracks live
/// TCP streams, not just inflight headers.
#[derive(Clone)]
pub struct Origin {
    routes: Arc<Vec<Arc<EgressRoute>>>,
    sem: Arc<Semaphore>,
    cursor: Arc<AtomicU64>,
    admission: Arc<OriginAdmission>,
}

impl Origin {
    #[cfg(test)]
    pub fn new(client: ProxyClient, max_connections: usize) -> Self {
        Self::with_client_limit(client, max_connections, max_connections)
    }

    pub fn with_client_limit(
        client: ProxyClient,
        max_connections: usize,
        max_per_host: usize,
    ) -> Self {
        Self::with_routes_and_limit(
            vec![EgressClient {
                name: "default".to_owned(),
                interface: None,
                weight: 1,
                client,
            }],
            max_connections,
            max_connections,
            2,
            Duration::from_secs(30),
            2,
            max_per_host,
        )
    }

    /// Build a weighted origin pool. `egress_max_connections == 0` means each
    /// route gets the same quota as the global cap.
    #[cfg(test)]
    pub fn with_routes(
        clients: Vec<EgressClient>,
        max_connections: usize,
        egress_max_connections: usize,
        failure_threshold: u32,
        cooldown: Duration,
        retry_budget: u32,
    ) -> Self {
        Self::with_routes_and_limit(
            clients,
            max_connections,
            egress_max_connections,
            failure_threshold,
            cooldown,
            retry_budget,
            max_connections,
        )
    }

    /// Build a weighted origin pool with per-authority admission control.
    pub fn with_routes_and_limit(
        clients: Vec<EgressClient>,
        max_connections: usize,
        egress_max_connections: usize,
        failure_threshold: u32,
        cooldown: Duration,
        retry_budget: u32,
        max_per_host: usize,
    ) -> Self {
        let route_quota = if egress_max_connections == 0 {
            max_connections
        } else {
            egress_max_connections
        };
        let routes = clients
            .into_iter()
            .map(|client| {
                Arc::new(EgressRoute::new(
                    client,
                    route_quota,
                    failure_threshold,
                    cooldown,
                    retry_budget,
                ))
            })
            .collect();
        Self {
            routes: Arc::new(routes),
            sem: Arc::new(Semaphore::new(max_connections.max(1))),
            cursor: Arc::new(AtomicU64::new(0)),
            admission: Arc::new(OriginAdmission::new(max_per_host)),
        }
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// One allocation per download planner, not per request. A zero estimate
    /// falls back to the configured weight.
    pub fn rate_hints(&self) -> Vec<u64> {
        self.routes
            .iter()
            .map(|route| {
                let rate = route.estimated_rate();
                if rate == 0 {
                    route.weight as u64 * 1_000_000
                } else {
                    rate
                }
            })
            .collect()
    }

    fn select_route(&self, expected_bytes: u64) -> Arc<EgressRoute> {
        let has_estimates = self.routes.iter().any(|route| route.estimated_rate() > 0);
        if self.routes.len() > 1 && expected_bytes > 0 && has_estimates {
            let mut best: Option<(&Arc<EgressRoute>, u64)> = None;
            for route in self.routes.iter().filter(|route| route.available()) {
                let cost = route.completion_cost(expected_bytes);
                if best.is_none_or(|(_, best_cost)| cost < best_cost) {
                    best = Some((route, cost));
                }
            }
            if let Some((route, _)) = best {
                return Arc::clone(route);
            }
        }

        let mut total = 0u64;
        for route in self.routes.iter().filter(|route| route.available()) {
            total = total.saturating_add(route.weight as u64);
        }
        let use_all = total == 0;
        if use_all {
            total = self
                .routes
                .iter()
                .map(|route| route.weight as u64)
                .sum::<u64>()
                .max(1);
        }
        let mut point = self.cursor.fetch_add(1, Ordering::Relaxed) % total;
        for route in self.routes.iter() {
            if !use_all && !route.available() {
                continue;
            }
            let weight = route.weight as u64;
            if point < weight {
                return Arc::clone(route);
            }
            point -= weight;
        }
        self.routes
            .iter()
            .find(|route| route.available())
            .map(Arc::clone)
            .or_else(|| self.routes.first().map(Arc::clone))
            .expect("Origin must contain at least one route")
    }

    async fn acquire_route(&self, expected_bytes: u64) -> Result<OriginPermit, OriginError> {
        // Prefer a non-full route so one saturated interface cannot head-of-
        // line block all other egresses. If all are full, wait on one route.
        for _ in 0..self.routes.len() {
            let route = self.select_route(expected_bytes);
            let Ok(route_permit) = route.sem.clone().try_acquire_owned() else {
                continue;
            };
            let global_permit = self
                .sem
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| OriginError::PoolClosed)?;
            route.requests.fetch_add(1, Ordering::Relaxed);
            route.inflight.fetch_add(1, Ordering::Relaxed);
            return Ok(OriginPermit {
                _global: global_permit,
                _authority: None,
                route,
                _route: route_permit,
                settled: false,
                request_started: None,
                sample_started: Instant::now(),
                sample_bytes: 0,
                rtt_recorded: false,
            });
        }
        let route = self.select_route(expected_bytes);
        let route_permit = route
            .sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| OriginError::PoolClosed)?;
        let global_permit = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| OriginError::PoolClosed)?;
        route.requests.fetch_add(1, Ordering::Relaxed);
        route.inflight.fetch_add(1, Ordering::Relaxed);
        Ok(OriginPermit {
            _global: global_permit,
            _authority: None,
            route,
            _route: route_permit,
            settled: false,
            request_started: None,
            sample_started: Instant::now(),
            sample_bytes: 0,
            rtt_recorded: false,
        })
    }

    async fn acquire_exchange(
        &self,
        authority: Option<&Authority>,
        expected_bytes: u64,
    ) -> Result<OriginPermit, OriginError> {
        let authority_permit = self.admission.acquire(authority).await?;
        let mut permit = self.acquire_route(expected_bytes).await?;
        permit._authority = authority_permit;
        Ok(permit)
    }

    /// Test helper for acquiring a route permit without an authority.
    #[cfg(test)]
    pub async fn acquire(&self) -> Result<OriginPermit, OriginError> {
        self.acquire_exchange(None, 0).await
    }

    /// Acquire an origin permit for a raw CONNECT authority, including
    /// per-authority admission control.
    pub async fn acquire_for(&self, authority: &str) -> Result<OriginPermit, OriginError> {
        let authority = authority.parse::<Authority>().ok();
        self.acquire_exchange(authority.as_ref(), 0).await
    }

    /// One origin exchange: acquires authority, global, and route permits,
    /// then issues the request. Hold the permit while streaming the body.
    pub async fn get(
        &self,
        req: Request<BoxBody>,
    ) -> Result<(Response<Incoming>, OriginPermit), OriginError> {
        self.get_sized(req, 0).await
    }

    /// Sized variant used by the range scheduler. The expected byte count is
    /// only a prediction hint; it never changes the requested HTTP range.
    pub async fn get_sized(
        &self,
        req: Request<BoxBody>,
        expected_bytes: u64,
    ) -> Result<(Response<Incoming>, OriginPermit), OriginError> {
        let authority = req.uri().authority().cloned();
        let mut permit = self
            .acquire_exchange(authority.as_ref(), expected_bytes)
            .await?;
        let route = permit.route.clone();
        let request_started = Instant::now();
        permit.request_started = Some(request_started);
        permit.sample_started = request_started;
        match route.client.request(req).await {
            Ok(response) => {
                if let Some(authority) = authority.as_ref()
                    && matches!(
                        response.status(),
                        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                    )
                {
                    let delay =
                        retry_after(response.headers()).unwrap_or(Duration::from_millis(250));
                    self.admission.note_retry_after(authority, delay);
                }
                permit.mark_success();
                Ok((response, permit))
            }
            Err(error) => {
                permit.mark_failure();
                Err(OriginError::Hyper(error))
            }
        }
    }

    /// Small operator-facing route snapshot, included in `/__stats`.
    pub fn egress_json(&self) -> String {
        self.routes
            .iter()
            .map(|route| {
                let name = route
                    .name
                    .chars()
                    .map(|c| match c {
                        '"' | '\\' => '_',
                        c if c.is_control() => '_',
                        c => c,
                    })
                    .collect::<String>();
                format!(
                    "{{\"name\":\"{name}\",\"weight\":{},\"healthy\":{},\"available\":{},\"inflight\":{},\"bytes\":{},\"rate_bps\":{},\"rtt_us\":{},\"requests\":{},\"transport_errors\":{},\"retries\":{}}}",
                    route.weight,
                    route.is_healthy(),
                    route.available(),
                    route.inflight.load(Ordering::Relaxed),
                    route.bytes.load(Ordering::Relaxed),
                    route.rate_bps.load(Ordering::Relaxed),
                    route.rtt_us.load(Ordering::Relaxed),
                    route.requests.load(Ordering::Relaxed),
                    route.errors.load(Ordering::Relaxed),
                    route.retries.load(Ordering::Relaxed),
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    let seconds = value.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds.min(60)))
}

/// How one origin exchange can fail. `PoolClosed` documents an invariant
/// (the semaphore is never closed) as a value instead of an `expect`.
#[derive(Debug)]
pub enum OriginError {
    /// The origin (or the way there) failed.
    Hyper(hyper_util::client::legacy::Error),
    /// Internal pool semaphore closed; signals a shutdown bug, never load.
    PoolClosed,
}

/// Cacheable probe outcome (small: length + borrowed-then-cloned headers).
#[derive(Debug, Clone)]
pub struct ProbeSnapshot {
    pub total: u64,
    pub range_ok: bool,
    pub headers: HeaderMap,
    /// When the probe ran; replayed as `Age` so cached responses stay honest.
    pub probed_at: Instant,
    /// Request `User-Agent` this entry is pinned to (origin `Vary` named
    /// it); `None` serves any client.
    pub vary_ua: Option<String>,
}

impl ProbeSnapshot {
    /// Age of a probe snapshot for HTTP freshness calculations.
    pub fn age(&self) -> Duration {
        self.probed_at.elapsed()
    }
}

/// Build an opaque cache key from the full URI and every repeated
/// `Authorization`, `Cookie`, and `User-Agent` value, in header order.
///
/// The SHA-256 digest prevents session credentials (including credentials
/// embedded in a URI) from being retained in the cache's keys.
pub fn cache_key(uri: &Uri, headers: &HeaderMap) -> String {
    fn update_framed(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"segregate/probe-cache/v1\0");
    update_framed(&mut hasher, uri.to_string().as_bytes());
    for name in [
        http::header::AUTHORIZATION,
        http::header::COOKIE,
        http::header::USER_AGENT,
    ] {
        let values = headers.get_all(name);
        hasher.update((values.iter().count() as u64).to_be_bytes());
        for value in values {
            update_framed(&mut hasher, value.as_bytes());
        }
    }

    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut key = String::with_capacity(digest.len() * 2);
    for byte in digest {
        key.push(char::from(HEX[(byte >> 4) as usize]));
        key.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    key
}

#[derive(Debug)]
struct InflightProbe {
    generation: Arc<()>,
    sender: Weak<tokio::sync::watch::Sender<Option<ProbeSnapshot>>>,
}

struct CachedProbe {
    snapshot: ProbeSnapshot,
    inserted: Instant,
}

impl std::fmt::Debug for CachedProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedProbe")
            .field("total", &self.snapshot.total)
            .field("range_ok", &self.snapshot.range_ok)
            .field("inserted", &self.inserted)
            .finish()
    }
}

/// Bounded, TTLed probe cache. Invalidation happens on 416 (stale length);
/// entries also expire via TTL. `std` lock: critical sections only clone
/// small maps, never `.await`.
#[derive(Debug)]
pub struct ProbeCache {
    ttl: Duration,
    max_entries: usize,
    inner: RwLock<HashMap<String, CachedProbe>>,
    /// In-flight probes for stampede protection. The weak sender lets a
    /// cancelled leader's slot be pruned without keeping its watch channel
    /// alive; the map never exceeds `max_entries`.
    inflight: tokio::sync::Mutex<HashMap<String, InflightProbe>>,
}

impl ProbeCache {
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs),
            max_entries: max_entries.max(1),
            inner: RwLock::new(HashMap::new()),
            inflight: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Lock recovery: a poisoned lock means another task panicked mid-access.
    /// For a cache, continuing with possibly-stale state is strictly more
    /// available than crashing the serving task, so recover instead.
    fn read_inner(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, CachedProbe>> {
        self.inner.read().unwrap_or_else(|poison| {
            tracing::warn!("probe cache lock poisoned; recovering");
            poison.into_inner()
        })
    }

    /// See [`ProbeCache::read_inner`].
    fn write_inner(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, CachedProbe>> {
        self.inner.write().unwrap_or_else(|poison| {
            tracing::warn!("probe cache lock poisoned; recovering");
            poison.into_inner()
        })
    }

    pub fn disabled(&self) -> bool {
        self.ttl.is_zero()
    }

    pub fn get(&self, key: &str) -> Option<ProbeSnapshot> {
        if self.disabled() {
            return None;
        }
        let inner = self.read_inner();
        let entry = inner.get(key)?;
        if entry.inserted.elapsed() > self.ttl {
            return None;
        }
        Some(entry.snapshot.clone())
    }

    pub fn put(&self, key: String, snapshot: ProbeSnapshot) {
        if self.disabled() {
            return;
        }
        let mut inner = self.write_inner();
        if inner.len() >= self.max_entries && !inner.contains_key(&key) {
            // Bounded without a dependency: evict one arbitrary entry.
            if let Some(victim) = inner.keys().next().cloned() {
                inner.remove(&victim);
            }
        }
        inner.insert(
            key,
            CachedProbe {
                snapshot,
                inserted: Instant::now(),
            },
        );
    }

    pub fn invalidate(&self, key: &str) {
        self.write_inner().remove(key);
    }

    async fn remove_inflight_generation(&self, key: &str, generation: &Arc<()>) {
        let mut inflight = self.inflight.lock().await;
        if inflight
            .get(key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.generation, generation))
        {
            inflight.remove(key);
        }
    }

    /// Cached hit, or run `probe` once across concurrent tasks for this key
    /// and share its outcome. `wait_budget` bounds follower wait time. A
    /// timed-out follower probes independently, and cleanup is generation-
    /// checked so a late leader can never remove a newer probe's slot.
    pub async fn get_or_probe<F, Fut>(
        &self,
        key: &str,
        wait_budget: Duration,
        run: F,
    ) -> Option<ProbeSnapshot>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<ProbeSnapshot>> + Send,
    {
        if self.disabled() {
            return run().await;
        }
        if let Some(hit) = self.get(key) {
            return Some(hit);
        }
        enum Role<F> {
            Leader {
                generation: Arc<()>,
                sender: Arc<tokio::sync::watch::Sender<Option<ProbeSnapshot>>>,
                run: F,
            },
            Follower {
                generation: Arc<()>,
                result: tokio::sync::watch::Receiver<Option<ProbeSnapshot>>,
            },
            Standalone(F),
        }

        let mut run = Some(run);
        let role = {
            let mut inflight = self.inflight.lock().await;
            // Recheck: another task may have filled while we queued.
            if let Some(hit) = self.get(key) {
                return Some(hit);
            }

            // Leaders own the only strong sender. Weak entries left by task
            // cancellation/panic carry no live probe and are safe to prune.
            inflight.retain(|_, entry| entry.sender.upgrade().is_some());
            let follower = inflight.get(key).and_then(|entry| {
                entry
                    .sender
                    .upgrade()
                    .map(|sender| (entry.generation.clone(), sender.subscribe()))
            });
            if let Some((generation, result)) = follower {
                Role::Follower { generation, result }
            } else {
                inflight.remove(key);
                if inflight.len() >= self.max_entries {
                    // Never evict a live generation. Bounded memory wins over
                    // stampede sharing; this request still probes normally.
                    let run = run.take()?;
                    Role::Standalone(run)
                } else {
                    let run = run.take()?;
                    let generation = Arc::new(());
                    let (sender, _result) = tokio::sync::watch::channel(None);
                    let sender = Arc::new(sender);
                    inflight.insert(
                        key.to_owned(),
                        InflightProbe {
                            generation: generation.clone(),
                            sender: Arc::downgrade(&sender),
                        },
                    );
                    Role::Leader {
                        generation,
                        sender,
                        run,
                    }
                }
            }
        };

        match role {
            Role::Follower {
                generation,
                mut result,
            } => {
                let updated = matches!(
                    tokio::time::timeout(wait_budget, result.wait_for(|value| value.is_some()))
                        .await,
                    Ok(Ok(_))
                );
                if updated {
                    return result.borrow().clone();
                }
                self.remove_inflight_generation(key, &generation).await;
                match run {
                    Some(run) => run().await,
                    None => None,
                }
            }
            Role::Leader {
                generation,
                sender,
                run,
            } => {
                let result = run().await;
                let _ = sender.send(result.clone());
                self.remove_inflight_generation(key, &generation).await;
                result
            }
            Role::Standalone(run) => run().await,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.read_inner().len()
    }

    #[cfg(test)]
    async fn inflight_len(&self) -> usize {
        self.inflight.lock().await.len()
    }
}

/// Lock-free operational counters, exposed via `/__stats`.
#[derive(Debug, Default)]
pub struct Metrics {
    pub downloads: AtomicU64,
    pub completed_downloads: AtomicU64,
    pub download_ms_total: AtomicU64,
    pub download_ms_max: AtomicU64,
    pub bytes_out: AtomicU64,
    /// Completed-but-unflushed slice bytes currently held (never leaks:
    /// the coordinator subtracts the remainder however it exits).
    pub buffered_bytes: AtomicU64,
    pub origin_retries: AtomicU64,
    pub hedges: AtomicU64,
    pub work_steals: AtomicU64,
    pub truncations: AtomicU64,
    pub cache_hits: AtomicU64,
    /// Requests refused before any origin work (CONNECT denied, 503).
    pub refused: AtomicU64,
    /// Failed CONNECT handlings (tunnel/MITM errors, sampled in logs).
    pub connect_errors: AtomicU64,
}

/// Log-sampling for hot failure paths: first occurrence plus every `each`-th.
/// Prevents log-disk-fill during sustained outages while keeping visibility.
pub fn sample_hit(n: u64, each: u64) -> bool {
    n == 1 || n.is_multiple_of(each.max(1))
}

impl Metrics {
    pub fn render_json_with_egress(&self, uptime_secs: u64, egress_json: &str) -> String {
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "{{\"downloads\":{},\"completed_downloads\":{},\"download_ms_total\":{},\"download_ms_max\":{},\"bytes_out\":{},\"buffered_bytes\":{},\"origin_retries\":{},\"hedges\":{},\"work_steals\":{},\"truncations\":{},\"cache_hits\":{},\"refused\":{},\"connect_errors\":{},\"uptime_secs\":{},\"egress\":[{egress_json}]}}",
            load(&self.downloads),
            load(&self.completed_downloads),
            load(&self.download_ms_total),
            load(&self.download_ms_max),
            load(&self.bytes_out),
            load(&self.buffered_bytes),
            load(&self.origin_retries),
            load(&self.hedges),
            load(&self.work_steals),
            load(&self.truncations),
            load(&self.cache_hits),
            load(&self.refused),
            load(&self.connect_errors),
            uptime_secs,
        )
    }
}

/// Parse `--allow-connect-ports "443,80"` into a set.
pub fn parse_connect_ports(s: &str) -> Result<HashSet<u16>, String> {
    let mut out = HashSet::new();
    for token in s.split(',') {
        let port: u16 = token
            .trim()
            .parse()
            .map_err(|_| format!("bad CONNECT port: {token:?}"))?;
        if port == 0 {
            return Err("CONNECT port 0 is not allowed".to_owned());
        }
        out.insert(port);
    }
    if out.is_empty() {
        return Err("CONNECT port allowlist is empty".to_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn parses_port_allowlist() {
        let set = parse_connect_ports("443,80").unwrap();
        assert!(set.contains(&443) && set.contains(&80));
        assert!(parse_connect_ports("").is_err());
        assert!(parse_connect_ports("443,abc").is_err());
        assert!(parse_connect_ports("0").is_err());
    }

    #[test]
    fn cache_keys_separate_sessions_and_user_agents() {
        let uri: Uri = "https://h/file".parse().unwrap();
        let mut auth_a = HeaderMap::new();
        auth_a.append(http::header::AUTHORIZATION, HeaderValue::from_static("a"));
        let mut auth_b = HeaderMap::new();
        auth_b.append(http::header::AUTHORIZATION, HeaderValue::from_static("b"));
        assert_ne!(cache_key(&uri, &auth_a), cache_key(&uri, &auth_b));

        let mut ua_a = HeaderMap::new();
        ua_a.append(
            http::header::USER_AGENT,
            HeaderValue::from_static("agent-a"),
        );
        let mut ua_b = HeaderMap::new();
        ua_b.append(
            http::header::USER_AGENT,
            HeaderValue::from_static("agent-b"),
        );
        assert_ne!(cache_key(&uri, &ua_a), cache_key(&uri, &ua_b));

        let empty = HeaderMap::new();
        assert_eq!(cache_key(&uri, &empty), cache_key(&uri, &empty));
        let other_uri: Uri = "https://h/other".parse().unwrap();
        assert_ne!(cache_key(&uri, &empty), cache_key(&other_uri, &empty));
    }

    #[test]
    fn cache_keys_include_repeated_header_values() {
        let uri: Uri = "https://h/file".parse().unwrap();
        let mut first = HeaderMap::new();
        first.append(http::header::COOKIE, HeaderValue::from_static("a=1"));
        first.append(http::header::COOKIE, HeaderValue::from_static("b=2"));
        let mut second = HeaderMap::new();
        second.append(http::header::COOKIE, HeaderValue::from_static("a=1"));
        let mut reversed = HeaderMap::new();
        reversed.append(http::header::COOKIE, HeaderValue::from_static("b=2"));
        reversed.append(http::header::COOKIE, HeaderValue::from_static("a=1"));
        assert_ne!(cache_key(&uri, &first), cache_key(&uri, &second));
        assert_ne!(cache_key(&uri, &first), cache_key(&uri, &reversed));
    }

    #[test]
    fn cache_keys_do_not_retain_secrets() {
        let uri: Uri = "https://h/file?token=uri-secret-token".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("super-secret-token"),
        );
        headers.append(
            http::header::COOKIE,
            HeaderValue::from_static("cookie-secret"),
        );
        let key = cache_key(&uri, &headers);
        assert_eq!(key.len(), 64);
        assert!(!key.contains("uri-secret-token"));
        assert!(!key.contains("super-secret-token"));
        assert!(!key.contains("cookie-secret"));
    }

    #[test]
    fn cache_put_get_invalidate() {
        let cache = ProbeCache::new(60, 8);
        let uri: Uri = "https://h/f".parse().unwrap();
        let key = cache_key(&uri, &HeaderMap::new());
        assert!(cache.get(&key).is_none());
        cache.put(
            key.clone(),
            ProbeSnapshot {
                total: 42,
                range_ok: true,
                headers: HeaderMap::new(),
                probed_at: Instant::now(),
                vary_ua: None,
            },
        );
        let hit = cache.get(&key).unwrap();
        assert_eq!((hit.total, hit.range_ok), (42, true));
        assert!(hit.age() <= Duration::from_secs(1));
        cache.invalidate(&key);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn cache_evicts_when_full() {
        let cache = ProbeCache::new(60, 2);
        for i in 0..4 {
            let uri: Uri = format!("https://h/f{i}").parse().unwrap();
            cache.put(
                cache_key(&uri, &HeaderMap::new()),
                ProbeSnapshot {
                    total: i,
                    range_ok: true,
                    headers: HeaderMap::new(),
                    probed_at: Instant::now(),
                    vary_ua: None,
                },
            );
        }
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cache_survives_lock_poison() {
        use std::sync::Arc;
        let cache = Arc::new(ProbeCache::new(60, 8));
        // Poison the lock from another thread, then prove the cache keeps
        // serving instead of panicking on every access.
        let poisoned = Arc::clone(&cache);
        let handle = std::thread::spawn(move || {
            let _guard = poisoned.inner.write().unwrap();
            panic!("intentional poison");
        });
        assert!(handle.join().is_err());
        let key = cache_key(&"https://h/f".parse().unwrap(), &HeaderMap::new());
        cache.put(
            key.clone(),
            ProbeSnapshot {
                total: 1,
                range_ok: true,
                headers: HeaderMap::new(),
                probed_at: Instant::now(),
                vary_ua: None,
            },
        );
        assert_eq!(cache.get(&key).unwrap().total, 1);
        cache.invalidate(&key);
        assert!(cache.get(&key).is_none());
    }

    #[tokio::test]
    async fn concurrent_probes_share_one_origin_call() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        let cache = Arc::new(ProbeCache::new(60, 8));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_probe("k", Duration::from_secs(5), || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Some(ProbeSnapshot {
                            total: 7,
                            range_ok: true,
                            headers: HeaderMap::new(),
                            probed_at: Instant::now(),
                            vary_ua: None,
                        })
                    })
                    .await
            }));
        }
        for t in tasks {
            let res = t.await.unwrap();
            assert_eq!(res.unwrap().total, 7);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn follower_budget_expiry_probes_alone() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        let cache = Arc::new(ProbeCache::new(60, 8));
        let calls = Arc::new(AtomicUsize::new(0));
        // Leader occupies the slot with a probe that never resolves.
        let leader = tokio::spawn({
            let cache = cache.clone();
            let calls = calls.clone();
            async move {
                cache
                    .get_or_probe("k", Duration::from_secs(5), || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        None
                    })
                    .await
            }
        });
        // Let the leader register its slot first.
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Follower budget (50 ms) expires long before the leader finishes:
        // it must probe on its own rather than hang.
        let calls_follower = calls.clone();
        let res = cache
            .get_or_probe("k", Duration::from_millis(50), || async move {
                calls_follower.fetch_add(1, Ordering::SeqCst);
                Some(ProbeSnapshot {
                    total: 9,
                    range_ok: true,
                    headers: HeaderMap::new(),
                    probed_at: Instant::now(),
                    vary_ua: None,
                })
            })
            .await;
        assert_eq!(res.unwrap().total, 9);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        leader.abort();
    }

    #[tokio::test]
    async fn stale_leader_cleanup_cannot_remove_new_generation() {
        use tokio::sync::Notify;

        let cache = Arc::new(ProbeCache::new(60, 8));
        let old_started = Arc::new(Notify::new());
        let release_old = Arc::new(Notify::new());
        let old = tokio::spawn({
            let cache = cache.clone();
            let old_started = old_started.clone();
            let release_old = release_old.clone();
            async move {
                cache
                    .get_or_probe("same-key", Duration::from_secs(5), || async move {
                        old_started.notify_one();
                        release_old.notified().await;
                        Some(ProbeSnapshot {
                            total: 1,
                            range_ok: true,
                            headers: HeaderMap::new(),
                            probed_at: Instant::now(),
                            vary_ua: None,
                        })
                    })
                    .await
            }
        });
        old_started.notified().await;

        // This follower removes generation 1 after its budget, while the old
        // leader is deliberately kept alive.
        let follower = cache
            .get_or_probe("same-key", Duration::from_millis(10), || async {
                Some(ProbeSnapshot {
                    total: 2,
                    range_ok: true,
                    headers: HeaderMap::new(),
                    probed_at: Instant::now(),
                    vary_ua: None,
                })
            })
            .await
            .unwrap();
        assert_eq!(follower.total, 2);

        let new_started = Arc::new(Notify::new());
        let release_new = Arc::new(Notify::new());
        let new = tokio::spawn({
            let cache = cache.clone();
            let new_started = new_started.clone();
            let release_new = release_new.clone();
            async move {
                cache
                    .get_or_probe("same-key", Duration::from_secs(5), || async move {
                        new_started.notify_one();
                        release_new.notified().await;
                        Some(ProbeSnapshot {
                            total: 3,
                            range_ok: true,
                            headers: HeaderMap::new(),
                            probed_at: Instant::now(),
                            vary_ua: None,
                        })
                    })
                    .await
            }
        });
        new_started.notified().await;

        release_old.notify_one();
        assert_eq!(old.await.unwrap().unwrap().total, 1);
        assert_eq!(
            cache.inflight_len().await,
            1,
            "old generation removed the new slot"
        );

        release_new.notify_one();
        assert_eq!(new.await.unwrap().unwrap().total, 3);
        assert_eq!(cache.inflight_len().await, 0);
    }

    #[tokio::test]
    async fn inflight_map_is_bounded_without_evicting_live_probes() {
        use tokio::sync::Notify;

        let cache = Arc::new(ProbeCache::new(60, 1));
        let started = Arc::new(Notify::new());
        let leader = tokio::spawn({
            let cache = cache.clone();
            let started = started.clone();
            async move {
                cache
                    .get_or_probe("first", Duration::from_secs(5), || async move {
                        started.notify_one();
                        std::future::pending::<()>().await;
                        None
                    })
                    .await
            }
        });
        started.notified().await;

        let standalone = cache
            .get_or_probe("second", Duration::from_millis(10), || async {
                Some(ProbeSnapshot {
                    total: 9,
                    range_ok: true,
                    headers: HeaderMap::new(),
                    probed_at: Instant::now(),
                    vary_ua: None,
                })
            })
            .await
            .unwrap();
        assert_eq!(standalone.total, 9);
        assert_eq!(cache.inflight_len().await, 1);

        leader.abort();
        let _ = leader.await;
    }

    #[tokio::test]
    async fn egress_stats_track_route_exchanges() {
        let clients = vec![
            EgressClient {
                name: "primary".to_owned(),
                interface: None,
                weight: 3,
                client: crate::segment::build_client(None, 4).unwrap(),
            },
            EgressClient {
                name: "backup".to_owned(),
                interface: None,
                weight: 1,
                client: crate::segment::build_client(None, 4).unwrap(),
            },
        ];
        let origin = Origin::with_routes(clients, 4, 2, 2, Duration::from_secs(30), 2);
        let mut permit = origin.acquire().await.unwrap();
        permit.mark_failure();
        drop(permit);
        let mut permit = origin.acquire().await.unwrap();
        permit.mark_success();
        permit.record_bytes(4096);
        drop(permit);
        let json = origin.egress_json();
        assert!(json.contains("\"name\":\"primary\""));
        assert!(json.contains("\"name\":\"backup\""));
        assert!(json.contains("\"weight\":3"));
        assert!(json.contains("\"transport_errors\":1"));
        assert!(json.contains("\"requests\":1"));
        assert!(json.contains("\"bytes\":4096"));
        assert!(json.contains("\"inflight\":0"));
    }

    #[test]
    fn metrics_renders_json() {
        let m = Metrics::default();
        m.downloads.fetch_add(3, Ordering::Relaxed);
        let json = m.render_json_with_egress(7, "[]");
        assert!(json.contains("\"downloads\":3") && json.contains("\"uptime_secs\":7"));
        assert!(json.contains("\"buffered_bytes\":0"));
    }
}
