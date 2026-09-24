use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use http::{HeaderMap, HeaderValue, Uri};
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::cert::CaAuthority;
use crate::config::Config;
use crate::segment::{BoxBody, ProxyClient};

/// Process-wide shared context. Cloned per connection/request; everything
/// inside is either immutable or lock-free, except the probe cache (short
/// `std` lock, never held across `.await`).
#[derive(Clone)]
pub struct Shared {
    pub cfg: Arc<Config>,
    pub origin: Origin,
    pub ca: Option<Arc<CaAuthority>>,
    pub downloads: Arc<Semaphore>,
    pub allowed_ports: Arc<HashSet<u16>>,
    pub mitm_ports: Arc<HashSet<u16>>,
    pub metrics: Arc<Metrics>,
    pub probe_cache: Arc<ProbeCache>,
    pub started: Instant,
}

/// Origin client with a process-wide cap on concurrent origin exchanges.
/// Permits are held for the whole body lifetime, so the count tracks live
/// TCP streams, not just inflight headers.
#[derive(Clone)]
pub struct Origin {
    client: ProxyClient,
    sem: Arc<Semaphore>,
}

impl Origin {
    pub fn new(client: ProxyClient, max_connections: usize) -> Self {
        Self {
            client,
            sem: Arc::new(Semaphore::new(max_connections.max(1))),
        }
    }

    /// One origin exchange: acquires a pool permit (times out via the
    /// caller's `timeout`, counting as a transient failure) and issues the
    /// request. Hold the permit while streaming the body.
    pub async fn get(
        &self,
        req: Request<BoxBody>,
    ) -> Result<(Response<Incoming>, OwnedSemaphorePermit), OriginError> {
        let permit = match self.sem.clone().acquire_owned().await {
            // Unreachable today: nothing ever calls `Semaphore::close`, and
            // the `Arc` keeps it alive. Returned as an error (never a panic)
            // so a future refactor cannot turn this into a crash.
            Ok(p) => p,
            Err(_) => return Err(OriginError::PoolClosed),
        };
        let resp = self.client.request(req).await.map_err(OriginError::Hyper)?;
        Ok((resp, permit))
    }
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

/// Keyed by absolute URI plus fingerprints of the headers that change the
/// representation for authenticated origins, so one user's cached length
/// never serves another's session — without retaining their secrets.
pub fn cache_key(uri: &Uri, auth: Option<&HeaderValue>, cookie: Option<&HeaderValue>) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    fn fingerprint(v: &HeaderValue) -> String {
        let mut h = DefaultHasher::new();
        v.as_bytes().hash(&mut h);
        format!("{:016x}", h.finish())
    }
    let uri = uri.to_string();
    let mut key = String::with_capacity(uri.len() + 64);
    key.push_str(&uri);
    key.push('|');
    key.push_str(&auth.map(fingerprint).unwrap_or_default());
    key.push('|');
    key.push_str(&cookie.map(fingerprint).unwrap_or_default());
    key
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
    /// In-flight probes for stampede protection: concurrent downloads of
    /// the same uncached URL share one origin probe instead of each
    /// firing their own.
    inflight:
        tokio::sync::Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<ProbeSnapshot>>>>,
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

    /// Cached hit, or run `probe` exactly once across concurrent tasks for
    /// this key and share its outcome. `wait_budget` bounds how long a
    /// follower waits for the leader; past it — or if the leader is gone
    /// (its sender drops on panic) — the follower cleans the slot and
    /// probes on its own. Degraded, never hung.
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
            Leader(tokio::sync::watch::Sender<Option<ProbeSnapshot>>, Option<F>),
            Follower(tokio::sync::watch::Receiver<Option<ProbeSnapshot>>),
        }
        let mut run = Some(run);
        let role = {
            let mut inflight = self.inflight.lock().await;
            // Recheck: another task may have filled while we queued.
            if let Some(hit) = self.get(key) {
                return Some(hit);
            }
            match inflight.get(key) {
                Some(rx) => Role::Follower(rx.clone()),
                None => {
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    inflight.insert(key.to_owned(), rx);
                    Role::Leader(tx, run.take())
                }
            }
        };
        match role {
            Role::Follower(mut rx) => {
                let updated = matches!(
                    tokio::time::timeout(wait_budget, rx.wait_for(|v| v.is_some())).await,
                    Ok(Ok(_))
                );
                if updated {
                    return rx.borrow().clone();
                }
                self.inflight.lock().await.remove(key);
                match run {
                    Some(r) => r().await,
                    // Unreachable: only the Leader arm takes `run`.
                    // Fall back to a miss rather than panic.
                    None => None,
                }
            }
            Role::Leader(tx, run) => {
                // Unreachable in the `None` case (only this arm takes `run`);
                // a miss degrades to passthrough downstream, never a panic.
                let res = match run {
                    Some(r) => r().await,
                    None => None,
                };
                let _ = tx.send(res.clone());
                // Slot served its purpose; late arrivals use the cache or
                // elect a fresh leader.
                self.inflight.lock().await.remove(key);
                res
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.read_inner().len()
    }
}

/// Lock-free operational counters, exposed via `/__stats`.
#[derive(Debug, Default)]
pub struct Metrics {
    pub downloads: AtomicU64,
    pub bytes_out: AtomicU64,
    /// Completed-but-unflushed slice bytes currently held (never leaks:
    /// the coordinator subtracts the remainder however it exits).
    pub buffered_bytes: AtomicU64,
    pub origin_retries: AtomicU64,
    pub hedges: AtomicU64,
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
    pub fn render_json(&self, uptime_secs: u64) -> String {
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "{{\"downloads\":{},\"bytes_out\":{},\"buffered_bytes\":{},\"origin_retries\":{},\"hedges\":{},\"truncations\":{},\"cache_hits\":{},\"refused\":{},\"connect_errors\":{},\"uptime_secs\":{}}}",
            load(&self.downloads),
            load(&self.bytes_out),
            load(&self.buffered_bytes),
            load(&self.origin_retries),
            load(&self.hedges),
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

    #[test]
    fn parses_port_allowlist() {
        let set = parse_connect_ports("443,80").unwrap();
        assert!(set.contains(&443) && set.contains(&80));
        assert!(parse_connect_ports("").is_err());
        assert!(parse_connect_ports("443,abc").is_err());
        assert!(parse_connect_ports("0").is_err());
    }

    #[test]
    fn cache_keys_separate_sessions() {
        let uri: Uri = "https://h/file".parse().unwrap();
        let a = HeaderValue::from_static("a");
        let b = HeaderValue::from_static("b");
        assert_ne!(
            cache_key(&uri, Some(&a), None),
            cache_key(&uri, Some(&b), None)
        );
        assert_eq!(cache_key(&uri, None, None), cache_key(&uri, None, None));
    }

    #[test]
    fn cache_keys_do_not_retain_secrets() {
        let uri: Uri = "https://h/file".parse().unwrap();
        let secret = HeaderValue::from_static("super-secret-token");
        let key = cache_key(&uri, Some(&secret), Some(&secret));
        assert!(!key.contains("super-secret-token"));
    }

    #[test]
    fn cache_put_get_invalidate() {
        let cache = ProbeCache::new(60, 8);
        let uri: Uri = "https://h/f".parse().unwrap();
        let key = cache_key(&uri, None, None);
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
        cache.invalidate(&key);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn cache_evicts_when_full() {
        let cache = ProbeCache::new(60, 2);
        for i in 0..4 {
            let uri: Uri = format!("https://h/f{i}").parse().unwrap();
            cache.put(
                cache_key(&uri, None, None),
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
        let key = cache_key(&"https://h/f".parse().unwrap(), None, None);
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

    #[test]
    fn metrics_renders_json() {
        let m = Metrics::default();
        m.downloads.fetch_add(3, Ordering::Relaxed);
        let json = m.render_json(7);
        assert!(json.contains("\"downloads\":3") && json.contains("\"uptime_secs\":7"));
        assert!(json.contains("\"buffered_bytes\":0"));
    }
}
