use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant};

use http::{HeaderMap, Uri};
use hyper::body::Incoming;
use hyper::{Request, Response};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::task::TaskTracker;

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
    pub connections: Arc<Semaphore>,
    pub tunnels: Arc<Semaphore>,
    pub upgrades: Arc<TaskTracker>,
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

    /// Acquire one active-origin permit for raw CONNECT tunnels.
    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, OriginError> {
        self.sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| OriginError::PoolClosed)
    }

    /// One origin exchange: acquires a pool permit (times out via the
    /// caller's `timeout`, counting as a transient failure) and issues the
    /// request. Hold the permit while streaming the body.
    pub async fn get(
        &self,
        req: Request<BoxBody>,
    ) -> Result<(Response<Incoming>, OwnedSemaphorePermit), OriginError> {
        let permit = self.acquire().await?;
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

    #[test]
    fn metrics_renders_json() {
        let m = Metrics::default();
        m.downloads.fetch_add(3, Ordering::Relaxed);
        let json = m.render_json(7);
        assert!(json.contains("\"downloads\":3") && json.contains("\"uptime_secs\":7"));
        assert!(json.contains("\"buffered_bytes\":0"));
    }
}
