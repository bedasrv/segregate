mod cert;
mod config;
mod proxy;
mod segment;
mod state;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::Semaphore;

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        // Signal setup happens once at startup; a failure here degrades to
        // SIGINT-only shutdown rather than crashing before serving.
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = term.recv() => {},
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler unavailable; waiting on SIGINT only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = config::Config::parse().validated();
    let listen = cfg.listen;

    let allowed_ports =
        state::parse_connect_ports(&cfg.allow_connect_ports).map_err(std::io::Error::other)?;
    let mitm_ports = state::parse_connect_ports(&cfg.mitm_ports).map_err(std::io::Error::other)?;

    let client = segment::build_client(cfg.origin_ca_bundle.as_deref(), cfg.max_origin_connections)
        .map_err(std::io::Error::other)?;

    // Persistent CA for the process lifetime (immutable → plain Arc sharing).
    // Skipped only when MITM is disabled; CONNECT then falls back to tunnels.
    let ca: Option<Arc<cert::CaAuthority>> = if cfg.tunnel_only {
        None
    } else {
        let ca =
            cert::CaAuthority::generate().map_err(|e| std::io::Error::other(format!("CA: {e}")))?;
        if let Some(path) = &cfg.ca_out {
            std::fs::write(path, ca.ca_pem())?;
            tracing::info!(path = %path.display(), "wrote MITM CA certificate (PEM)");
        }
        Some(Arc::new(ca))
    };

    let shared = state::Shared {
        origin: state::Origin::new(client, cfg.max_origin_connections),
        cfg: Arc::new(cfg.clone()),
        ca,
        downloads: Arc::new(Semaphore::new(cfg.max_downloads.max(1))),
        allowed_ports: Arc::new(allowed_ports),
        mitm_ports: Arc::new(mitm_ports),
        metrics: Arc::new(state::Metrics::default()),
        probe_cache: Arc::new(state::ProbeCache::new(
            cfg.probe_cache_ttl_secs,
            cfg.probe_cache_entries,
        )),
        started: std::time::Instant::now(),
    };

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, workers = cfg.workers, "segmented proxy listening");
    if shared.ca.is_some() {
        tracing::info!("use: curl -k --proxy http://{listen} https://example.com/file");
        tracing::info!(
            "  or trust --ca-out PEM via REQUESTS_CA_BUNDLE and drop --no-check-certificate"
        );
    }
    tracing::info!(
        "or without MITM: curl \"http://{listen}/__fetch?url=<percent-encoded-https-url>\""
    );

    let header_timeout = Duration::from_secs(cfg.header_timeout_secs);
    let mut conns = tokio::task::JoinSet::new();
    // Stop accepting on signal; in-flight downloads drain within the grace
    // period instead of being cut mid-byte.
    let mut shutdown = std::pin::pin!(shutdown_signal());
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!("shutdown signal; draining in-flight downloads");
                break;
            }
            accepted = listener.accept() => {
                // An accept failure must not kill the process and abandon
                // in-flight downloads; log and keep serving.
                let (stream, peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed; continuing");
                        continue;
                    }
                };
                let shared = shared.clone();
                conns.spawn(async move {
                    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
                    let io = TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |req| {
                        let shared = shared.clone();
                        proxy::handle(req, shared)
                    });
                    // Upgrades (CONNECT) require the `with_upgrades` path;
                    // plain `serve_connection` rejects `hyper::upgrade::on`.
                    // The header timer bounds slow-loris clients (hyper
                    // panics if a read timeout is set without a timer).
                    let mut builder =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    builder.http1().timer(TokioTimer::new());
                    if cfg.header_timeout_secs > 0 {
                        builder.http1().header_read_timeout(header_timeout);
                    }
                    if let Err(e) = builder
                        .serve_connection_with_upgrades(io, svc)
                        .await
                    {
                        tracing::debug!(%peer, error = %e, "downstream closed");
                    }
                });
            }
        }
    }
    let grace = Duration::from_secs(cfg.shutdown_grace_secs.max(1));
    // Refuse new SYNs during the drain instead of letting them pile in
    // the backlog behind a process that is going away.
    drop(listener);
    drain_conns(&mut conns, grace).await;
    Ok(())
}

/// Drain in-flight connection tasks, bounded by `grace`. Slow tasks are
/// abandoned (and killed with the runtime); panics are logged, never silent.
async fn drain_conns(conns: &mut tokio::task::JoinSet<()>, grace: Duration) {
    let _ = tokio::time::timeout(grace, async {
        while let Some(res) = conns.join_next().await {
            // A panicking connection task must not vanish silently; the
            // download it served is already truncated by the client seeing
            // the connection die, but operators need the cause.
            if let Err(e) = res {
                tracing::warn!(error = %e, "connection task panicked");
            }
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn drain_finishes_fast_tasks() {
        let mut set = tokio::task::JoinSet::new();
        set.spawn(async {});
        drain_conns(&mut set, Duration::from_secs(5)).await;
        assert!(set.is_empty());
    }

    #[tokio::test]
    async fn drain_is_bounded_by_grace() {
        let mut set = tokio::task::JoinSet::new();
        set.spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        let t = Instant::now();
        drain_conns(&mut set, Duration::from_millis(50)).await;
        assert!(t.elapsed() < Duration::from_secs(5));
        set.abort_all();
    }
}
