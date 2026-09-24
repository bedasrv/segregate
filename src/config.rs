use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "segregate",
    about = "Segmented multi-connection HTTP forward proxy"
)]
pub struct Config {
    /// Listen address, e.g. 127.0.0.1:8080
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    /// Concurrent origin connections per download (striping workers)
    #[arg(long, alias = "segments", default_value_t = 8)]
    pub workers: usize,

    /// Minimum bytes for striping; smaller files use one connection
    #[arg(long, default_value_t = 1024 * 1024)]
    pub min_segment: u64,

    /// Per-request / per-chunk origin timeout, seconds
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,

    /// Time to first byte for origin exchanges (dial, TLS, headers).
    /// Chunk streaming keeps using --timeout-secs.
    #[arg(long, default_value_t = 10)]
    pub connect_timeout_secs: u64,

    /// Consecutive origin failures per slice before truncating so the
    /// client can resume with Range (instead of hanging forever)
    #[arg(long, alias = "max-part-retries", default_value_t = 30)]
    pub max_slice_retries: u32,

    /// Slice granularity for striped multi-connection downloads, bytes.
    /// Larger slices mean fewer, bigger requests; smaller slices stream
    /// steadier and bound memory tighter. Keep well above a TCP frame.
    #[arg(long, default_value_t = 1024 * 1024)]
    pub slice_bytes: u64,

    /// Bounded channel depth for the downstream body
    #[arg(long, default_value_t = 16)]
    pub body_buffer: usize,

    /// Disable hedged duplicate requests for stalled segments
    #[arg(long, default_value_t = false)]
    pub no_hedge: bool,

    /// Disable TLS MITM for CONNECT; plain TCP tunnel instead
    #[arg(long, default_value_t = false)]
    pub tunnel_only: bool,

    /// Write the generated MITM CA certificate (PEM) here so clients can
    /// trust it instead of disabling certificate verification
    #[arg(long)]
    pub ca_out: Option<PathBuf>,

    /// Maximum concurrent downstream TCP connections, including HTTP
    /// keep-alive connections and long-lived CONNECT tunnels
    #[arg(long, default_value_t = 1024)]
    pub max_connections: usize,

    /// Maximum concurrent CONNECT tunnels/MITM sessions
    #[arg(long, default_value_t = 64)]
    pub max_tunnels: usize,

    /// Concurrent downstream downloads; excess gets 503 + Retry-After
    /// before any origin work
    #[arg(long, default_value_t = 16)]
    pub max_downloads: usize,

    /// Concurrent origin connections total (all downloads + probe/hedge)
    #[arg(long, default_value_t = 64)]
    pub max_origin_connections: usize,

    /// Weighted origin egress routes, e.g. `eth0=4,wg0=1`.
    /// Empty preserves the default system route.
    #[arg(long, default_value = "")]
    pub egress_routes: String,

    /// Per-egress active connection quota; 0 uses max-origin-connections.
    #[arg(long, default_value_t = 0)]
    pub egress_max_connections: usize,

    /// Consecutive transport failures before an egress enters cooldown.
    #[arg(long, default_value_t = 2)]
    pub egress_failure_threshold: u32,

    /// Cooldown before an unhealthy egress becomes eligible again.
    #[arg(long, default_value_t = 30)]
    pub egress_cooldown_secs: u64,

    /// Transport failures allowed per egress before cooldown.
    #[arg(long, default_value_t = 2)]
    pub egress_retry_budget: u32,

    /// Max seconds to receive downstream request headers before closing
    #[arg(long, default_value_t = 10)]
    pub header_timeout_secs: u64,

    /// Probe-result cache TTL, seconds (0 disables the cache)
    #[arg(long, default_value_t = 60)]
    pub probe_cache_ttl_secs: u64,

    /// Max cached probe entries (one arbitrary entry evicted when full)
    #[arg(long, default_value_t = 1024)]
    pub probe_cache_entries: usize,

    /// Extra CA bundle (PEM) trusted for *origin* TLS verification, in
    /// addition to system roots. For self-signed/corporate origins.
    /// (This is unrelated to --ca-out, which exports the MITM CA.)
    #[arg(long)]
    pub origin_ca_bundle: Option<PathBuf>,

    /// CONNECT destination ports allowed (tunnel or MITM); others get 403
    #[arg(long, default_value = "443,80")]
    pub allow_connect_ports: String,

    /// CONNECT ports eligible for TLS MITM (should be a subset of
    /// --allow-connect-ports). Other allowed ports get a plain TCP tunnel:
    /// the proxy cannot know whether they speak TLS or plaintext.
    #[arg(long, default_value = "443")]
    pub mitm_ports: String,

    /// Grace period on shutdown to let in-flight downloads finish, seconds
    #[arg(long, default_value_t = 30)]
    pub shutdown_grace_secs: u64,

    /// Max upstream request-body bytes for non-GET forwarding (0 disables).
    /// Declared overruns get 413 before origin contact; undeclared streams
    /// are cut at the cap.
    #[arg(long, default_value_t = 64 << 20)]
    pub max_upload_bytes: u64,
}

impl Config {
    /// Clamp operator knobs to ranges that cannot exhaust the machine.
    /// Surprising inputs are warned about, not silently honored.
    pub fn validated(mut self) -> Self {
        fn clamp<T>(v: &mut T, lo: T, hi: T, name: &str)
        where
            T: Ord + Copy + std::fmt::Display,
        {
            let orig = *v;
            *v = (*v).max(lo).min(hi);
            if *v != orig {
                tracing::warn!(%name, from = %orig, to = %*v, "clamped to sane range");
            }
        }
        const MAX_WORKER_RETENTION: u64 = 256 << 20;
        const DOWNSTREAM_QUEUE_RETENTION: u64 = 16 << 20;
        const MAX_TOTAL_DOWNSTREAM_RETENTION: u64 = 1 << 30;

        clamp(&mut self.workers, 1, 128, "workers");
        clamp(&mut self.min_segment, 1, 1 << 40, "min_segment");
        clamp(&mut self.timeout_secs, 1, 300, "timeout_secs");
        clamp(
            &mut self.connect_timeout_secs,
            1,
            300,
            "connect_timeout_secs",
        );
        clamp(&mut self.max_slice_retries, 1, 100_000, "max_slice_retries");

        // Every worker can hold an assembled slice plus a hedge even if
        // downstream stops reading, so cap that retention before the
        // aggregate download cap.
        let retention_slices = (self.workers as u64) * if self.no_hedge { 1 } else { 2 };
        let max_slice_bytes = (MAX_WORKER_RETENTION / retention_slices).max(1024);
        clamp(&mut self.slice_bytes, 1024, max_slice_bytes, "slice_bytes");
        clamp(&mut self.body_buffer, 1, 256, "body_buffer");
        clamp(&mut self.max_connections, 1, 4096, "max_connections");
        clamp(&mut self.max_tunnels, 1, 4096, "max_tunnels");

        let per_download_retention = retention_slices
            .saturating_mul(self.slice_bytes)
            .saturating_add(DOWNSTREAM_QUEUE_RETENTION);
        let memory_max_downloads =
            (MAX_TOTAL_DOWNSTREAM_RETENTION / per_download_retention).clamp(1, 100_000) as usize;
        clamp(
            &mut self.max_downloads,
            1,
            memory_max_downloads,
            "max_downloads",
        );
        clamp(
            &mut self.max_origin_connections,
            1,
            4096,
            "max_origin_connections",
        );
        if self.egress_max_connections > 0 {
            clamp(
                &mut self.egress_max_connections,
                1,
                4096,
                "egress_max_connections",
            );
        }
        clamp(
            &mut self.egress_failure_threshold,
            1,
            1000,
            "egress_failure_threshold",
        );
        clamp(
            &mut self.egress_cooldown_secs,
            1,
            3600,
            "egress_cooldown_secs",
        );
        clamp(
            &mut self.egress_retry_budget,
            1,
            1000,
            "egress_retry_budget",
        );
        clamp(&mut self.header_timeout_secs, 0, 300, "header_timeout_secs");
        clamp(
            &mut self.probe_cache_ttl_secs,
            0,
            86_400,
            "probe_cache_ttl_secs",
        );
        clamp(
            &mut self.probe_cache_entries,
            1,
            16_384,
            "probe_cache_entries",
        );
        clamp(
            &mut self.shutdown_grace_secs,
            0,
            3600,
            "shutdown_grace_secs",
        );
        clamp(&mut self.max_upload_bytes, 0, 1 << 40, "max_upload_bytes");
        if self.max_origin_connections < self.max_downloads.saturating_mul(self.workers) {
            tracing::warn!(
                max_origin = self.max_origin_connections,
                worst_case = self.max_downloads.saturating_mul(self.workers),
                "origin cap below worst-case fan-out; segments will queue (still correct)"
            );
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn preserves_safe_backward_compatible_defaults() {
        let cfg = Config::parse_from(["segregate"]).validated();
        assert_eq!(cfg.max_connections, 1024);
        assert_eq!(cfg.max_tunnels, 64);
        assert_eq!(cfg.max_downloads, 16);
        assert_eq!(cfg.max_origin_connections, 64);
        assert_eq!(cfg.workers, 8);
        assert_eq!(cfg.slice_bytes, 1024 * 1024);
    }

    #[test]
    fn clamps_connection_and_retention_budgets() {
        let mut cfg = Config::parse_from(["segregate"]);
        cfg.workers = 128;
        cfg.slice_bytes = 1 << 30;
        cfg.max_connections = 100_000;
        cfg.max_downloads = 100_000;
        cfg.max_origin_connections = 100_000;
        cfg.body_buffer = 4096;
        cfg.probe_cache_entries = 100_000;
        let cfg = cfg.validated();

        assert_eq!(cfg.max_connections, 4096);
        assert_eq!(cfg.max_origin_connections, 4096);
        assert_eq!(cfg.body_buffer, 256);
        assert_eq!(cfg.probe_cache_entries, 16_384);
        // 128 workers plus hedges at 1 MiB retain 256 MiB; adding the
        // 16 MiB downstream queue still permits three in a 1 GiB budget.
        assert_eq!(cfg.slice_bytes, 1024 * 1024);
        assert_eq!(cfg.max_downloads, 3);
    }

    #[test]
    fn clamps_absurd_knobs() {
        let cfg = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            workers: 1_000_000,
            min_segment: 0,
            timeout_secs: 0,
            connect_timeout_secs: 0,
            max_slice_retries: 0,
            slice_bytes: 1,
            body_buffer: 0,
            no_hedge: false,
            tunnel_only: false,
            ca_out: None,
            max_connections: 0,
            max_tunnels: 0,
            max_downloads: 0,
            max_origin_connections: 0,
            egress_routes: String::new(),
            egress_max_connections: 0,
            egress_failure_threshold: 0,
            egress_cooldown_secs: 0,
            egress_retry_budget: 0,
            header_timeout_secs: 9999,
            probe_cache_ttl_secs: 0,
            probe_cache_entries: 0,
            origin_ca_bundle: None,
            allow_connect_ports: "443".to_owned(),
            mitm_ports: "443".to_owned(),
            shutdown_grace_secs: 0,
            max_upload_bytes: 0,
        }
        .validated();
        assert_eq!(cfg.workers, 128);
        assert_eq!(cfg.connect_timeout_secs, 1);
        assert_eq!(cfg.max_upload_bytes, 0);
        assert_eq!(cfg.min_segment, 1);
        assert_eq!(cfg.timeout_secs, 1);
        assert_eq!(cfg.body_buffer, 1);
        assert_eq!(cfg.max_connections, 1);
        assert_eq!(cfg.max_tunnels, 1);
        assert_eq!(cfg.max_downloads, 1);
        assert_eq!(cfg.egress_max_connections, 0);
        assert_eq!(cfg.egress_failure_threshold, 1);
        assert_eq!(cfg.egress_cooldown_secs, 1);
        assert_eq!(cfg.egress_retry_budget, 1);
        assert_eq!(cfg.slice_bytes, 1024);
    }
}
