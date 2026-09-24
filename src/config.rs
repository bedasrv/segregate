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
    /// trust it instead of using --no-check-certificate
    #[arg(long)]
    pub ca_out: Option<PathBuf>,

    /// Concurrent downstream downloads; excess gets 503 + Retry-After
    #[arg(long, default_value_t = 16)]
    pub max_downloads: usize,

    /// Concurrent origin connections total (all downloads + probe/hedge)
    #[arg(long, default_value_t = 64)]
    pub max_origin_connections: usize,

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
        clamp(&mut self.slice_bytes, 1024, 1 << 30, "slice_bytes");
        clamp(&mut self.body_buffer, 1, 4096, "body_buffer");
        clamp(&mut self.max_downloads, 1, 100_000, "max_downloads");
        clamp(
            &mut self.max_origin_connections,
            1,
            100_000,
            "max_origin_connections",
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
            100_000,
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
        // The completion window never drops below one slice per worker, so
        // giant slices imply giant retention floors no matter the other caps.
        if (self.workers as u64).saturating_mul(self.slice_bytes) > 256 << 20 {
            tracing::warn!(
                workers = self.workers,
                slice_bytes = self.slice_bytes,
                "striped retention floor above 256 MiB per download; lower --workers or --slice-bytes to bound RAM"
            );
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            max_downloads: 0,
            max_origin_connections: 0,
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
        assert_eq!(cfg.max_downloads, 1);
        assert_eq!(cfg.slice_bytes, 1024);
    }
}
