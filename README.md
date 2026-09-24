# segregate

A forward HTTP proxy that downloads each file from the origin over N
concurrent `Range` connections and streams the reassembled bytes to
the client over one clean downstream connection. Works with any HTTP
client (curl, wget, and similar); no client code changes needed.

## Run

```bash
cargo run --release -- --listen 127.0.0.1:8080 --workers 8 --ca-out mitm-ca.pem
```

## Use

```bash
# HTTPS via MITM. Trust the CA for this curl (the CA is per proxy run) ...
curl --cacert ./mitm-ca.pem --proxy http://127.0.0.1:8080 https://example.com/file
# ... or skip verification (per-host leaf certs, no cache/files)
curl -k --proxy http://127.0.0.1:8080 https://example.com/file

# Plain HTTP, or HTTPS without cert flags (no CONNECT involved)
curl http://127.0.0.1:8080/__fetch?url=https%3A%2F%2Fexample.com%2Ffile

# Disable MITM, plain TCP tunnel for CONNECT instead (no acceleration)
cargo run --release -- --tunnel-only
```

## Flags

- `--workers N` (default 8, alias `--segments`): concurrent origin connections per download.
- `--min-segment BYTES` (default 1048576): files smaller than this use a
  single connection instead of striping.
- `--slice-bytes BYTES` (default 1048576): granularity of striped
  multi-connection downloads. Smaller slices stream steadier and bound
  memory tighter at the cost of more origin requests.
- `--timeout-secs S` (default 10): idle gap allowed between body chunks,
  downstream or origin. Retries resume from the current offset, so transient
  stalls stay well under the client's own socket timeout; a downstream that
  stops reading is truncated instead of pinning slots forever.
- `--connect-timeout-secs S` (default 10): time to first byte for origin
  exchanges (dial, TLS, headers, CONNECT upgrade). Split from chunk idle
  so slow-but-moving links aren't false-retried.
- `--max-slice-retries N` (default 30, alias `--max-part-retries`):
  consecutive origin failures per slice before truncating so the client
  resumes with Range instead of hanging forever on a dead origin.
- `--body-buffer N` (default 16): maximum downstream frame depth; the
  effective depth is also capped by a 16 MiB byte budget.
- `--no-hedge`: disable hedged duplicate requests for stalled segments.
- `--tunnel-only`: skip MITM, relay CONNECT as TCP.
- `--ca-out PATH`: write the run's MITM CA certificate (PEM) for clients
  to trust. The CA is ephemeral and changes on every proxy start.
- `--max-connections N` (default 1024): maximum downstream TCP connections,
  including keep-alive connections.
- `--max-tunnels N` (default 64): maximum concurrent CONNECT tunnels/MITM
  sessions.
- `--max-downloads N` (default 16): concurrent downstream response bodies;
  excess gets `503` + `Retry-After` instead of queueing unboundedly.
- `--max-origin-connections N` (default 64): total concurrent origin
  exchanges and raw CONNECT sockets, including probe/segment/hedge/passthrough.
- `--egress-routes "eth0=4,wg0=1"`: opt-in weighted origin egress pool.
  Each name is a network interface passed to `HttpConnector`; `default` uses
  the system-selected route. The pool is disabled when this is empty.
- `--egress-max-connections N` (default 0): active-stream quota per egress;
  0 gives each route the same quota as `--max-origin-connections`. The global
  origin cap still applies across all routes.
- `--egress-failure-threshold N` (default 2): consecutive transport failures
  before an egress is marked unhealthy.
- `--egress-cooldown-secs S` (default 30): passive health recovery interval;
  after it, the next exchange verifies the route again.
- `--egress-retry-budget N` (default 2): consecutive transport failures
  allowed per egress before it enters cooldown; a successful exchange resets
  the budget. Segment retries are still bounded by `--max-slice-retries`.
- `--header-timeout-secs S` (default 10, 0 disables): max time to receive
  downstream request headers before closing (slow-loris bound).
- `--probe-cache-ttl-secs S` (default 60, 0 disables), `--probe-cache-entries N`
  (default 1024): cache only safe probe metadata, keyed by a SHA-256
  fingerprint of URI + all auth/cookie/user-agent values, so retries and
  resumes skip the probe RTT; invalidated on 416.
- `--origin-ca-bundle PATH`: extra CA bundle (PEM) trusted for *origin*
  TLS verification, for self-signed/corporate origins. Unrelated to
  `--ca-out`, which exports the MITM CA.
- `--allow-connect-ports "443,80"`: CONNECT destinations outside this set
  get `403` without dialing. `TRACE` always gets `405`. Userinfo in the
  authority (`user@host`) is refused with `400`.
- `--mitm-ports "443"`: CONNECT ports eligible for TLS MITM. Other allowed
  ports get a plain TCP tunnel, since the proxy cannot know whether they
  speak TLS or plaintext.
- `--shutdown-grace-secs S` (default 30): drain in-flight downloads on
  SIGINT/SIGTERM before exiting.
- `--max-upload-bytes N` (default 64 MiB, 0 disables): cap on upstream
  request bodies for non-GET forwarding. Declared overruns get 413 before
  origin contact; undeclared streams are cut at the cap.

Numeric knobs are clamped to sane ranges at startup (with warnings), so
absurd values fail safe instead of exhausting tasks, channels, or memory.

## Operator endpoint

`GET /__stats` (origin-form, proxy itself only) returns JSON counters:
`downloads`, `bytes_out`, `buffered_bytes` (completed-but-unflushed slice
bytes currently held), `origin_retries`, `hedges`, `truncations`,
`cache_hits`, `refused` (CONNECT-denied + 503-overload),
`connect_errors`, `uptime_secs`, and an `egress` array with each configured
route's weight, health, current availability, request count, transport errors,
and retry count.
Interface names are operator labels; `/__stats` does not expose client data.

## Status codes (and what clients should do)

- `200` / `206`: full / partial body, byte-exact for the requested range.
- `304`: returned only when the origin evaluates the client's complete
  conditional request; probe metadata is never used to synthesize freshness.
- `400`: malformed proxy request (bad `/__fetch` URL, origin-form
  non-proxy request that isn't `/__stats`).
- `403`: CONNECT port outside `--allow-connect-ports`, answered before
  any dial.
- `405`: `TRACE`, always refused without touching any origin.
- `413`: upload over `--max-upload-bytes`.
- `416`: downstream range starts past EOF (mirrors the origin when the
  cached length went stale; the entry is invalidated so the retry
  re-probes).
- `502`: origin unreachable / TLS failed / probe failed and no cached
  entry. Retryable.
- `503` + `Retry-After: 5`: at `--max-downloads` or `--max-tunnels`
  capacity. Back off and retry; never a hung socket.
- Truncated `200` (short body vs `Content-Length`): origin died mid-stream
  after headers. Resume with `Range` (e.g. `curl -C -`, `wget -c`), which
  the proxy serves from cache without re-probing.

## Binding and trust model

This is an intercepting forward proxy: anyone who can reach the listener
and trusts (or ignores) the MITM CA gets their traffic decrypted. The
default bind is loopback — keep it that way. Binding `0.0.0.0` exposes an
open proxy that MITMs whoever points at it; only do that on a trusted
network you control, and prefer `--ca-out` plus client trust over skipping
certificate verification.

## Client pairing

Keep the proxy's chunk timeout comfortably below the client's socket
timeout so stalls recover proxy-side with resume-from-offset instead of
full restarts:

```bash
curl --proxy http://127.0.0.1:8080 --max-time 120 https://example.com/file
wget -e use_proxy=yes -e http_proxy=127.0.0.1:8080 --timeout=30 --tries=10 http://example.com/file
```

## How it works

1. `Range: bytes=0-0` probe learns length + range support (retried 3x,
   result cached and shared across concurrent downloads of the same URL).
   Conditional requests (`If-Match`, `If-None-Match`, `If-Range`, and date
   validators) are sent to the origin as a complete single-request
   exchange rather than answered from cached metadata. Probe bodies are
   never buffered unboundedly: 206 probe bodies are drained bounded; full
   200 bodies are dropped unread. Session cookies are never placed in the
   shared probe snapshot.
2. A first real range is checked before fan-out. If the origin ignores
   Range, the proxy switches to one linear full-body response instead of
   downloading and discarding a growing prefix for every slice. Otherwise
   range-capable files with a strong validator are striped into
   `--slice-bytes` slices; N workers pull indices past a bounded completion
   window (no coordinator lock), each with timeout + resume-from-offset
   retry. `Content-Range` and validators must match every slice; a mismatch
   invalidates the metadata and safely truncates for client resume. Files
   below `--min-segment`, or without a safe validator, use one connection.
3. A slice that goes idle mid-body races one bounded duplicate request
   (headers + first chunk only) against the stalled connection and keeps
   whichever delivers first.
4. Origin chunks are truncated to the requested window so a buggy origin
   can never corrupt downstream `Content-Length` framing.
5. A coordinator flushes completed slices strictly in order into the
   downstream body. Slices are never silently enlarged: ranges that would
   exceed one million descriptors fall back to one full response. Retention
   is bounded by `(window + body-depth) × slice_bytes`; startup validation
   keeps the aggregate downstream budget near 1 GiB. `buffered_bytes` in
   `/__stats` shows completed-but-unflushed bytes, while active worker
   buffers are bounded separately by the validated configuration.
6. Downstream always sees valid HTTP framing: transport errors become
   502, stalls truncate (resumable via `Range`, incl. suffix ranges
   `bytes=-N`), never a dropped socket. Single-connection passthrough
   has the same idle timeout.
7. `CONNECT` defaults to MITM (per-connection leaf signed by a run-local
   CA, verified-TLS re-originate, correct IPv6/scheme handling, port
   preserved) so HTTPS gets the same fan-out; `--tunnel-only` relays
   bytes opaquely instead. Upgrade, TLS handshake, and header reads all
   have timeouts.
8. Sharing is lock-free except the probe cache (short `std` lock, never
   held across `.await`): `Clone` handles the libraries already refcount
   internally (`hyper` client, `Bytes` chunks), one immutable `Arc` for
   the CA, and semaphores for connection, tunnel, download, and origin
   caps.
9. Origin connections are HTTP/1.1 only: segmentation needs one TCP
   connection per segment (HTTP/2 would multiplex everything onto one),
   and plain HTTP/1.1 is accepted by the pickiest WAFs. An optional weighted
   egress pool gives each configured interface its own connector and active
   quota. Transport failures consume a bounded per-route budget; unhealthy
   routes leave the selection set until cooldown recovery, allowing bounded
   retries to fail over without retrying HTTP status errors. On Linux,
   interface binding uses `SO_BINDTODEVICE` and may require elevated
   privileges.

## Tests

```bash
cargo clippy --all-targets -- -D warnings
cargo test   # unit + in-repo async integration: CONNECT/MITM/tunnel loopback,
             # flaky/slow/range-ignoring origins, caps (503/413/403/405/304),
             # probe stampede sharing, and a buffer-flatness scaling test
```
