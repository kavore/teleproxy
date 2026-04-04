# Changelog

## 4.7.0

Per-secret quotas, unique-IP limits, and expiration ([#26](https://github.com/teleproxy/teleproxy/issues/26)).

- **Data quota** — cap total bytes transferred per secret; active connections are closed and new ones rejected when exhausted. Configurable in bytes or human-readable sizes (`quota = "10G"`)
- **Unique IP limit** — cap how many distinct client IPs can use a secret simultaneously (`max_ips = 5`). Additional connections from an already-connected IP are always allowed
- **Secret expiration** — auto-disable a secret after a timestamp (`expires = 2025-12-31T23:59:59Z`). Existing connections continue; only new ones are rejected
- Per-reason rejection counters in Prometheus and plain-text stats (`rejected_quota`, `rejected_ips`, `rejected_expired`)
- Docker env vars: `SECRET_QUOTA_N`, `SECRET_MAX_IPS_N`, `SECRET_EXPIRES_N`
- SOCKS5 upstream proxy support ([#22](https://github.com/teleproxy/teleproxy/issues/22))
- One-click cloud deploy page
- Documentation: install/upgrade instructions, SOCKS5 docs, Observatory link

## 4.6.0

DPI resistance and operational improvements.

- **ServerHello size variation** widened from ±1 to ±32 bytes, mimicking the natural variation in certificate chain and session ticket sizes seen from real TLS servers
- **ServerHello fragmentation**: ServerHello and CCS+AppData are now sent as separate TCP segments, defeating DPI that pattern-matches the full handshake response in a single packet
- Docker healthcheck respects custom `STATS_PORT` — previously hardcoded to 8888, now uses `${STATS_PORT:-8888}` ([#38](https://github.com/teleproxy/teleproxy/issues/38))
- `install.sh` supports multiple secrets via comma-separated `SECRET` or numbered `SECRET_N` variables
- `/link` endpoint serves connection links as HTML pages with scannable QR codes

New documentation: [DPI Resistance](features/dpi-resistance.md) — covers server-side mitigations, recommended setup, and client-side bypass tools.

!!! note "Client-side detection"
    The primary detection vector for MTProxy fake-TLS in Russia is the **Telegram client's TLS fingerprint**, which cannot be fixed server-side. Telegram Desktop [fixed several fingerprint artifacts](https://github.com/telegramdesktop/tdesktop/pull/30513); keep clients updated. For affected networks, client-side bypass tools like [zapret](https://github.com/bol-van/zapret) and [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) can help.

## 4.5.0

QR codes for connection links.

- `teleproxy link` subcommand prints a proxy URL and renders a scannable QR code in the terminal using UTF-8 half-block characters
- Docker `start.sh` and `install.sh` now display QR codes automatically at startup — point a phone camera at the screen to connect
- Vendored nayuki/QR-Code-generator (MIT) for zero-dependency QR rendering on any platform
- E2E tests decode the rendered QR output with pyzbar and verify it matches the expected URL
- Documentation: new "Connection Links" page (en + ru)

## 4.4.0

- `teleproxy check` diagnostic subcommand — validates configuration and tests connectivity before accepting clients. Checks DC reachability, NTP clock drift, fake-TLS domain probe, and SNI/DNS mismatch. Exit 0/1/2 for pass/fail/bad-args.

## 4.3.0

Direct mode connection resilience.

- IPv6 auto-detection: probe at startup, enable without `-6` if reachable
- Multiple addresses per DC with synchronous failover on connect failure
- Connection retry with exponential backoff (200ms–800ms, 3 attempts)
- `--dc-override dc_id:host:port` to add or replace DC addresses (repeatable). Docker: `DC_OVERRIDE=2:1.2.3.4:443,2:5.6.7.8:443`
- New stat: `direct_dc_retries` / `teleproxy_direct_dc_retries_total`

## 4.2.1

- Fix aarch64 build: remove unused x86-only `sys/io.h` include
- Add native ARM64 glibc build to CI (catches platform-specific issues masked by Alpine/musl)

## 4.2.0

- `--stats-allow-net CIDR` flag to extend stats endpoint access beyond RFC1918 ranges (repeatable). Docker: `STATS_ALLOW_NET=100.64.0.0/10,fd00::/8`

## 4.1.0

MTProto transport protocol compliance improvements.

- Detect and log transport error codes (-404, -429, etc.) from DCs in direct mode
- Detect transport error codes in medium mode client parse path
- Track quick ACK packets with `teleproxy_quickack_packets_total` counter
- Track transport errors with `teleproxy_transport_errors_total` counter

## 4.0.0

Rebrand to Teleproxy. Binary renamed from `mtproto-proxy` to `teleproxy`.

- Binary name: `teleproxy` (was `mtproto-proxy`)
- Prometheus metrics prefix: `teleproxy_` (was `mtproxy_`)
- Docker user/paths: `/opt/teleproxy/` (was `/opt/mtproxy/`)
- Environment variables: `TELEPROXY_*` (old `MTPROXY_*` still accepted with deprecation warning)
- Docker image includes backward-compat symlink `mtproto-proxy -> teleproxy`
- CLI flags and behavior unchanged
