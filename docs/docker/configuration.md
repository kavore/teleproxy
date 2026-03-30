# Docker Configuration

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET` | auto-generated | Proxy secret(s) — 32 hex chars each. Single, comma-separated, or with labels |
| `SECRET_1`...`SECRET_16` | — | Numbered secrets (combined with `SECRET` if both set) |
| `SECRET_LABEL_1`...`SECRET_LABEL_16` | — | Labels for numbered secrets |
| `SECRET_LIMIT_1`...`SECRET_LIMIT_16` | — | Per-secret connection limits |
| `PORT` | 443 | Client connection port |
| `STATS_PORT` | 8888 | Statistics endpoint port |
| `WORKERS` | 1 | Worker processes |
| `PROXY_TAG` | — | Tag from @MTProxybot (channel promotion) |
| `DIRECT_MODE` | false | Connect directly to Telegram DCs |
| `RANDOM_PADDING` | false | Enable random padding only (DD mode) |
| `EXTERNAL_IP` | auto-detected | Public IP for NAT environments |
| `EE_DOMAIN` | — | Domain for Fake-TLS. Accepts `host:port` for custom TLS backends |
| `IP_BLOCKLIST` | — | Path to CIDR blocklist file |
| `IP_ALLOWLIST` | — | Path to CIDR allowlist file |

Maximum 16 secrets (binary limit).

## Docker Compose

Simple setup:

```yaml
services:
  teleproxy:
    image: ghcr.io/teleproxy/teleproxy:latest
    ports:
      - "443:443"
      - "8888:8888"
    restart: unless-stopped
```

With `.env` file:

```bash
SECRET=your_secret_here
PROXY_TAG=your_proxy_tag_here
```

## Volume Mounting

The container stores `proxy-multi.conf` in `/opt/teleproxy/data/`. Mount a volume to persist the configuration across restarts:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -v /path/to/host/data:/opt/teleproxy/data \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

`proxy-secret` is baked into the image at build time — no volume needed for it.

If `core.telegram.org` is unreachable, the container uses the cached config from the volume.

## Automatic Config Refresh

A cron job refreshes the Telegram DC configuration every 6 hours. It downloads the latest config, validates it, compares it with the existing one, and hot-reloads the proxy via `SIGHUP` if the config changed. No configuration needed.

## Health Check

The Docker image includes a built-in health check that monitors the stats endpoint:

```bash
docker ps  # Check the STATUS column for health
```

The health check runs every 30 seconds after a 60-second startup grace period.
