# Secrets & Limits

## Generating Secrets

Generate a random 16-byte secret:

```bash
teleproxy generate-secret
```

For fake-TLS mode, pass the domain to get the full `ee`-prefixed secret ready for client links:

```bash
teleproxy generate-secret www.google.com
# stdout:  ee<secret><domain-hex>  (use in tg://proxy links)
# stderr:  Secret for -S: <secret>  (use with -S flag)
```

## Multiple Secrets

Up to 16 secrets, each with an optional label:

```bash
./teleproxy ... -S cafe...ab:family -S dead...ef:friends
```

## Secret Labels

Labels identify which secret a connection uses.

CLI:

```bash
./teleproxy ... -S cafe...ab:family -S dead...ef:friends
```

Installer:

```bash
curl -sSL .../install.sh | \
  SECRET_1=cafe...ab SECRET_LABEL_1=family \
  SECRET_2=dead...ef SECRET_LABEL_2=friends \
  sh
```

Docker:

```bash
# Inline labels
SECRET=cafe...ab:family,dead...ef:friends

# Or numbered
SECRET_1=cafe...ab
SECRET_LABEL_1=family
SECRET_2=dead...ef
SECRET_LABEL_2=friends
```

Labels appear in:

- **Logs:** `TLS handshake matched secret [family] from 1.2.3.4:12345`
- **Prometheus:** `teleproxy_secret_connections{secret="family"} 3`
- **Stats:** `secret_family_connections	3`

Unlabeled secrets are auto-labeled `secret_0`, `secret_1`, etc.

Label rules: max 32 chars, alphanumeric plus `_` and `-`.

## Per-Secret Connection Limits

Prevent a leaked secret from consuming all resources:

```bash
# CLI: append :LIMIT after the label
./teleproxy ... -S cafe...ab:family:1000 -S dead...ef:public:200

# Without a label
./teleproxy ... -S cafe...ab::500
```

Installer:

```bash
curl -sSL .../install.sh | \
  SECRET_1=cafe...ab SECRET_LABEL_1=family SECRET_LIMIT_1=1000 \
  SECRET_2=dead...ef SECRET_LABEL_2=public SECRET_LIMIT_2=200 \
  sh
```

Docker:

```bash
# Environment variables
SECRET_LIMIT_1=1000
SECRET_LIMIT_2=200

# Inline
SECRET=cafe...ab:family:1000,dead...ef:public:200
```

When the limit is reached:

- **Fake-TLS (EE):** rejected during TLS handshake — client sees the backend website
- **Obfuscated2 (DD):** connection silently dropped

Multi-worker note: with `-M N` workers, each enforces `limit / N` independently.

Metrics:

- **Stats:** `secret_family_limit 1000`, `secret_family_rejected 42`
- **Prometheus:** `teleproxy_secret_connection_limit{secret="family"} 1000`, `teleproxy_secret_connections_rejected_total{secret="family"} 42`

## Per-Secret Quotas

Cap total bytes transferred (received + sent) per secret. Once exhausted, active connections are closed and new connections are rejected.

TOML config:

```toml
[[secret]]
key = "cafe...ab"
label = "guest"
quota = "10G"    # accepts: bytes (int), or "500M", "10G", "1T"
```

Docker:

```bash
SECRET_QUOTA_1=10737418240   # 10 GB in bytes
```

Quota is cumulative since startup — it does not reset on SIGHUP config reload. Restart the proxy to reset usage.

Metrics:

- **Stats:** `secret_guest_quota 10737418240`, `secret_guest_bytes_total 5368709120`, `secret_guest_rejected_quota 3`
- **Prometheus:** `teleproxy_secret_quota_bytes{secret="guest"} 10737418240`, `teleproxy_secret_bytes_total{secret="guest"} 5368709120`

## Per-Secret Unique IP Limits

Cap how many distinct client IPs can use a secret simultaneously. Additional connections from an already-connected IP are allowed.

TOML config:

```toml
[[secret]]
key = "cafe...ab"
label = "guest"
max_ips = 5
```

Docker:

```bash
SECRET_MAX_IPS_1=5
```

Metrics:

- **Stats:** `secret_guest_max_ips 5`, `secret_guest_unique_ips 3`, `secret_guest_rejected_ips 0`
- **Prometheus:** `teleproxy_secret_max_ips{secret="guest"} 5`, `teleproxy_secret_unique_ips{secret="guest"} 3`

## Secret Expiration

Auto-disable a secret after a timestamp. New connections are rejected; existing connections continue until they close naturally.

TOML config:

```toml
[[secret]]
key = "cafe...ab"
label = "temp"
expires = 2025-06-30T23:59:59Z    # TOML datetime (UTC)
# or: expires = 1751327999         # Unix timestamp
```

Docker:

```bash
SECRET_EXPIRES_1=2025-06-30T23:59:59Z
# or: SECRET_EXPIRES_1=1751327999
```

Metrics:

- **Stats:** `secret_temp_expires 1751327999`, `secret_temp_rejected_expired 12`
- **Prometheus:** `teleproxy_secret_expires_timestamp{secret="temp"} 1751327999`

## TOML Config Example

All per-secret features combined:

```toml
[[secret]]
key = "cafe01234567890abcafe01234567890a"
label = "family"
limit = 100
quota = "50G"
max_ips = 10
expires = 2026-12-31T23:59:59Z

[[secret]]
key = "dead01234567890abcead01234567890a"
label = "guest"
limit = 50
quota = "5G"
max_ips = 3
expires = 2025-06-30T00:00:00Z
```
