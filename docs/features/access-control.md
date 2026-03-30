# IP Access Control

Restrict client connections by IP using CIDR-based files:

```bash
./teleproxy ... --ip-blocklist blocklist.txt --ip-allowlist allowlist.txt
```

File format (one CIDR per line, `#` comments):

```
# Block known scanner ranges
185.220.101.0/24
2001:db8::/32
```

- Both IPv4 and IPv6 CIDR supported
- `--ip-allowlist`: whitelist mode — only matching IPs accepted
- `--ip-blocklist`: matching IPs rejected
- Files reloaded on `SIGHUP` — update without restart
- Rejected connections tracked: `teleproxy_ip_acl_rejected_total` Prometheus metric
