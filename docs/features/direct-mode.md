# Direct-to-DC Mode

By default, Teleproxy routes through Telegram's middle-end (ME) relay servers. Direct mode bypasses them:

```
Default:  Client -> Teleproxy -> ME relay -> Telegram DC
Direct:   Client -> Teleproxy -> Telegram DC
```

Enable with `--direct`:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> --http-stats --direct
```

In direct mode:

- No `proxy-multi.conf` or `proxy-secret` files needed
- No config file argument required
- Connects directly to well-known Telegram DC addresses
- **Incompatible with `-P` (proxy tag)** — promoted channels require ME relays

Docker:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```
