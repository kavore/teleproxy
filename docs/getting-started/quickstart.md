# Quick Start

Get Teleproxy running in under 2 minutes.

## 1. Download the proxy secret

This key is used for encrypted communication with Telegram servers:

```bash
curl -fsSL https://core.telegram.org/getProxySecret -o proxy-secret
```

## 2. Download the DC configuration

This file maps Telegram datacenter addresses. Update it daily via cron.

```bash
curl -fsSL https://core.telegram.org/getProxyConfig -o proxy-multi.conf
```

## 3. Generate a client secret

Clients will use this secret to connect through your proxy:

```bash
head -c 16 /dev/urandom | xxd -ps
```

Save the output — you'll need it for the next step and for the connection link.

## 4. Run Teleproxy

```bash
./teleproxy \
  -u nobody \
  -p 8888 \
  -H 443 \
  -S <secret> \
  --http-stats \
  --aes-pwd proxy-secret proxy-multi.conf \
  -M 1
```

| Flag | Description |
|------|-------------|
| `-u nobody` | Drop root privileges after binding ports |
| `-H 443` | Client-facing port (what users connect to) |
| `-p 8888` | HTTP stats port — bind to localhost or a private network only |
| `-S <secret>` | Client secret. Repeat for multiple secrets: `-S <s1> -S <s2>` |
| `--http-stats` | Enable the built-in HTTP statistics page |
| `--aes-pwd proxy-secret` | Path to the proxy secret file |
| `proxy-multi.conf` | Path to the DC configuration file |
| `-M 1` | Number of worker processes |

## 5. Share the connection link

Give users a link they can tap to configure Telegram automatically:

```
tg://proxy?server=YOUR_SERVER_IP&port=443&secret=SECRET
```

Replace `YOUR_SERVER_IP` with your server's public IP and `SECRET` with the hex secret from step 3.

## 6. Register with Telegram

Message [@MTProxybot](https://t.me/MTProxybot) on Telegram to register your proxy and receive a proxy tag. Then add it to your launch command:

```bash
./teleproxy ... -P <proxy-tag>
```

The proxy tag enables sponsored channels (required by Telegram for listed proxies) and makes your proxy discoverable.

---

!!! tip
    For the simplest setup, use [Direct-to-DC mode](../features/direct-mode.md) — no config files needed.

## Or just use Docker

Skip all of the above with a single command:

```bash
docker run -d --name teleproxy \
  -p 443:443 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

The container auto-downloads config files, generates a random secret, and prints the `tg://` connection link to the logs. See [Docker Quick Start](../docker/index.md) for details.
