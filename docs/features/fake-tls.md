---
description: "Configure Teleproxy EE mode to wrap MTProto in genuine TLS 1.3 handshakes, making proxy traffic indistinguishable from regular HTTPS."
---

# Fake-TLS (EE Mode)

Teleproxy supports EE mode which makes proxy traffic look like standard TLS 1.3, making it harder to detect and block.

## How It Works

The client secret uses the format: `ee` + server_secret + domain_hex

Server setup — add domain configuration (must support TLS 1.3):

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> -D www.google.com --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

Generate the full client secret in one step:

```bash
teleproxy generate-secret www.google.com
# stdout:  eecafe...7777772e676f6f676c652e636f6d
# stderr:  Secret for -S:  cafe...
#          Domain:         www.google.com
```

Use the stdout value in `tg://proxy` links and the `Secret for -S` value with the `-S` flag.

## Custom TLS Backend (TCP Splitting)

Instead of mimicking a public website, run your own web server behind Teleproxy with a real TLS certificate. Non-proxy visitors see a fully functioning HTTPS website — the server is indistinguishable from a normal web server.

How it works:

- Teleproxy listens on port 443
- nginx runs on a non-standard port (e.g. 8443) with a valid certificate
- Domain's DNS A record points to the Teleproxy server
- Valid proxy clients connect normally; all other traffic forwarded to nginx

**Active probing resistance:** Every connection that fails validation — wrong secret, expired timestamp, unknown SNI, replayed handshake, malformed ClientHello, or plain non-TLS traffic — is transparently forwarded to the backend. Anyone probing sees a real HTTPS website.

Requirements:

- Backend must support TLS 1.3 (verified at startup)
- `-D` value must be a hostname, not an IP (TLS SNI doesn't support IPs per RFC 6066)

Setup example with nginx:

```nginx
server {
    listen 127.0.0.1:8443 ssl default_server;
    server_name mywebsite.com;
    ssl_certificate /etc/letsencrypt/live/mywebsite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mywebsite.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    root /var/www/html;
    location / { try_files $uri $uri/ =404; }
}
```

Add `/etc/hosts` entry if nginx only listens on loopback:

```
127.0.0.1 mywebsite.com
```

Run with domain and port:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> -D mywebsite.com:8443 --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

!!! note
    Use certbot with DNS-01 challenge for certificate renewal — HTTP-01 won't work since Teleproxy occupies port 443.

## Unix Socket Backend

On high-traffic deployments, the loopback TCP flow between Teleproxy
and the local nginx backend puts pressure on the kernel's conntrack
table and doubles per-probe TCP state. Routing the backend through an
AF_UNIX stream socket eliminates loopback entirely — conntrack never
sees it.

Syntax:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> \
    -D mywebsite.com@unix:/run/nginx-mtproxy.sock \
    --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

Left of `@unix:` is the SNI hostname used for fake-TLS domain matching.
Right of `@unix:` is the absolute path to the backend socket. The path
must fit in `sockaddr_un.sun_path` (107 bytes on Linux).

nginx configuration:

```nginx
server {
    listen unix:/run/nginx-mtproxy.sock ssl default_server;
    server_name mywebsite.com;
    ssl_certificate /etc/letsencrypt/live/mywebsite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mywebsite.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    root /var/www/html;
    location / { try_files $uri $uri/ =404; }
}
```

**Permissions.** Teleproxy typically runs as `nobody`. Make the socket
accessible:

```nginx
# In the main nginx.conf, under the relevant context:
user www-data;  # or whichever user owns nginx workers
```

Then `chown www-data:nogroup /run/nginx-mtproxy.sock && chmod 660 ...`
via a tmpfiles.d or systemd drop-in, or use systemd socket activation
with `SocketUser=`/`SocketGroup=` so the socket is created with the
right ownership automatically.

**Startup verification.** Teleproxy performs the same TLS 1.3
handshake probing over the unix socket that it performs over TCP,
measuring `ServerHello` record sizes to drive mimicry. The backend
must already be listening when Teleproxy starts — use systemd
`After=nginx.service` (or equivalent) in the Teleproxy unit to
enforce the order.

If the verification fails, Teleproxy logs a warning and falls back to
randomized encrypted sizes (2500–3620 bytes). Startup does not abort.

## Dynamic Record Sizing (DRS)

TLS connections automatically use graduated record sizes that mimic real HTTPS servers (Cloudflare, Go, Caddy): small MTU-sized records during TCP slow-start (~1450 bytes), ramping to ~4096 bytes, then max TLS payload (~16144 bytes). This defeats statistical traffic analysis that fingerprints proxy traffic by uniform record sizes.

No configuration needed — DRS activates automatically for all TLS connections.

## DD Mode (Random Padding)

For ISPs that detect MTProto by packet sizes, random padding is added.

Client setup: prefix `dd` to secret (`cafe...babe` becomes `ddcafe...babe`).

Server setup: use `-R` to allow only padded clients.
