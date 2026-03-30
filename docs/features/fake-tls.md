# Fake-TLS (EE Mode)

Teleproxy supports EE mode which makes proxy traffic look like standard TLS 1.3, making it harder to detect and block.

## How It Works

The client secret uses the format: `ee` + server_secret + domain_hex

Server setup — add domain configuration (must support TLS 1.3):

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> -D www.google.com --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

Get the domain hex:

```bash
echo -n www.google.com | xxd -plain
# Output: 7777772e676f6f676c652e636f6d
```

Client secret: `eecafe1234567890abcdef1234567890ab7777772e676f6f676c652e636f6d`

Quick generation:

```bash
SECRET="cafe1234567890abcdef1234567890ab"
DOMAIN="www.google.com"
echo -n "ee${SECRET}" && echo -n $DOMAIN | xxd -plain
```

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

## Dynamic Record Sizing (DRS)

TLS connections automatically use graduated record sizes that mimic real HTTPS servers (Cloudflare, Go, Caddy): small MTU-sized records during TCP slow-start (~1450 bytes), ramping to ~4096 bytes, then max TLS payload (~16144 bytes). This defeats statistical traffic analysis that fingerprints proxy traffic by uniform record sizes.

No configuration needed — DRS activates automatically for all TLS connections.

## DD Mode (Random Padding)

For ISPs that detect MTProto by packet sizes, random padding is added.

Client setup: prefix `dd` to secret (`cafe...babe` becomes `ddcafe...babe`).

Server setup: use `-R` to allow only padded clients.
