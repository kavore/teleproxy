# Systemd

## Service File

Create `/etc/systemd/system/teleproxy.service`:

```ini
[Unit]
Description=Teleproxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/teleproxy
ExecStart=/opt/teleproxy/teleproxy -u nobody -p 8888 -H 443 -S <secret> --http-stats -P <proxy tag> --aes-pwd proxy-secret proxy-multi.conf -M 1
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Setup

```bash
systemctl daemon-reload
systemctl restart teleproxy.service
systemctl status teleproxy.service
systemctl enable teleproxy.service
```

## IPv6 Example

```ini
[Unit]
Description=Teleproxy (IPv6)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/teleproxy
ExecStart=/opt/teleproxy/teleproxy -6 -u nobody -p 8888 -H 443 -S <secret> --http-stats -P <proxy tag> --aes-pwd proxy-secret proxy-multi.conf -M 1
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
