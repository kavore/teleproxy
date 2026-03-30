# IPv6

Teleproxy supports IPv6. Enable with the `-6` flag.

## Example

```bash
./teleproxy -6 -u nobody -p 8888 -H 443 -S <secret> --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

- `-6` enables IPv6 listening. Binds to `::` (all IPv6 interfaces). On most systems also accepts IPv4 (dual-stack).
- `-H` accepts comma-separated port numbers only (e.g. `-H 80,443`). Don't pass IP literals.
- Binding to a specific IPv6 address is not supported — use a firewall.

## Client Side

- Prefer a hostname with an AAAA record
- Some clients may not accept raw IPv6 literals in `tg://` links

Examples:

- Hostname: `tg://proxy?server=proxy.example.com&port=443&secret=<secret>`
- Raw IPv6: `tg://proxy?server=[2001:db8::1]&port=443&secret=<secret>`

## Verification

```bash
# Check proxy listens on IPv6
ss -ltnp | grep :443
# Expect :::443

# Test stats via IPv6
curl -6 http://[::1]:8888/stats
```

## Troubleshooting

- Ensure IPv6 is enabled: `sysctl net.ipv6.conf.all.disable_ipv6` (should be `0`)
- Firewalls/security groups must allow IPv6 on the chosen port
- If IPv4 breaks after `-6`, check `net.ipv6.bindv6only` and firewall rules
- Use a hostname with an AAAA record to avoid client parsing issues

## Docker

- Ensure the Docker daemon has IPv6 enabled and the host has routable IPv6
- The default image entrypoint doesn't include `-6`. Override the container command or run on the host.
- See Docker docs for `daemon.json` (`"ipv6": true`, `"fixed-cidr-v6"`)
