# Monitoring

## HTTP Stats Endpoint

```bash
curl http://localhost:8888/stats
```

Requires `--http-stats` flag. Accessible from private networks only (loopback, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

## Prometheus Metrics

```bash
curl http://localhost:8888/metrics
```

Returns Prometheus exposition format on the same stats port. Includes per-secret metrics when labels are configured.

Available metrics include connection counts, per-secret connections, rejection counts, and IP ACL rejections.

## Health Checks

Docker containers include built-in health monitoring via the stats endpoint. Check with:

```bash
docker ps  # STATUS column shows health
```
