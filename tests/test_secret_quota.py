#!/usr/bin/env python3
"""E2E tests for per-secret quotas, unique-IP limits, and expiration.

Verifies that:
- Stats and Prometheus metrics expose quota, max_ips, expires, and rejection counters
- An expired secret is rejected at the TLS handshake level
- An active secret with quota/max_ips/expires still works normally
"""
import os
import sys
import time

import requests

from test_tls_e2e import (
    _do_handshake,
    _verify_server_hmac,
    wait_for_proxy,
)


def _get_stats(host, stats_port):
    """Fetch plain-text stats from the proxy."""
    url = f"http://{host}:{stats_port}/stats"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def _get_metrics(host, stats_port):
    """Fetch Prometheus metrics from the proxy."""
    url = f"http://{host}:{stats_port}/metrics"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def test_quota_in_plain_stats():
    """Verify per-secret quota, bytes_total, and rejection counters in /stats."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    stats = _get_stats(host, stats_port)

    assert "secret_active_quota\t1073741824" in stats, (
        f"Expected 'secret_active_quota\\t1073741824' in stats:\n{stats}"
    )
    assert "secret_active_max_ips\t10" in stats, (
        f"Expected 'secret_active_max_ips\\t10' in stats:\n{stats}"
    )
    assert "secret_active_expires\t" in stats, (
        f"Expected 'secret_active_expires' in stats:\n{stats}"
    )
    assert "secret_active_bytes_total\t" in stats, (
        f"Expected 'secret_active_bytes_total' in stats:\n{stats}"
    )
    assert "secret_active_unique_ips\t" in stats, (
        f"Expected 'secret_active_unique_ips' in stats:\n{stats}"
    )
    assert "secret_active_rejected_quota\t" in stats, (
        f"Expected 'secret_active_rejected_quota' in stats:\n{stats}"
    )
    assert "secret_active_rejected_ips\t" in stats, (
        f"Expected 'secret_active_rejected_ips' in stats:\n{stats}"
    )
    assert "secret_active_rejected_expired\t" in stats, (
        f"Expected 'secret_active_rejected_expired' in stats:\n{stats}"
    )
    # Expired secret should NOT have quota/max_ips lines (not configured)
    assert "secret_expired_quota" not in stats, (
        f"Expired secret should not have a quota line:\n{stats}"
    )
    print("  Plain stats: quota/max_ips/expires fields present")


def test_quota_in_prometheus_metrics():
    """Verify per-secret quota metrics in /metrics."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    metrics = _get_metrics(host, stats_port)

    assert 'teleproxy_secret_quota_bytes{secret="active"} 1073741824' in metrics, (
        f"Expected quota_bytes=1073741824 for 'active' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_max_ips{secret="active"} 10' in metrics, (
        f"Expected max_ips=10 for 'active' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_unique_ips{secret="active"}' in metrics, (
        f"Expected unique_ips for 'active' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_expires_timestamp{secret="active"}' in metrics, (
        f"Expected expires_timestamp for 'active' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_bytes_total{secret="active"}' in metrics, (
        f"Expected bytes_total for 'active' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_rejected_quota_total{secret="active"}' in metrics, (
        f"Expected rejected_quota_total for 'active' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_rejected_ips_total{secret="active"}' in metrics, (
        f"Expected rejected_ips_total for 'active' in metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_rejected_expired_total{secret="expired"}' in metrics, (
        f"Expected rejected_expired_total for 'expired' in metrics:\n{metrics}"
    )
    # Expired secret should have quota=0 (not configured)
    assert 'teleproxy_secret_quota_bytes{secret="expired"} 0' in metrics, (
        f"Expected quota_bytes=0 for 'expired' in metrics:\n{metrics}"
    )
    print("  Prometheus metrics: quota/max_ips/expires fields present")


def test_active_secret_works():
    """Verify active secret with quota/max_ips/future-expiry accepts connections."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET_1", "")
    assert secret_hex, "TELEPROXY_SECRET_1 not set"

    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)

    assert len(data) >= 138, f"Response too short ({len(data)} bytes)"
    assert _verify_server_hmac(data, client_random, secret_bytes), "HMAC mismatch"
    print("  Active secret: handshake OK")


def test_expired_secret_rejected():
    """Verify expired secret is rejected at TLS handshake."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET_2", "")
    assert secret_hex, "TELEPROXY_SECRET_2 not set"

    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)

    # Expired secret should be rejected — either short response or HMAC mismatch
    rejected = not _verify_server_hmac(data, client_random, secret_bytes)
    assert rejected, "Expired secret should be rejected"
    print("  Expired secret: correctly rejected")


def test_expired_rejection_counter():
    """Verify the expired rejection counter increments."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    metrics = _get_metrics(host, stats_port)
    for line in metrics.splitlines():
        if 'teleproxy_secret_rejected_expired_total{secret="expired"}' in line:
            count = int(line.split()[-1])
            assert count > 0, f"Expected expired rejection count > 0, got {count}"
            print(f"  Expired rejection counter: {count}")
            return

    assert False, "rejected_expired_total metric not found for 'expired' secret"


def main():
    tests = [
        ("test_quota_in_plain_stats", test_quota_in_plain_stats),
        ("test_quota_in_prometheus_metrics", test_quota_in_prometheus_metrics),
        ("test_active_secret_works", test_active_secret_works),
        ("test_expired_secret_rejected", test_expired_secret_rejected),
        ("test_expired_rejection_counter", test_expired_rejection_counter),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    print("Starting secret quota/IP/expiry tests...\n", flush=True)
    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_proxy(host, port, timeout=90):
        print("ERROR: Proxy not ready after 90s")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)

    # Brief delay for stats endpoint to be ready
    time.sleep(2)

    passed = 0
    failed = 0
    errors = []

    for name, fn in tests:
        try:
            print(f"[RUN]  {name}")
            fn()
            print(f"[PASS] {name}\n")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}\n")
            failed += 1
            errors.append((name, e))

    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for name, err in errors:
            print(f"  {name}: {err}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
