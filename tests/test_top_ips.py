#!/usr/bin/env python3
"""E2E tests for per-IP Prometheus metrics (issue #46).

Verifies metric-family exposure for the three new families:
- teleproxy_secret_ip_connections
- teleproxy_secret_ip_bytes_received_total
- teleproxy_secret_ip_bytes_sent_total

The actual counter increment path (account_bytes / account_connect) is
covered transitively by the existing test_direct_e2e suite, which drives
real Telethon connections through the same call sites that increment the
sidecar IP volume table.  A fake-TLS ClientHello alone does not advance to
the obfs2 secret identification phase that triggers account_connect, so we
do not assert per-IP samples here — only structural exposure and the
cardinality cap.
"""
import os
import re
import sys
import time

import requests

from test_tls_e2e import (
    _do_handshake,
    _verify_server_hmac,
    wait_for_proxy,
)


def _get_metrics(host, stats_port):
    url = f"http://{host}:{stats_port}/metrics"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def test_help_and_type_headers_present():
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    metrics = _get_metrics(host, stats_port)

    expected = [
        "# HELP teleproxy_secret_ip_connections",
        "# TYPE teleproxy_secret_ip_connections gauge",
        "# HELP teleproxy_secret_ip_bytes_received_total",
        "# TYPE teleproxy_secret_ip_bytes_received_total counter",
        "# HELP teleproxy_secret_ip_bytes_sent_total",
        "# TYPE teleproxy_secret_ip_bytes_sent_total counter",
    ]
    for line in expected:
        assert line in metrics, f"Expected '{line}' in /metrics output"
    print("  HELP/TYPE headers present for all three metric families")


def test_handshake_still_works_with_top_ips_enabled():
    """Per-IP tracking must not break the normal connection path."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET_1", "")
    assert secret_hex, "TELEPROXY_SECRET_1 not set"

    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)

    assert len(data) >= 138, f"Handshake response too short ({len(data)} bytes)"
    assert _verify_server_hmac(data, client_random, secret_bytes), "HMAC mismatch"
    print("  Handshake completes with TOP_IPS_PER_SECRET enabled")


def test_cardinality_cap_respected():
    """The runtime cap is 5; sample count must not exceed that per secret."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    metrics = _get_metrics(host, stats_port)

    pattern = re.compile(
        r'^teleproxy_secret_ip_connections\{secret="alpha",ip="[^"]+"\}',
        re.MULTILINE,
    )
    count = len(pattern.findall(metrics))
    assert count <= 5, f"cardinality cap violated: got {count} samples, expected ≤ 5"
    print(f"  Cardinality cap respected: {count} ≤ 5 samples for secret 'alpha'")


def test_existing_per_secret_metrics_still_present():
    """Sanity check: introducing per-IP metrics didn't break the per-secret aggregates."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    metrics = _get_metrics(host, stats_port)

    expected = [
        'teleproxy_secret_connections{secret="alpha"}',
        'teleproxy_secret_connections_created_total{secret="alpha"}',
        'teleproxy_secret_bytes_received_total{secret="alpha"}',
        'teleproxy_secret_bytes_sent_total{secret="alpha"}',
    ]
    for needle in expected:
        assert needle in metrics, f"Existing per-secret metric missing: {needle}"
    print("  Per-secret aggregate metrics still present")


def main():
    tests = [
        ("test_help_and_type_headers_present", test_help_and_type_headers_present),
        ("test_handshake_still_works_with_top_ips_enabled",
         test_handshake_still_works_with_top_ips_enabled),
        ("test_cardinality_cap_respected", test_cardinality_cap_respected),
        ("test_existing_per_secret_metrics_still_present",
         test_existing_per_secret_metrics_still_present),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    print("Starting per-IP metrics tests...\n", flush=True)
    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_proxy(host, port, timeout=90):
        print("ERROR: Proxy not ready after 90s")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)
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
