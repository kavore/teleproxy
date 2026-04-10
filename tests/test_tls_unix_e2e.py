#!/usr/bin/env python3
"""E2E test for the -D domain@unix:<path> fake-TLS backend.

Three independent assertions:

  1. Teleproxy /stats reports max_connections == EXPECTED_MAX_CONN
     (verifies Part 1 — runtime-sized heap allocation via -c).

  2. Teleproxy does not crash on startup with @unix: domain + -c 200000
     (verifies Part 1 + Part 2 coexist; implicit, proven by #1 succeeding).

  3. A plain TLS 1.3 connection to teleproxy's MTProto port with
     SNI=EE_DOMAIN (no proxy-secret, just a probe) is forwarded through
     teleproxy to nginx on the unix socket and returns HTTP 200 "OK".
     (verifies Part 2 — proxy_connection opens AF_UNIX backend
     successfully and pipes bytes.)
"""

import os
import socket
import ssl
import sys
import time
import urllib.request


TELEPROXY_HOST = os.environ["TELEPROXY_HOST"]
TELEPROXY_PORT = int(os.environ["TELEPROXY_PORT"])
TELEPROXY_STATS_PORT = int(os.environ["TELEPROXY_STATS_PORT"])
EE_DOMAIN = os.environ["EE_DOMAIN"]
EXPECTED_MAX_CONN = int(os.environ["EXPECTED_MAX_CONN"])


def assert_max_conn_from_stats():
    """Verify Part 1 by querying the stats endpoint.

    The http-stats page emits a line `max_connections\\t<N>` where <N>
    is the runtime max_connection_fd. With -c 200000 passed on the
    command line (via MAX_CONNECTIONS env -> TOML maxconn -> set_maxconn),
    this must read 200000.
    """
    url = f"http://{TELEPROXY_HOST}:{TELEPROXY_STATS_PORT}/stats"
    deadline = time.time() + 30.0
    last_err = None
    body = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            break
        except Exception as e:
            last_err = e
            time.sleep(1)
    if body is None:
        raise RuntimeError(f"could not reach stats endpoint {url}: {last_err}")

    expected = f"max_connections\t{EXPECTED_MAX_CONN}"
    if expected not in body:
        print("--- stats body (first 2 KiB) ---")
        print(body[:2048])
        print("--- end ---")
        raise AssertionError(
            f"expected '{expected}' in stats body; did not find it"
        )
    print(f"OK: stats reports max_connections = {EXPECTED_MAX_CONN}")


def assert_probe_forwarded_to_unix_backend():
    """Verify Part 2 by sending a vanilla TLS 1.3 ClientHello with SNI
    matching EE_DOMAIN but WITHOUT the MTProto ee-prefix. The connection
    is not a valid proxy client -> teleproxy forwards the entire flow to
    the unix-socket backend (nginx), which replies with HTTP 200 OK.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    with socket.create_connection((TELEPROXY_HOST, TELEPROXY_PORT), timeout=15) as raw:
        with ctx.wrap_socket(raw, server_hostname=EE_DOMAIN) as tls:
            tls.sendall(
                f"GET / HTTP/1.1\r\nHost: {EE_DOMAIN}\r\n"
                "Connection: close\r\n\r\n".encode("ascii")
            )
            buf = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 64 * 1024:
                    break

    if not buf:
        raise AssertionError("empty response from forwarded probe")

    head = buf.split(b"\r\n", 1)[0]
    if not head.startswith(b"HTTP/1."):
        raise AssertionError(f"unexpected response from forwarded probe: {head!r}")
    if b" 200 " not in head:
        raise AssertionError(f"non-200 from unix backend: {head!r}")
    if b"OK" not in buf:
        raise AssertionError(f"missing OK payload from unix backend: {buf[:200]!r}")
    print("OK: probe was forwarded to the unix-socket backend and returned 200 OK")


def main():
    # Give teleproxy a moment to reach the event loop if started just now
    time.sleep(2)
    assert_max_conn_from_stats()
    assert_probe_forwarded_to_unix_backend()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(f"TEST FAILED: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"TEST ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
