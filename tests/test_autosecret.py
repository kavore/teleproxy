"""Test that auto-generated secrets are written to TOML config.

When no SECRET env var is provided, start.sh generates a random secret.
This test verifies the /link page shows a proper connection link instead
of "No secrets configured".
"""

import os
import sys
import time

import requests

HOST = os.environ.get("TELEPROXY_HOST", "teleproxy")
STATS_PORT = os.environ.get("TELEPROXY_STATS_PORT", "8888")


def test_link_page():
    url = f"http://{HOST}:{STATS_PORT}/link"

    for attempt in range(5):
        try:
            resp = requests.get(url, timeout=5)
            break
        except Exception as e:
            print(f"Attempt {attempt + 1}: {e}")
            time.sleep(2)
    else:
        print("FAIL: /link endpoint unreachable after 5 attempts")
        return False

    if resp.status_code != 200:
        print(f"FAIL: /link returned {resp.status_code}")
        return False

    body = resp.text

    if "No secrets configured" in body:
        print("FAIL: auto-generated secret was not written to config")
        return False

    if "t.me/proxy" not in body:
        print(f"FAIL: no connection link in response (first 500 chars: {body[:500]})")
        return False

    print("PASS: /link page contains a valid connection link")
    return True


if __name__ == "__main__":
    time.sleep(2)
    ok = test_link_page()
    sys.exit(0 if ok else 1)
