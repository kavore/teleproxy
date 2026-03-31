#!/usr/bin/env python3
"""TLS fingerprint validation tests for Teleproxy's fake-TLS implementation.

Validates that the ClientHello matches a real Chrome TLS 1.3 fingerprint,
GREASE values are properly randomized (RFC 8701), the ServerHello complies
with RFC 8446 byte-by-byte, and encrypted payloads have high entropy.

Local tests (JA3, extension completeness, GREASE) run without a proxy.
Proxy tests (ServerHello compliance, entropy) need TELEPROXY_HOST/PORT/SECRET.
"""
import collections
import hashlib
import math
import os
import struct
import sys

from test_tls_e2e import (
    build_client_hello,
    wait_for_proxy,
    _do_handshake,
    _verify_server_hmac,
)


# ============================================================
# Helpers
# ============================================================


def _is_grease(value):
    """Check if a 16-bit value is a TLS GREASE value (RFC 8701)."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def compute_ja3(hello):
    """Compute JA3 fingerprint from a raw ClientHello bytearray.

    Args:
        hello: 517-byte ClientHello bytearray from build_client_hello().

    Returns:
        Tuple of (ja3_string, ja3_hash) where ja3_hash is the MD5 hex digest.
    """
    ssl_version = struct.unpack(">H", hello[9:11])[0]

    cs_len = struct.unpack(">H", hello[76:78])[0]
    ciphers = []
    for i in range(0, cs_len, 2):
        c = struct.unpack(">H", hello[78 + i : 80 + i])[0]
        if not _is_grease(c):
            ciphers.append(c)

    comp_len = hello[78 + cs_len]
    ext_offset = 78 + cs_len + 1 + comp_len
    ext_total = struct.unpack(">H", hello[ext_offset : ext_offset + 2])[0]
    ext_offset += 2

    extensions = []
    groups = []
    formats = []
    pos = ext_offset

    while pos < ext_offset + ext_total:
        ext_type = struct.unpack(">H", hello[pos : pos + 2])[0]
        ext_len = struct.unpack(">H", hello[pos + 2 : pos + 4])[0]
        ext_data = hello[pos + 4 : pos + 4 + ext_len]

        if not _is_grease(ext_type):
            extensions.append(ext_type)

            if ext_type == 0x000A:  # supported_groups
                list_len = struct.unpack(">H", ext_data[0:2])[0]
                for j in range(0, list_len, 2):
                    g = struct.unpack(">H", ext_data[2 + j : 4 + j])[0]
                    if not _is_grease(g):
                        groups.append(g)

            elif ext_type == 0x000B:  # ec_point_formats
                fmt_len = ext_data[0]
                for j in range(fmt_len):
                    formats.append(ext_data[1 + j])

        pos += 4 + ext_len

    ja3_parts = [
        str(ssl_version),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in extensions),
        "-".join(str(g) for g in groups),
        "-".join(str(f) for f in formats),
    ]
    ja3_string = ",".join(ja3_parts)
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

    return ja3_string, ja3_hash


def parse_extensions(hello):
    """Parse all extensions from a ClientHello into a list of (type, length, data).

    Args:
        hello: 517-byte ClientHello bytearray.

    Returns:
        List of (ext_type, ext_len, ext_data) tuples.
    """
    cs_len = struct.unpack(">H", hello[76:78])[0]
    comp_len = hello[78 + cs_len]
    ext_offset = 78 + cs_len + 1 + comp_len
    ext_total = struct.unpack(">H", hello[ext_offset : ext_offset + 2])[0]
    ext_offset += 2

    result = []
    pos = ext_offset
    while pos < ext_offset + ext_total:
        ext_type = struct.unpack(">H", hello[pos : pos + 2])[0]
        ext_len = struct.unpack(">H", hello[pos + 2 : pos + 4])[0]
        ext_data = hello[pos + 4 : pos + 4 + ext_len]
        result.append((ext_type, ext_len, bytes(ext_data)))
        pos += 4 + ext_len

    return result


# ============================================================
# Tests
# ============================================================


def test_ja3_fingerprint():
    """Compute JA3 hash of our ClientHello and verify structural correctness.

    JA3 is a method for fingerprinting TLS clients based on the ClientHello.
    This test proves our ClientHello has the expected structure: correct cipher
    count, extension count, and no GREASE leakage into the fingerprint.
    The hash must be stable across calls (GREASE is stripped).
    """
    hello1 = build_client_hello("www.google.com")
    hello2 = build_client_hello("www.google.com")

    ja3_str1, ja3_hash1 = compute_ja3(hello1)
    ja3_str2, ja3_hash2 = compute_ja3(hello2)

    assert len(ja3_hash1) == 32, f"JA3 hash wrong length: {len(ja3_hash1)}"
    assert all(c in "0123456789abcdef" for c in ja3_hash1), "JA3 hash not hex"

    assert ja3_hash1 == ja3_hash2, (
        f"JA3 hash not stable: {ja3_hash1} vs {ja3_hash2}"
    )

    parts = ja3_str1.split(",")
    assert len(parts) == 5, f"JA3 string has {len(parts)} parts, expected 5"
    assert parts[0] == "771", f"SSLVersion = {parts[0]}, expected 771"

    cipher_count = len(parts[1].split("-"))
    assert cipher_count == 16, f"Cipher count = {cipher_count}, expected 16"

    ext_count = len(parts[2].split("-"))
    assert ext_count == 15, f"Extension count = {ext_count}, expected 15"

    group_count = len(parts[3].split("-"))
    assert group_count == 3, f"Group count = {group_count}, expected 3"

    fmt_count = len(parts[4].split("-"))
    assert fmt_count == 1, f"Format count = {fmt_count}, expected 1"

    for part in parts[1:]:
        for val in part.split("-"):
            v = int(val)
            assert not _is_grease(v), f"GREASE value {v:#06x} leaked into JA3"

    print(f"  JA3 fingerprint OK: hash={ja3_hash1}, ciphers={cipher_count}, "
          f"extensions={ext_count}, groups={group_count}")


def test_tls_extension_completeness():
    """Verify all 15 TLS extensions are present in correct order with valid lengths.

    Our ClientHello must contain the same extensions as a real Chrome TLS 1.3
    handshake. This test parses every extension and validates its type ID,
    position, and data length.
    """
    domain = "example.com"
    hello = build_client_hello(domain)

    assert len(hello) == 517, f"ClientHello size = {len(hello)}, expected 517"

    exts = parse_extensions(hello)

    expected_ids = [
        0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010,
        0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B, 0x001B, 0x0015,
    ]
    non_grease = [(t, l, d) for t, l, d in exts if not _is_grease(t)]
    grease_exts = [(t, l, d) for t, l, d in exts if _is_grease(t)]

    assert len(non_grease) == 15, (
        f"Non-GREASE extension count = {len(non_grease)}, expected 15"
    )
    assert len(grease_exts) == 2, (
        f"GREASE extension count = {len(grease_exts)}, expected 2"
    )

    actual_ids = [t for t, l, d in non_grease]
    assert actual_ids == expected_ids, (
        f"Extension order mismatch:\n"
        f"  expected: {[f'0x{x:04X}' for x in expected_ids]}\n"
        f"  actual:   {[f'0x{x:04X}' for x in actual_ids]}"
    )

    ext_map = {t: (l, d) for t, l, d in non_grease}

    sni_len = ext_map[0x0000][0]
    assert sni_len == len(domain) + 5, (
        f"SNI length = {sni_len}, expected {len(domain) + 5}"
    )

    assert ext_map[0x0010][0] == 14, f"ALPN length = {ext_map[0x0010][0]}, expected 14"
    assert ext_map[0x000D][0] == 20, f"sig_algs length = {ext_map[0x000D][0]}, expected 20"
    assert ext_map[0x0033][0] == 43, f"key_share length = {ext_map[0x0033][0]}, expected 43"
    assert ext_map[0x002B][0] == 11, f"supported_versions length = {ext_map[0x002B][0]}, expected 11"

    cs_len = struct.unpack(">H", hello[76:78])[0]
    comp_len = hello[78 + cs_len]
    ext_offset = 78 + cs_len + 1 + comp_len
    ext_total = struct.unpack(">H", hello[ext_offset : ext_offset + 2])[0]
    assert ext_total == 401, f"Extensions total = {ext_total}, expected 401"

    print(f"  Extension completeness OK: {len(non_grease)} extensions, "
          f"{len(grease_exts)} GREASE, total={ext_total} bytes")


def test_grease_randomness():
    """Verify GREASE values are properly randomized across multiple ClientHellos.

    RFC 8701 GREASE values must vary between connections to prevent static
    fingerprinting. This test generates 20 hellos and checks that GREASE
    values are diverse and conform to the spec.
    """
    n = 20
    cipher_greases = []
    ext_greases = []

    for _ in range(n):
        hello = build_client_hello("example.com")

        gc = struct.unpack(">H", hello[78:80])[0]
        assert _is_grease(gc), f"First cipher 0x{gc:04X} is not GREASE"
        cipher_greases.append(gc)

        exts = parse_extensions(hello)
        g_exts = [t for t, l, d in exts if _is_grease(t)]
        assert len(g_exts) == 2, f"Expected 2 GREASE extensions, got {len(g_exts)}"
        ext_greases.extend(g_exts)

        for gv in [gc] + g_exts:
            assert (gv & 0x0F) == 0x0A, f"GREASE low nibble wrong: 0x{gv:04X}"
            assert (gv >> 8) == (gv & 0xFF), f"GREASE bytes differ: 0x{gv:04X}"

    unique_ciphers = len(set(cipher_greases))
    assert unique_ciphers >= 5, (
        f"Only {unique_ciphers} unique GREASE cipher values in {n} samples "
        f"(expected >= 5 of 16 possible)"
    )

    unique_ext = len(set(ext_greases))
    assert unique_ext >= 3, (
        f"Only {unique_ext} unique GREASE ext values in {n * 2} samples"
    )

    print(f"  GREASE randomness OK: {unique_ciphers} unique cipher values, "
          f"{unique_ext} unique ext values across {n} samples")


def test_server_hello_tls13_compliance():
    """Byte-level validation of proxy's ServerHello against RFC 8446.

    Verifies every field of the emulated ServerHello: record type, version,
    handshake type, session_id echo, cipher suite selection, extensions
    (key_share + supported_versions), CCS record, and application data.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    assert secret_hex, "TELEPROXY_SECRET environment variable not set"
    secret_bytes = bytes.fromhex(secret_hex)
    domain = os.environ.get(
        "EE_DOMAIN", os.environ.get("TLS_BACKEND_HOST", "172.30.0.10")
    )

    hello = build_client_hello(domain)
    sent_session_id = bytes(hello[44:76])

    data, client_random = _do_handshake(host, port, secret_bytes)
    assert len(data) >= 138, f"Response too short: {len(data)} bytes"
    assert _verify_server_hmac(data, client_random, secret_bytes), \
        "HMAC mismatch — not a proxy-generated ServerHello"

    assert data[0:3] == b"\x16\x03\x03", \
        f"Record header: {data[0:3].hex()}, expected 160303"

    rec_len = struct.unpack(">H", data[3:5])[0]
    assert rec_len == 0x7A, f"Record length = {rec_len}, expected 122"

    assert data[5] == 0x02, f"Handshake type = 0x{data[5]:02x}, expected 0x02"

    body_len = (data[6] << 16) | (data[7] << 8) | data[8]
    assert body_len == 0x76, f"Body length = {body_len}, expected 118"

    assert data[9:11] == b"\x03\x03", \
        f"ServerHello version: {data[9:11].hex()}, expected 0303"

    assert data[43] == 0x20, f"session_id_length = {data[43]}, expected 32"
    assert data[44:76] == sent_session_id, "Session ID not echoed correctly"

    cipher = struct.unpack(">H", data[76:78])[0]
    assert cipher in (0x1301, 0x1302, 0x1303), \
        f"Cipher suite 0x{cipher:04X} is not TLS 1.3"

    assert data[78] == 0x00, f"Compression = {data[78]}, expected 0"

    ext_len = struct.unpack(">H", data[79:81])[0]
    assert ext_len == 0x2E, f"Extensions length = {ext_len}, expected 46"

    pos = 81
    srv_exts = {}
    while pos < 127:
        eid = struct.unpack(">H", data[pos:pos + 2])[0]
        elen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        srv_exts[eid] = data[pos + 4:pos + 4 + elen]
        pos += 4 + elen

    assert set(srv_exts.keys()) == {0x33, 0x2B}, \
        f"Expected extensions {{0x33, 0x2B}}, got {set(f'0x{k:02X}' for k in srv_exts)}"

    ks = srv_exts[0x33]
    assert len(ks) == 36, f"key_share data = {len(ks)} bytes, expected 36"
    ks_group = struct.unpack(">H", ks[0:2])[0]
    assert ks_group == 0x001D, f"key_share group = 0x{ks_group:04X}, expected x25519"
    ks_key_len = struct.unpack(">H", ks[2:4])[0]
    assert ks_key_len == 32, f"key_share key length = {ks_key_len}, expected 32"

    sv = srv_exts[0x2B]
    assert sv == b"\x03\x04", f"supported_versions = {sv.hex()}, expected 0304"

    assert data[127:133] == b"\x14\x03\x03\x00\x01\x01", \
        f"CCS = {data[127:133].hex()}, expected 140303000101"

    assert data[133:136] == b"\x17\x03\x03", \
        f"AppData header = {data[133:136].hex()}, expected 170303"

    enc_len = struct.unpack(">H", data[136:138])[0]
    assert enc_len > 0, "Encrypted data length is zero"
    assert len(data) >= 138 + enc_len, \
        f"Truncated app data: have {len(data) - 138}, need {enc_len}"

    print(f"  ServerHello TLS 1.3 compliance OK: cipher=0x{cipher:04X}, "
          f"key_share=x25519, encrypted={enc_len} bytes")


def test_encrypted_data_entropy():
    """Verify fake encrypted records have high Shannon entropy.

    The proxy fills encrypted application data with RAND_bytes(). This test
    computes the Shannon entropy of the payload and verifies it looks like
    random data (H >= 7.0 bits/byte for true random approaching 8.0).
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    assert secret_hex, "TELEPROXY_SECRET environment variable not set"
    secret_bytes = bytes.fromhex(secret_hex)

    data1, cr1 = _do_handshake(host, port, secret_bytes)
    data2, cr2 = _do_handshake(host, port, secret_bytes)

    assert len(data1) >= 138 and len(data2) >= 138, "Responses too short"

    enc_len1 = struct.unpack(">H", data1[136:138])[0]
    enc_len2 = struct.unpack(">H", data2[136:138])[0]
    payload1 = data1[138:138 + enc_len1]
    payload2 = data2[138:138 + enc_len2]

    assert len(payload1) >= 100, f"Encrypted payload too small: {len(payload1)} bytes"

    freq = collections.Counter(payload1)
    total = len(payload1)
    entropy = -sum(
        (count / total) * math.log2(count / total)
        for count in freq.values()
    )
    assert entropy >= 7.0, (
        f"Shannon entropy = {entropy:.2f} bits/byte (expected >= 7.0 for random data)"
    )

    if total >= 200:
        max_freq = max(freq.values()) / total
        assert max_freq < 0.03, (
            f"Dominant byte frequency = {max_freq:.3f} (expected < 0.03)"
        )

    assert payload1 != payload2, "Two handshakes produced identical encrypted data"

    print(f"  Encrypted data entropy OK: H={entropy:.2f} bits/byte, "
          f"payload={total} bytes, unique across handshakes")


# ============================================================
# Main
# ============================================================


def main():
    local_tests = [
        ("test_ja3_fingerprint", test_ja3_fingerprint),
        ("test_tls_extension_completeness", test_tls_extension_completeness),
        ("test_grease_randomness", test_grease_randomness),
    ]

    proxy_tests = [
        ("test_server_hello_tls13_compliance", test_server_hello_tls13_compliance),
        ("test_encrypted_data_entropy", test_encrypted_data_entropy),
    ]

    print("Starting TLS fingerprint validation tests...\n", flush=True)

    passed = 0
    failed = 0
    errors = []

    # Local tests run without proxy
    for name, test_fn in local_tests:
        try:
            print(f"[RUN]  {name}")
            test_fn()
            print(f"[PASS] {name}\n")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}\n")
            failed += 1
            errors.append((name, e))

    # Proxy tests need TELEPROXY_SECRET
    secret = os.environ.get("TELEPROXY_SECRET", "")
    if secret:
        host = os.environ.get("TELEPROXY_HOST", "teleproxy")
        proxy_port = os.environ.get("TELEPROXY_PORT", "8443")
        print(f"Waiting for proxy at {host}:{proxy_port}...", flush=True)
        if not wait_for_proxy(host, proxy_port, timeout=90):
            print("ERROR: Proxy not ready, skipping proxy tests")
        else:
            print("Proxy is ready.\n", flush=True)
            for name, test_fn in proxy_tests:
                try:
                    print(f"[RUN]  {name}")
                    test_fn()
                    print(f"[PASS] {name}\n")
                    passed += 1
                except Exception as e:
                    print(f"[FAIL] {name}: {e}\n")
                    failed += 1
                    errors.append((name, e))
    else:
        print("TELEPROXY_SECRET not set, skipping proxy tests\n")

    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for name, err in errors:
            print(f"  {name}: {err}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
