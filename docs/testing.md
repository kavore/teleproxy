# Testing

Teleproxy includes a comprehensive test suite. For full details, see [TESTING.md](https://github.com/teleproxy/teleproxy/blob/main/TESTING.md) in the repository.

## Running Tests (Docker)

```bash
make test
```

This builds the proxy image, test runner image, starts both, and runs connectivity checks. A random secret is generated if `TELEPROXY_SECRET` is not set.

## Running Tests (Local)

```bash
pip install -r tests/requirements.txt
export TELEPROXY_HOST=localhost
export TELEPROXY_PORT=443
python3 tests/test_proxy.py
```

## Test Suite

- **HTTP Stats**: Stats endpoint accessibility
- **Prometheus Metrics**: Valid exposition format
- **MTProto Port**: TCP connection acceptance
- **E2E Tests**: Real Telegram client connections (Telethon) through the proxy
- **Fuzz Testing**: libFuzzer harnesses with AddressSanitizer for protocol parsers

## Fuzz Testing

Requires Clang:

```bash
make fuzz CC=clang
make fuzz-run
make fuzz-run FUZZ_DURATION=300  # custom duration
```

Seed corpus in `fuzz/corpus/`. Fuzzers run automatically in CI.

## Troubleshooting

- **Timeout**: Check network — MTProto proxies may be blocked by some ISPs
- **Port in use**: Tests use ports 18443/18888 by default
