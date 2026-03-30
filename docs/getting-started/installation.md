# Installation

## Static Binary (Any Linux)

Pre-built static binaries are published with every release — statically linked against musl libc, zero runtime dependencies. Download and run.

=== "amd64"

    ```bash
    curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-amd64
    chmod +x teleproxy
    ```

=== "arm64"

    ```bash
    curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-arm64
    chmod +x teleproxy
    ```

SHA256 checksums are published alongside each release for verification.

## Docker

See [Docker Quick Start](../docker/index.md) for the simplest way to run Teleproxy — a single `docker run` command with auto-generated secrets.

## Building from Source

Install build dependencies:

=== "Debian / Ubuntu"

    ```bash
    apt install git curl build-essential libssl-dev zlib1g-dev
    ```

=== "CentOS / RHEL"

    ```bash
    yum groupinstall "Development Tools"
    yum install openssl-devel zlib-devel
    ```

Clone and build:

```bash
git clone https://github.com/teleproxy/teleproxy
cd teleproxy
make
```

The compiled binary will be at `objs/bin/teleproxy`.

!!! note
    If the build fails, run `make clean` before retrying.
