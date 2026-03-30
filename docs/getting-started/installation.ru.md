# Установка

## Готовый бинарник (любой Linux)

Статически собранные бинарники публикуются с каждым релизом — линковка с musl libc, никаких зависимостей. Скачайте и запускайте.

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

Контрольные суммы SHA256 публикуются вместе с каждым релизом.

## Docker

Подробности в разделе [Docker Quick Start](../docker/index.md) — самый простой способ запустить Teleproxy одной командой с автоматической генерацией секретов.

## Сборка из исходников

Установите зависимости для сборки:

=== "Debian / Ubuntu"

    ```bash
    apt install git curl build-essential libssl-dev zlib1g-dev
    ```

=== "CentOS / RHEL"

    ```bash
    yum groupinstall "Development Tools"
    yum install openssl-devel zlib-devel
    ```

Клонируйте репозиторий и соберите:

```bash
git clone https://github.com/teleproxy/teleproxy
cd teleproxy
make
```

Скомпилированный бинарник будет находиться по пути `objs/bin/teleproxy`.

!!! note
    Если сборка завершилась ошибкой, выполните `make clean` перед повторной попыткой.
