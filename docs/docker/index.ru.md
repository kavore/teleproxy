# Быстрый старт с Docker

Самый простой способ запустить Teleproxy — никакой настройки не нужно:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

Контейнер автоматически:

- Скачивает актуальную конфигурацию прокси от Telegram
- Генерирует случайный секрет, если не задан
- Запускает прокси на порту 443

Ссылки для подключения выводятся в логах:

```bash
docker logs teleproxy
# ===== Connection Links =====
# https://t.me/proxy?server=203.0.113.1&port=443&secret=eecafe...
# =============================
```

Если автоопределение внешнего IP не работает (например, за корпоративным файрволом), задайте переменную окружения `EXTERNAL_IP` явно.

## С Fake-TLS (режим EE)

Оборачивает трафик MTProto в настоящий TLS-хэндшейк, делая его неотличимым от обычного HTTPS:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e EE_DOMAIN=www.google.com \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

## Прямое подключение к DC

Минует промежуточные relay-серверы Telegram, направляя клиентов напрямую к ближайшему дата-центру:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

## Доступные теги

**GitHub Container Registry:**

- `ghcr.io/teleproxy/teleproxy:latest`
- `ghcr.io/teleproxy/teleproxy:v*`

**Docker Hub:**

- `rkline0x/teleproxy:latest`
- `rkline0x/teleproxy:v*`

Используйте Docker Hub, если ваше окружение не может загружать образы из ghcr.io (например, контейнеры MikroTik RouterOS).

## Сборка собственного образа

```bash
docker build -t teleproxy .
docker run -d --name teleproxy -p 443:443 -p 8888:8888 teleproxy
docker logs teleproxy 2>&1 | grep "Generated secret"
```
