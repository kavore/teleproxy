# Прямое подключение к DC

По умолчанию Teleproxy маршрутизирует трафик через промежуточные relay-серверы Telegram (middle-end, ME). Прямой режим обходит их:

```
По умолчанию:  Клиент -> Teleproxy -> ME relay -> Telegram DC
Прямой режим:  Клиент -> Teleproxy -> Telegram DC
```

Включение через `--direct`:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <секрет> --http-stats --direct
```

В прямом режиме:

- Файлы `proxy-multi.conf` и `proxy-secret` не нужны
- Аргумент конфигурационного файла не требуется
- Подключение идёт напрямую к известным адресам дата-центров Telegram
- **Несовместим с `-P` (тег прокси)** — спонсорские каналы требуют ME relay

Docker:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```
