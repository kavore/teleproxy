---
description: "Настройка режима EE в Teleproxy для обёртки MTProto в настоящий TLS 1.3 хэндшейк. Трафик неотличим от обычного HTTPS."
---

# Fake-TLS (режим EE)

Teleproxy поддерживает режим EE, который маскирует трафик прокси под стандартный TLS 1.3, затрудняя его обнаружение и блокировку.

## Как это работает

Клиентский секрет формируется по шаблону: `ee` + серверный_секрет + домен_hex

Настройка сервера — укажите домен (должен поддерживать TLS 1.3):

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <секрет> -D www.google.com --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

Получите hex-представление домена:

```bash
echo -n www.google.com | xxd -plain
# Результат: 7777772e676f6f676c652e636f6d
```

Клиентский секрет: `eecafe1234567890abcdef1234567890ab7777772e676f6f676c652e636f6d`

Быстрая генерация:

```bash
SECRET="cafe1234567890abcdef1234567890ab"
DOMAIN="www.google.com"
echo -n "ee${SECRET}" && echo -n $DOMAIN | xxd -plain
```

## Собственный TLS-бэкенд (TCP Splitting) {#custom-tls-backend-tcp-splitting}

Вместо имитации публичного сайта можно запустить собственный веб-сервер за Teleproxy с настоящим TLS-сертификатом. Обычные посетители видят полноценный HTTPS-сайт — сервер неотличим от обычного веб-сервера.

Как это работает:

- Teleproxy слушает порт 443
- nginx работает на нестандартном порту (например, 8443) с валидным сертификатом
- DNS A-запись домена указывает на сервер Teleproxy
- Клиенты с правильным секретом подключаются к прокси; весь остальной трафик перенаправляется на nginx

**Устойчивость к активному зондированию:** Каждое соединение, не прошедшее валидацию — неверный секрет, истекшая метка времени, неизвестный SNI, повторный handshake, некорректный ClientHello или обычный не-TLS трафик — прозрачно перенаправляется на бэкенд. Любой, кто зондирует сервер, видит настоящий HTTPS-сайт.

Требования:

- Бэкенд должен поддерживать TLS 1.3 (проверяется при запуске)
- Значение `-D` должно быть именем хоста, а не IP-адресом (TLS SNI не поддерживает IP-адреса согласно RFC 6066)

Пример настройки с nginx:

```nginx
server {
    listen 127.0.0.1:8443 ssl default_server;
    server_name mywebsite.com;
    ssl_certificate /etc/letsencrypt/live/mywebsite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mywebsite.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    root /var/www/html;
    location / { try_files $uri $uri/ =404; }
}
```

Добавьте запись в `/etc/hosts`, если nginx слушает только на loopback:

```
127.0.0.1 mywebsite.com
```

Запуск с указанием домена и порта:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <секрет> -D mywebsite.com:8443 --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

!!! note
    Используйте certbot с DNS-01 challenge для обновления сертификата — HTTP-01 не сработает, так как Teleproxy занимает порт 443.

## Unix-сокет бэкенд

На высоконагруженных развёртываниях трафик через loopback TCP между
Teleproxy и локальным nginx создаёт давление на таблицу conntrack
ядра и удваивает количество TCP-состояний на каждый проб. Маршрутизация
бэкенда через AF_UNIX стрим-сокет полностью убирает loopback —
conntrack его не видит.

Синтаксис:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> \
    -D mywebsite.com@unix:/run/nginx-mtproxy.sock \
    --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

Слева от `@unix:` — SNI-hostname для мэтчинга fake-TLS домена.
Справа — абсолютный путь к файлу бэкенд-сокета. Путь должен
помещаться в `sockaddr_un.sun_path` (107 байт на Linux).

Конфигурация nginx:

```nginx
server {
    listen unix:/run/nginx-mtproxy.sock ssl default_server;
    server_name mywebsite.com;
    ssl_certificate /etc/letsencrypt/live/mywebsite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mywebsite.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    root /var/www/html;
    location / { try_files $uri $uri/ =404; }
}
```

**Права.** Teleproxy обычно работает под `nobody`. Сокет должен быть
доступен этому пользователю:

```nginx
# В основном nginx.conf, в нужном контексте:
user www-data;  # или кто там владеет воркерами nginx
```

Затем `chown www-data:nogroup /run/nginx-mtproxy.sock && chmod 660 ...`
через tmpfiles.d или systemd drop-in, либо через systemd socket
activation с `SocketUser=`/`SocketGroup=` — тогда сокет создаётся
сразу с правильным владельцем.

**Проверка при старте.** Teleproxy делает ту же TLS 1.3 handshake
проверку через unix-сокет, что и через TCP, замеряя размеры
`ServerHello` записей для мимикрии. Бэкенд должен уже слушать на
момент старта Teleproxy — используйте systemd `After=nginx.service`
(или эквивалент) в юните Teleproxy для фиксации порядка.

Если проверка провалилась, Teleproxy логирует предупреждение и
откатывается на рандомизированные размеры шифрованных данных
(2500–3620 байт). Старт не аварийно завершается.

## Динамический размер записей (DRS)

TLS-соединения автоматически используют градуированные размеры записей, имитирующие поведение реальных HTTPS-серверов (Cloudflare, Go, Caddy): маленькие записи размером MTU во время TCP slow-start (~1450 байт), увеличивающиеся до ~4096 байт, затем до максимального TLS payload (~16144 байт). Это нейтрализует статистический анализ трафика, который определяет прокси по одинаковому размеру записей.

Настройка не требуется — DRS активируется автоматически для всех TLS-соединений.

## Режим DD (случайное дополнение)

Для провайдеров, обнаруживающих MTProto по размеру пакетов, добавляется случайное дополнение (padding).

Настройка клиента: добавьте префикс `dd` к секрету (`cafe...babe` становится `ddcafe...babe`).

Настройка сервера: используйте `-R`, чтобы разрешить подключение только клиентам с padding.
