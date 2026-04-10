FROM nginx:alpine

RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# /var/run is a tmpfs by default in alpine nginx; the socket lives there and
# will be exposed through a docker-compose shared volume.
VOLUME ["/var/run/nginx-mtproxy"]

ENTRYPOINT ["/entrypoint.sh"]
