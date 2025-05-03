FROM alpine:latest
COPY ../../simple-va-linux-amd64 /usr/local/bin/simple-va
COPY ../config/default.ini /etc/simple-va/config.ini

RUN mkdir -p /var/lib/simple-va/certs
RUN mkdir -p /etc/simple-va

VOLUME ["/etc/simple-va", "/var/lib/simple-va"]

ENTRYPOINT ["/usr/local/bin/simple-va"]
