FROM alpine
COPY server-tls-metrics /
ENTRYPOINT ["/server-tls-metrics"]