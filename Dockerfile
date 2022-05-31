FROM alpine
COPY server-tls-monitor /
ENTRYPOINT ["/server-tls-metrics"]