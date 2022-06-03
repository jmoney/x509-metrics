FROM alpine
COPY x509-metrics /
ENTRYPOINT ["/x509-metrics"]