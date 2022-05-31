package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/jmoney/server-tls-metrics/pkg/tlsmetrics"
)

func main() {

	host := flag.String("host", "", "The host to connect too.")
	port := flag.Int("port", 443, "The port to connect too.")
	protocol := flag.String("protocol", "tcp", "The protocol to use.  Valid values are tcp or postgres.")
	flag.Parse()

	tlsMetrics := tlsmetrics.FetchTlsMetrics(protocol, host, port)
	fmt.Println(marshalTlsMetrics(tlsMetrics))
}

func marshalTlsMetrics(metrics tlsmetrics.TlsMetrics) string {
	jsonBytes, err := json.Marshal(metrics)
	if err != nil {
		panic("cannot convert map to json")
	}
	return string(jsonBytes)
}
