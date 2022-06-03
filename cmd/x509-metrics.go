package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/jmoney/x509-metrics/pkg/tls"
	"github.com/jmoney/x509-metrics/pkg/x509metrics"
	"io/ioutil"
	"os"
)

func main() {

	host := flag.String("host", "", "The host to connect too.")
	port := flag.Int("port", 443, "The port to connect too.")
	protocol := flag.String("protocol", "tcp", "The protocol to use.  Valid values are tcp or postgres.")
	b64Cert := flag.String("b64", "", "base64 encoded certificate")
	stdin := flag.Bool("stdin", false, "Whether to accept the PEM certificate on stdin.")
	flag.Parse()

	var certificate *x509.Certificate
	var err error
	if !*stdin && *b64Cert != "" {
		certificate, err = tls.FetchTlsCertificate(protocol, host, port)
		if err != nil {
			panic(err)
		}
	} else {
		var data []byte
		if *stdin {
			data, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				panic(err)
			}
		} else {
			data, err = base64.StdEncoding.DecodeString(*b64Cert)
			if err != nil {
				panic(err)
			}
		}

		block, _ := pem.Decode(data)
		if block == nil {
			panic("failed to parse certificate PEM")
		}

		certificates, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			panic(err)
		}
		certificate = certificates[0]
	}

	x509Metrics := x509metrics.ParseX509Metrics(certificate)
	fmt.Println(x509Metrics.Marshal())
}
