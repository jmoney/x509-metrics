package main

import (
	"crypto/tls"
	"log"
)

func main() {
	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{
		//InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "www.vrbo.com:443", conf)
	if err != nil {
		log.Panic(err)
	}
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		log.Panic(err)
	}

	commonName := conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	dnsNames := conn.ConnectionState().PeerCertificates[0].DNSNames
	notBefore := conn.ConnectionState().PeerCertificates[0].NotBefore.Local().String()
	notAfter := conn.ConnectionState().PeerCertificates[0].NotAfter.Local().String()

	log.Printf("cert common name: %s ", commonName)
	log.Printf("cert DNSNames: %v", dnsNames)
	log.Printf("cert invalid before: %s ", notBefore)
	log.Printf("cert invalid after: %s ", notAfter)
}
