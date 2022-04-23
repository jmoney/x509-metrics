package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strconv"
	"time"
)

func main() {

	host := flag.String("host", "", "The host to connect too.")
	port := flag.Int("port", 443, "The port to connect too.")
	protocol := flag.String("protocol", "tcp", "The protocol to use.  Valid values are tcp.")
	flag.Parse()

	var conn *tls.Conn
	var err error

	switch *protocol {
	case "tcp":
		conn, err = connectTcp(*host, *port)
	default:
		panic("Unknown protocol")
	}

	if err != nil {
		panic(err)
	}

	tlsMetrics := tlsMetrics(conn)
	jsonBytes, err := json.Marshal(tlsMetrics)
	if err != nil {
		panic("cannot convert map to json")
	}
	fmt.Println(string(jsonBytes))
}

func connectTcp(host string, port int) (*tls.Conn, error) {
	conf := &tls.Config{
		ServerName: host,
	}

	conn, err := tls.Dial("tcp", host+":"+strconv.Itoa(port), conf)
	if err != nil {
		log.Panic(err)
	}

	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	err = conn.Handshake()
	if err != nil {
		log.Panic(err)
	}

	return conn, err
}

func tlsMetrics(client *tls.Conn) map[string]map[string]int64 {
	metrics := make(map[string]int64)

	err := client.Handshake()
	if err != nil {
		panic(err)
	}
	certs := client.ConnectionState().PeerCertificates

	expiresIn := certs[0].NotAfter.Sub(time.Now())
	issuedAt := time.Now().Sub(certs[0].NotBefore)

	metrics["days_left"] = int64(expiresIn.Hours() / 24)
	metrics["seconds_left"] = int64(expiresIn.Seconds())
	metrics["issued_days"] = int64(issuedAt.Hours() / 24)
	metrics["issued_seconds"] = int64(issuedAt.Seconds())

	return map[string]map[string]int64{"tls": metrics}
}
