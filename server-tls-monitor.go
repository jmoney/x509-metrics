package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

type TlsMetrics struct {
	Tls  map[string]int64 `json:"tls"`
	Tags []string         `json:"tags"`
}

func main() {

	host := flag.String("host", "", "The host to connect too.")
	port := flag.Int("port", 443, "The port to connect too.")
	protocol := flag.String("protocol", "tcp", "The protocol to use.  Valid values are tcp or postgres.")
	flag.Parse()

	var conn *tls.Conn
	var err error

	switch *protocol {
	case "tcp":
		conn, err = connectTcp(*host, *port)
	case "postgres":
		conn, err = connectPostgres(*host, *port)
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

func connectPostgres(host string, port int) (*tls.Conn, error) {
	conn, err := net.Dial("tcp", host+":"+strconv.Itoa(port))
	if err != nil {
		panic(err)
	}
	defer func(cxn net.Conn) {
		_ = cxn.Close()
	}(conn)

	// Begin postgres handshake
	var scratchBuffer [512]byte
	scratchBuffer[0] = 0
	startupMessage := scratchBuffer[:5]

	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(80877103))
	startupMessage = append(startupMessage, x...)

	y := startupMessage[1:]
	binary.BigEndian.PutUint32(y, uint32(len(y)))

	_, err = conn.Write(startupMessage[1:])
	if err != nil {
		panic(err)
	}

	buffer := scratchBuffer[:1]
	_, err = io.ReadFull(conn, buffer)
	if err != nil {
		panic(err)
	}

	if buffer[0] != 'S' {
		panic("SSL not supported")
	}
	// End Postgres handshake

	conf := &tls.Config{
		ServerName: host,
	}

	client := tls.Client(conn, conf)
	defer func(cxn *tls.Conn) {
		_ = cxn.Close()
	}(client)

	err = client.Handshake()
	if err != nil {
		panic(err)
	}

	return client, err
}

func connectTcp(host string, port int) (*tls.Conn, error) {
	conf := &tls.Config{
		ServerName: host,
	}

	conn, err := tls.Dial("tcp", host+":"+strconv.Itoa(port), conf)
	if err != nil {
		panic(err)
	}

	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	err = conn.Handshake()
	if err != nil {
		panic(err)
	}

	return conn, err
}

func tlsMetrics(client *tls.Conn) TlsMetrics {
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

	return TlsMetrics{
		Tls:  metrics,
		Tags: []string{"host:" + client.ConnectionState().ServerName},
	}
}
