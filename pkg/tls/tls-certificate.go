package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

// FetchTlsCertificate fetches tls expiration metrics from a hosted server.
// Protocol is either tcp or postgres.
// host is the host that is hosting the certificate in question.
// port is the port to connect too.
func FetchTlsCertificate(protocol *string, host *string, port *int) (*x509.Certificate, error) {

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
		return nil, err
	}

	err = conn.Handshake()
	if err != nil {
		return nil, err
	}
	certs := conn.ConnectionState().PeerCertificates
	return certs[0], nil
}

func connectPostgres(host string, port int) (*tls.Conn, error) {
	conn, err := net.Dial("tcp", host+":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
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
		return nil, err
	}

	buffer := scratchBuffer[:1]
	_, err = io.ReadFull(conn, buffer)
	if err != nil {
		return nil, err
	}

	if buffer[0] != 'S' {
		return nil, errors.New("SSL not supported")
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
		return nil, err
	}

	return client, nil
}

func connectTcp(host string, port int) (*tls.Conn, error) {
	conf := &tls.Config{
		ServerName: host,
	}

	conn, err := tls.Dial("tcp", host+":"+strconv.Itoa(port), conf)
	if err != nil {
		return nil, err
	}

	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	err = conn.Handshake()
	if err != nil {
		return nil, err
	}

	return conn, nil
}
