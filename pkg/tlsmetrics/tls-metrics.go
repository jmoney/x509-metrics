package tlsmetrics

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// TlsMetrics contains the expiration metrics of a TLS certificate hosted on a server.
// Tls a map of the expiration metrics. The key metrics are issued and left in both days and second flavors.
// Issued is how old the certificate is and left is how many units left until expiration.
// Tags are not customizable and currently only contain the servername from the certificate but could house more useful
// data later.
// Error is any error message that occurred during the collection process.
type TlsMetrics struct {
	Tls   map[string]int64 `json:"tls,omitempty"`
	Tags  []string         `json:"tags,omitempty"`
	Error string           `json:"error,omitempty"`
}

// FetchTlsMetrics fetches tls expiration metrics from a hosted server.
// Protocol is either tcp or postgres.
// host is the host that is hosting the certificate in question.
// port is the port to connect too.
func FetchTlsMetrics(protocol *string, host *string, port *int) TlsMetrics {

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
		return TlsMetrics{
			Error: err.Error(),
		}
	}

	tlsMetrics, err := tlsMetrics(conn)
	if err != nil {
		return TlsMetrics{
			Error: err.Error(),
		}
	}

	return *tlsMetrics
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

func tlsMetrics(client *tls.Conn) (*TlsMetrics, error) {
	metrics := make(map[string]int64)

	err := client.Handshake()
	if err != nil {
		return nil, err
	}
	certs := client.ConnectionState().PeerCertificates

	expiresIn := certs[0].NotAfter.Sub(time.Now())
	issuedAt := time.Now().Sub(certs[0].NotBefore)

	metrics["days_left"] = int64(expiresIn.Hours() / 24)
	metrics["seconds_left"] = int64(expiresIn.Seconds())
	metrics["issued_days"] = int64(issuedAt.Hours() / 24)
	metrics["issued_seconds"] = int64(issuedAt.Seconds())

	return &TlsMetrics{
		Tls:  metrics,
		Tags: []string{"name:" + client.ConnectionState().ServerName},
	}, nil
}
