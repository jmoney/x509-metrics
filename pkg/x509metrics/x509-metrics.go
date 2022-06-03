package x509metrics

import (
	"crypto/x509"
	"encoding/json"
	"strings"
	"time"
)

// X509Metrics contains the expiration metrics of a x509 passed in PEM format.
// X509 a map of the expiration metrics. The key metrics are issued and left in both days and second flavors.
// Issued is how old the certificate is and left is how many units left until expiration.
// Tags are not customizable and currently only contain the servername from the certificate but could house more useful
// data later.
// Error is any error message that occurred during the collection process.
type X509Metrics struct {
	X509  map[string]int64  `json:"x509,omitempty"`
	Tags  map[string]string `json:"tags,omitempty"`
	Error string            `json:"error,omitempty"`
}

// ParseX509Metrics fetches x509 expiration metrics from a PEM formatted certificate
func ParseX509Metrics(certificate *x509.Certificate) X509Metrics {

	expiresIn := certificate.NotAfter.Sub(time.Now())
	issuedAt := time.Now().Sub(certificate.NotBefore)

	metrics := make(map[string]int64)
	metrics["days_left"] = int64(expiresIn.Hours() / 24)
	metrics["seconds_left"] = int64(expiresIn.Seconds())
	metrics["issued_days"] = int64(issuedAt.Hours() / 24)
	metrics["issued_seconds"] = int64(issuedAt.Seconds())

	return X509Metrics{
		X509: metrics,
		Tags: map[string]string{
			"name":              certificate.Subject.CommonName,
			"issuer":            strings.ReplaceAll(certificate.Issuer.CommonName, " ", ""),
			"organization":      strings.Join(certificate.Issuer.Organization, ","),
			"organization_unit": strings.Join(certificate.Issuer.OrganizationalUnit, ","),
		},
	}
}

func (m X509Metrics) Marshal() string {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		panic("cannot convert map to json")
	}
	return string(jsonBytes)
}
