// ThreatSpec package github.com/pki-io/core/x509 as x509
package x509

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pki-io/core/crypto"
	"math/big"
	"strings"
)

// ThreatSpec TMv0.1 for PemEncodeX509CertificateDER
// Does PEM encoding of an X509 certificate for App:X509

func PemEncodeX509CertificateDER(cert []byte) []byte {
	b := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	return pem.EncodeToMemory(b)
}

// ThreatSpec TMv0.1 for PemDecodeX509Certificate
// Does PEM decoding of a X509 certificate for App:X509

func PemDecodeX509Certificate(in []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(in)
	if certs, err := x509.ParseCertificates(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse certificate: %s", err)
	} else {
		return certs[0], nil
	}
}

// ThreatSpec TMv0.1 for PemEncodeX509CSRDER
// Does PEM encoding of X509 CSR for App:X509

func PemEncodeX509CSRDER(cert []byte) []byte {
	b := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: cert}
	return pem.EncodeToMemory(b)
}

// ThreatSpec TMv0.1 for PemDecodeX509CSR
// Does PEM decoding of X509 CSR for App:X509

func PemDecodeX509CSR(in []byte) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(in)
	if csr, err := x509.ParseCertificateRequest(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse csr: %s", err)
	} else {
		return csr, nil
	}
}

// ThreatSpec TMv0.1 for NewSerial
// Does new certificate serial creation for App:X509

func NewSerial() (*big.Int, error) {
	uuid := crypto.TimeOrderedUUID()
	clean := strings.Replace(uuid, "-", "", -1)
	i := new(big.Int)
	_, err := fmt.Sscanf(clean, "%x", i)
	if err != nil {
		return nil, fmt.Errorf("Could not scan UUID to int: %s", err)
	} else {
		return i, nil
	}
}
