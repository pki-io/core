package x509

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pki-io/core/crypto"
	"math/big"
	"strings"
)

func PemEncodeX509CertificateDER(cert []byte) []byte {
	b := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	return pem.EncodeToMemory(b)
}

func PemDecodeX509Certificate(in []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(in)
	if certs, err := x509.ParseCertificates(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse certificate: %s", err)
	} else {
		return certs[0], nil
	}
}

func PemEncodeX509CSRDER(cert []byte) []byte {
	b := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: cert}
	return pem.EncodeToMemory(b)
}

func PemDecodeX509CSR(in []byte) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(in)
	if csr, err := x509.ParseCertificateRequest(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse csr: %s", err)
	} else {
		return csr, nil
	}
}

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
