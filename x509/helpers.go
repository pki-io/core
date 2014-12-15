package x509

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func PemEncodeX509CertificateDER(cert []byte) []byte {
	b := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	return pem.EncodeToMemory(b)
}

func PemDecodeX509Certificate(in []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(in)
	if certs, err := x509.ParseCertificates(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse certificate: %s", err.Error())
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
		return nil, fmt.Errorf("Could not parse csr: %s", err.Error())
	} else {
		return csr, nil
	}
}
