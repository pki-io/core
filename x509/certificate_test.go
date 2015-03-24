package x509

import (
	//"fmt"
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestX509NewCertificate(t *testing.T) {
	certficiate, err := NewCertificate(nil)
	assert.Nil(t, err)
	assert.NotNil(t, certficiate)
	assert.Equal(t, certficiate.Data.Scope, "pki.io")
}

func TestX509CertificateDump(t *testing.T) {
	certficiate, _ := NewCertificate(nil)
	certficiateJson := certficiate.Dump()
	assert.NotEqual(t, len(certficiateJson), 0)
}

func TestX509CertificateGenerateSelfSigned(t *testing.T) {
	certificate, _ := NewCertificate(nil)

	subject := &pkix.Name{CommonName: "Test"}
	certificate.Data.Body.Expiry = 10

	err := certificate.Generate(nil, subject)
	assert.Nil(t, err)
	assert.NotEqual(t, certificate.Data.Body.Certificate, "")
}
