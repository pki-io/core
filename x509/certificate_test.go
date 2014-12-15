package x509

import (
	//"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
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
	certficiate, _ := NewCertificate(nil)
	err := certficiate.Generate(nil, time.Now(), time.Now().AddDate(5, 5, 5))
	assert.Nil(t, err)
	assert.NotEqual(t, certficiate.Data.Body.Certificate, "")
}
