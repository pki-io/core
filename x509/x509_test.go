package x509

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestX509SignCSR(t *testing.T) {
	rootCA, _ := NewCA(nil)
	rootCA.Data.Body.Name = "RootCA"
	rootCA.Data.Body.DNScope.Country = "UK"
	rootCA.Data.Body.DNScope.Organization = "pki.io"
	rootCA.GenerateRoot()

	subCA, _ := NewCA(nil)
	subCA.Data.Body.Name = "DevCA"
	subCA.Data.Body.DNScope.OrganizationalUnit = "Development"
	subCA.GenerateSub(rootCA)

	csr, _ := NewCSR(nil)
	csr.Data.Body.Name = "Server1"
	csr.Generate()

	csrPublic, _ := csr.Public()

	cert, err := subCA.Sign(csrPublic)
	assert.Nil(t, err)
	assert.NotNil(t, cert)
	assert.NotEqual(t, cert.Data.Body.Certificate, "")

	certificate, err := PemDecodeX509Certificate([]byte(cert.Data.Body.Certificate))
	assert.Nil(t, err)
	assert.True(t, certificate.NotBefore.After(time.Now().AddDate(0, 0, -1)))
	assert.True(t, certificate.NotAfter.Before(time.Now().AddDate(0, 0, 1)))
}
