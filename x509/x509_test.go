package x509

import (
	//"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestX509SignCSR(t *testing.T) {
	rootCA, _ := NewCA(nil)
	rootCA.Data.Body.Name = "RootCA"
	rootCA.Data.Body.DNScope.Country = "UK"
	rootCA.Data.Body.DNScope.Organization = "pki.io"
	rootCA.GenerateRoot(time.Now(), time.Now().AddDate(5, 5, 5))

	subCA, _ := NewCA(nil)
	subCA.Data.Body.Name = "DevCA"
	subCA.Data.Body.DNScope.OrganizationalUnit = "Development"
	subCA.GenerateSub(rootCA, time.Now(), time.Now().AddDate(5, 5, 1))

	csr, _ := NewCSR(nil)
	csr.Data.Body.Name = "Server1"
	csr.Generate()

	csrPublic, _ := csr.Public()

	cert, err := subCA.Sign(csrPublic)
	assert.Nil(t, err)
	assert.NotNil(t, cert)
	assert.NotEqual(t, cert.Data.Body.Certificate, "")
}
