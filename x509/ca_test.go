package x509

import (
	//"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestX509NewCA(t *testing.T) {
	ca, err := NewCA(nil)
	assert.Nil(t, err)
	assert.NotNil(t, ca)
	assert.Equal(t, ca.Data.Scope, "pki.io")
}

func TestX509CADump(t *testing.T) {
	ca, _ := NewCA(nil)
	caJson := ca.Dump()
	assert.NotEqual(t, len(caJson), 0)
}

func TestX509CAGenerateRoot(t *testing.T) {
	ca, _ := NewCA(nil)
	err := ca.GenerateRoot()
	assert.Nil(t, err)
	assert.NotEqual(t, ca.Data.Body.Certificate, "")
	assert.NotEqual(t, ca.Data.Body.Id, "")

	cert, err := PemDecodeX509Certificate([]byte(ca.Data.Body.Certificate))
	assert.Nil(t, err)
	assert.True(t, cert.NotBefore.After(time.Now().AddDate(0, 0, -1)))
	assert.True(t, cert.NotAfter.Before(time.Now().AddDate(0, 0, 1)))
}

func TestX509CAGenerateSub(t *testing.T) {
	rootCA, _ := NewCA(nil)
	rootCA.Data.Body.Name = "RootCA"
	rootCA.Data.Body.DNScope.Country = "UK"
	rootCA.Data.Body.DNScope.Organization = "pki.io"
	rootCA.GenerateRoot()

	subCA, _ := NewCA(nil)
	subCA.Data.Body.Name = "DevCA"
	subCA.Data.Body.DNScope.OrganizationalUnit = "Development"
	err := subCA.GenerateSub(rootCA)

	assert.Nil(t, err)
	assert.NotEqual(t, subCA.Data.Body.Certificate, "")

	cert, err := PemDecodeX509Certificate([]byte(subCA.Data.Body.Certificate))
	assert.Nil(t, err)
	assert.True(t, cert.NotBefore.After(time.Now().AddDate(0, 0, -1)))
	assert.True(t, cert.NotAfter.Before(time.Now().AddDate(0, 0, 1)))
}
