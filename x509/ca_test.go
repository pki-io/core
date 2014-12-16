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
	err := ca.GenerateRoot(time.Now(), time.Now().AddDate(5, 5, 5))
	assert.Nil(t, err)
	assert.NotEqual(t, ca.Data.Body.Certificate, "")
}

func TestX509CAGenerateSub(t *testing.T) {
	rootCA, _ := NewCA(nil)
	rootCA.Data.Body.Name = "RootCA"
	rootCA.Data.Body.DNScope.Country = "UK"
	rootCA.Data.Body.DNScope.Organization = "pki.io"
	rootCA.GenerateRoot(time.Now(), time.Now().AddDate(5, 5, 5))

	subCA, _ := NewCA(nil)
	subCA.Data.Body.Name = "DevCA"
	subCA.Data.Body.DNScope.OrganizationalUnit = "Development"
	err := subCA.GenerateSub(rootCA, time.Now(), time.Now().AddDate(5, 5, 1))

	assert.Nil(t, err)
	assert.NotEqual(t, subCA.Data.Body.Certificate, "")
}
