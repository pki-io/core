package x509

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestX509NewCSR(t *testing.T) {
    csr, err := NewCSR(nil)
    assert.Nil(t, err)
    assert.NotNil(t, csr)
    assert.Equal(t, csr.Data.Scope, "pki.io")
}

func TestX509CSRDump(t *testing.T) {
    csr, _ := NewCSR(nil)
    csrJson := csr.Dump()
    assert.NotEqual(t, len(csrJson), 0)
}

func TestX509CSRGenerate(t *testing.T) {
    csr, _ := NewCSR(nil)
    err := csr.Generate()
    assert.Nil(t, err)
    assert.NotEqual(t, csr.Data.Body.CSR, "")
}

func TestX509CSRPublic(t *testing.T) {
    csr, _ := NewCSR(nil)
    csr.Generate()
    publicCSR, err := csr.Public()
    assert.Nil(t, err)
    assert.Equal(t, csr.Data.Body.CSR, publicCSR.Data.Body.CSR)
    assert.Equal(t, publicCSR.Data.Body.PrivateKey, "")
}
