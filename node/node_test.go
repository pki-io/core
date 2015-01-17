package node

import (
	"encoding/hex"
	//"fmt"
	"github.com/mitchellh/packer/common/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/pki-io/pki.io/crypto"
	"testing"
)

func TestNodeNew(t *testing.T) {
	node, err := New(nil)
	assert.Nil(t, err)
	assert.NotNil(t, node)
	assert.Equal(t, node.Data.Scope, "pki.io")
}

func TestNodeNewRegistration(t *testing.T) {
	reg, err := NewRegistration(nil)
	assert.Nil(t, err)
	assert.NotNil(t, reg)
}

func TestNodeRegistrationAuthenticate(t *testing.T) {
	reg, _ := NewRegistration(nil)
	pairingId := uuid.TimeOrderedUUID()
	pairingKey := hex.EncodeToString(crypto.RandomBytes(16))
	err := reg.Authenticate(pairingId, pairingKey)
	assert.Nil(t, err)
	assert.NotEqual(t, reg.Data.Options.Signature, "")
	assert.NotEqual(t, reg.Data.Options.SignatureSalt, "")
}
