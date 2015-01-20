package entity

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"github.com/pki-io/pki.io/crypto"
)

func TestEntityNewDefault(t *testing.T) {
	entity, err := New(nil)
	assert.NoError(t, err)
	assert.NotNil(t, entity)
	assert.Equal(t, entity.Data.Scope, "pki.io")
}

func TestGenerateKeys(t *testing.T) {
	entity, _ := New(nil)
	entity.Data.Body.KeyType = string(crypto.KeyTypeRSA)
	err := entity.GenerateKeys()
	assert.NoError(t, err)
	assert.Equal(t, strings.Contains(entity.Data.Body.PublicSigningKey, "RSA PUBLIC KEY"), true)
	assert.Equal(t, strings.Contains(entity.Data.Body.PublicEncryptionKey, "RSA PUBLIC KEY"), true)

	entity.Data.Body.KeyType = string(crypto.KeyTypeEC)
	err = entity.GenerateKeys()
	assert.NoError(t, err)
	assert.Equal(t, strings.Contains(entity.Data.Body.PublicSigningKey, "ECDSA PUBLIC KEY"), true)
	assert.Equal(t, strings.Contains(entity.Data.Body.PublicEncryptionKey, "ECDSA PUBLIC KEY"), true)
}

func TestRSASignString(t *testing.T) {
	entity, _ := New(nil)
	entity.Data.Body.KeyType = string(crypto.KeyTypeRSA)
	entity.GenerateKeys()
	message := "this is a message"
	container, err := entity.SignString(message)
	assert.NoError(t, err)
	assert.Equal(t, container.Data.Body, message)
	assert.NotEqual(t, len(container.Data.Options.Signature), 0)
	assert.True(t, container.IsSigned())
}

func TestRSAVerify(t *testing.T) {
	entity, _ := New(nil)
	entity.Data.Body.KeyType = string(crypto.KeyTypeRSA)
	entity.GenerateKeys()
	container, _ := entity.SignString("this is a message")
	err := entity.Verify(container)
	assert.NoError(t, err)
}

func TestECSignString(t *testing.T) {
	entity, _ := New(nil)
	entity.Data.Body.KeyType = string(crypto.KeyTypeEC)
	entity.GenerateKeys()
	message := "this is a message"
	container, err := entity.SignString(message)
	assert.NoError(t, err)
	assert.Equal(t, container.Data.Body, message)
	assert.NotEqual(t, len(container.Data.Options.Signature), 0)
	assert.True(t, container.IsSigned())
}

func TestECVerify(t *testing.T) {
	entity, _ := New(nil)
	entity.Data.Body.KeyType = string(crypto.KeyTypeEC)
	entity.GenerateKeys()
	container, _ := entity.SignString("this is a message")
	err := entity.Verify(container)
	assert.NoError(t, err)
}
