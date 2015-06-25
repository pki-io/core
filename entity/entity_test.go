package entity

import (
	"encoding/hex"
	"github.com/pki-io/core/crypto"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
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
	assert.Equal(t, strings.Contains(entity.Data.Body.PublicSigningKey, "EC PUBLIC KEY"), true)
	assert.Equal(t, strings.Contains(entity.Data.Body.PublicEncryptionKey, "EC PUBLIC KEY"), true)
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

func TestAuthentication(t *testing.T) {
	entity, _ := New(nil)
	id := crypto.UUID()
	keyBytes, _ := crypto.RandomBytes(16)
	key := hex.EncodeToString(keyBytes)

	message := "this is a message"
	container, err := entity.AuthenticateString(message, id, key)
	assert.NoError(t, err)
	assert.Equal(t, container.Data.Body, message)
	assert.NotEqual(t, len(container.Data.Options.Signature), 0)
	assert.True(t, container.IsSigned())
}

func TestVerifyAuthentication(t *testing.T) {
	entity, _ := New(nil)
	id := crypto.UUID()
	keyBytes, _ := crypto.RandomBytes(16)
	key := hex.EncodeToString(keyBytes)
	message := "this is a message"
	container, err := entity.AuthenticateString(message, id, key)

	err = entity.VerifyAuthentication(container, key)
	assert.NoError(t, err)
}
