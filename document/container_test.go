package document

import (
	"encoding/hex"
	"github.com/pki-io/core/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewContainer(t *testing.T) {
	container, err := NewContainer(nil)
	assert.Nil(t, err)
	assert.NotNil(t, container)
	assert.Equal(t, container.Data.Type, "container")
}

func TestSymmetricEncryptDecrypt(t *testing.T) {
	rawId, _ := crypto.RandomBytes(16)
	rawKey, _ := crypto.RandomBytes(16)

	id := hex.EncodeToString(rawId)
	key := hex.EncodeToString(rawKey)

	container, _ := NewContainer(nil)
	message := "this is a secret"
	err := container.SymmetricEncrypt(message, id, key)
	assert.Nil(t, err)

	newMessage, err := container.SymmetricDecrypt(key)
	assert.Nil(t, err)
	assert.NotNil(t, newMessage)
	assert.Equal(t, newMessage, message)
}
