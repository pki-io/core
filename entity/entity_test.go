package entity

import (
	//"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestEntityNewDefault(t *testing.T) {
	entity, err := New(nil)
	assert.Nil(t, err)
	assert.NotNil(t, entity)
	assert.Equal(t, entity.Data.Scope, "pki.io")
}

func TestGenerateKeys(t *testing.T) {
	entity, _ := New(nil)
	err := entity.GenerateKeys()
	assert.Nil(t, err)
	assert.Equal(t, strings.Contains(entity.Data.Body.PublicSigningKey, "RSA PUBLIC KEY"), true)
	assert.Equal(t, strings.Contains(entity.Data.Body.PublicEncryptionKey, "RSA PUBLIC KEY"), true)
}

//func TestSignString(t *testing.T) {
//	entity, _ := New(nil)
//	entity.GenerateKeys()
//	message := "this is a message"
//	container, err := entity.SignString(message)
//	assert.Nil(t, err)
//	assert.Equal(t, container.Data.Body, message)
//	assert.NotEqual(t, len(container.Data.Options.Signature), 0)
//	assert.True(t, container.IsSigned())
//}

func TestVerify(t *testing.T) {
	entity, _ := New(nil)
	entity.GenerateKeys()
	container, _ := entity.SignString("this is a message")
	err := entity.Verify(container)
	assert.Nil(t, err)
}
