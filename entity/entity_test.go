package entity

import (
    //"fmt"
    "strings"
    "testing"
    "github.com/stretchr/testify/assert")

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
