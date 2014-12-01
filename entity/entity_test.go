package entity

import (
    //"fmt"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestEntityNewDefault(t *testing.T) {
    entity, err := New(nil)
    assert.Nil(t, err)
    assert.NotNil(t, entity)
    assert.Equal(t, entity.Data.Scope, "pki.io")
}

func TestGenerateKeys(t *testing.T) {
    entity, err := New(nil)
    entity.GenerateKeys()
    assert.Nil(t, err)
    assert.NotNil(t, entity.Data.Body.PublicSigningKey)
}
