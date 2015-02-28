package fs

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLocalNew(t *testing.T) {
	local, err := NewLocal("")
	assert.Nil(t, err)
	assert.NotNil(t, local)
}

func TestLocalWriteExistsReadDelete(t *testing.T) {
	local, _ := NewLocal("")
	file := "test"
	content := "testing"
	err := local.Write(file, content)
	assert.Nil(t, err)
	exists, err := local.Exists(file)
	assert.Nil(t, err)
	assert.True(t, exists)
	newContent, err := local.Read(file)
	assert.Nil(t, err)
	assert.Equal(t, content, newContent)
	err = local.Delete(file)
	assert.Nil(t, err)
}
