package fs

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHomeNew(t *testing.T) {
	home, err := NewHome("")
	assert.Nil(t, err)
	assert.NotNil(t, home)
}

func TestHomeWriteExistsReadDelete(t *testing.T) {
	home, _ := NewHome("")
	file := "test"
	content := "testing"
	err := home.Write(file, content)
	assert.Nil(t, err)
	exists, err := home.Exists(file)
	assert.Nil(t, err)
	assert.True(t, exists)
	newContent, err := home.Read(file)
	assert.Nil(t, err)
	assert.Equal(t, content, newContent)
	err = home.Delete(file)
	assert.Nil(t, err)
}
