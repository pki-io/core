package fs

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

// Need teardown function to clean up dir

func TestFSNewAPI(t *testing.T) {
	currentDir, _ := os.Getwd()
	fs, err := NewAPI(currentDir, "fs-test")
	assert.Nil(t, err)
	assert.NotNil(t, fs)
}

func TestFSPushPop(t *testing.T) {
	currentDir, _ := os.Getwd()
	fs, _ := NewAPI(currentDir, "fs-test")
	fs.Id = "123"
	err := fs.Push("this is a test")
	assert.Nil(t, err)
	content, err := fs.Pop()
	assert.Nil(t, err)
	assert.Equal(t, content, "this is a test")
}
