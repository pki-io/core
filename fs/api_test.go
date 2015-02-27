package fs

import (
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

// Need teardown function to clean up dir

func TestFSNewAPI(t *testing.T) {
	currentDir, _ := os.Getwd()
	path := filepath.Join(currentDir, "fs-test")
	fs, err := NewAPI(path)
	assert.Nil(t, err)
	assert.NotNil(t, fs)
}

func TestFSPushPopIncoming(t *testing.T) {
	currentDir, _ := os.Getwd()
	path := filepath.Join(currentDir, "fs-test")
	fs, err := NewAPI(path)
	fs.Id = "123"
	err = fs.PushIncoming(fs.Id, "test", "this is a test")
	assert.Nil(t, err)
	content, err := fs.PopIncoming("test")
	assert.Nil(t, err)
	assert.Equal(t, content, "this is a test")
}

func TestFSPushPopOutgoing(t *testing.T) {
	currentDir, _ := os.Getwd()
	path := filepath.Join(currentDir, "fs-test")
	fs, err := NewAPI(path)
	fs.Id = "123"
	err = fs.PushOutgoing("test", "this is a test")
	assert.Nil(t, err)
	content, err := fs.PopOutgoing(fs.Id, "test")
	assert.Nil(t, err)
	assert.Equal(t, content, "this is a test")
}

func TestFSIncomingSize(t *testing.T) {
	currentDir, _ := os.Getwd()
	path := filepath.Join(currentDir, "fs-test")
	fs, err := NewAPI(path)
	fs.Id = "123"
	fs.PushIncoming(fs.Id, "test", "this is a test")
	size, err := fs.IncomingSize("test")
	assert.Nil(t, err)
	assert.NotEqual(t, size, 0)
}
