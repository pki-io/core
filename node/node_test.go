package node

import (
	//"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNodeNew(t *testing.T) {
	node, err := New(nil)
	assert.Nil(t, err)
	assert.NotNil(t, node)
	assert.Equal(t, node.Data.Type, "entity-document")
}
