package index

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNodeIndexNew(t *testing.T) {
	index, err := NewNode(nil)
	assert.Nil(t, err)
	assert.NotNil(t, index)
	assert.Equal(t, index.Data.Scope, "pki.io")
}

func TestNodeIndexDump(t *testing.T) {
	index, _ := NewNode(nil)
	indexJson := index.Dump()
	assert.NotEqual(t, len(indexJson), 0)
}

func TestNodeIndexAddCertTagsString(t *testing.T) {
	index, _ := NewNode(nil)
	err := index.AddCertTags("cert1", "tag1")
	assert.Nil(t, err)
}

func TestNodeIndexAddCertTagsSlice(t *testing.T) {
	index, _ := NewNode(nil)
	inIndex := []string{"tag1", "tag2"}
	err := index.AddCertTags("cert2", inIndex)
	assert.Nil(t, err)
}

func TestNodeIndexAddTags(t *testing.T) {
	index, _ := NewNode(nil)
	inTags1 := []string{"tag1", "tag2"}
	inTags2 := []string{"tag2", "tag3"}
	err := index.AddCertTags("cert1", inTags2)
	assert.Nil(t, err)
	err = index.AddCertTags("cert2", inTags1)
	assert.Nil(t, err)
}
