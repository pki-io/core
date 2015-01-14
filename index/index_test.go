package index

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIndexNew(t *testing.T) {
	index, err := New(nil)
	assert.Nil(t, err)
	assert.NotNil(t, index)
	assert.Equal(t, index.Data.Scope, "pki.io")
}

func TestIndexDump(t *testing.T) {
	index, _ := New(nil)
	indexJson := index.Dump()
	assert.NotEqual(t, len(indexJson), 0)
}

func TestIndexAddCATagsString(t *testing.T) {
	index, _ := New(nil)
	err := index.AddCATags("ca1", "tag1")
	assert.Nil(t, err)
}

func TestIndexAddCATagsSlice(t *testing.T) {
	index, _ := New(nil)
	inIndex := []string{"tag1", "tag2"}
	err := index.AddCATags("ca2", inIndex)
	assert.Nil(t, err)
}

func TestIndexAddEntityTagsString(t *testing.T) {
	index, _ := New(nil)
	err := index.AddEntityTags("entity1", "tag1")
	assert.Nil(t, err)
}

func TestIndexAddEntityTagsSlice(t *testing.T) {
	index, _ := New(nil)
	inIndex := []string{"tag1", "tag2"}
	err := index.AddEntityTags("entity2", inIndex)
	assert.Nil(t, err)
}

func TestIndexAddTags(t *testing.T) {
	index, _ := New(nil)
	inTags1 := []string{"tag1", "tag2"}
	inTags2 := []string{"tag2", "tag3"}
	err := index.AddEntityTags("entity1", inTags1)
	assert.Nil(t, err)
	err = index.AddEntityTags("entity2", inTags2)
	assert.Nil(t, err)
	err = index.AddCATags("ca1", inTags2)
	assert.Nil(t, err)
	err = index.AddCATags("ca2", inTags1)
	assert.Nil(t, err)
}

func TestAddPairingKey(t *testing.T) {
	index, _ := New(nil)
	id := "123"
	key := "abc"
	tags := []string{"tag1", "tag2"}
	err := index.AddPairingKey(id, key, tags)
	assert.Nil(t, err)
}
