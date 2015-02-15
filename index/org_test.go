package index

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOrgIndexNew(t *testing.T) {
	index, err := NewOrg(nil)
	assert.Nil(t, err)
	assert.NotNil(t, index)
	assert.Equal(t, index.Data.Scope, "pki.io")
}

func TestOrgIndexDump(t *testing.T) {
	index, _ := NewOrg(nil)
	indexJson := index.Dump()
	assert.NotEqual(t, len(indexJson), 0)
}

func TestOrgIndexAddCATagsString(t *testing.T) {
	index, _ := NewOrg(nil)
	err := index.AddCATags("ca1", "tag1")
	assert.Nil(t, err)
}

func TestOrgIndexAddCATagsSlice(t *testing.T) {
	index, _ := NewOrg(nil)
	inIndex := []string{"tag1", "tag2"}
	err := index.AddCATags("ca2", inIndex)
	assert.Nil(t, err)
}

func TestOrgIndexAddEntityTagsString(t *testing.T) {
	index, _ := NewOrg(nil)
	err := index.AddEntityTags("entity1", "tag1")
	assert.Nil(t, err)
}

func TestOrgIndexAddEntityTagsSlice(t *testing.T) {
	index, _ := NewOrg(nil)
	inIndex := []string{"tag1", "tag2"}
	err := index.AddEntityTags("entity2", inIndex)
	assert.Nil(t, err)
}

func TestOrgIndexAddTags(t *testing.T) {
	index, _ := NewOrg(nil)
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

func TestOrgIndexAddPairingKey(t *testing.T) {
	index, _ := NewOrg(nil)
	id := "123"
	key := "abc"
	tags := []string{"tag1", "tag2"}
	err := index.AddPairingKey(id, key, tags)
	assert.Nil(t, err)
}
