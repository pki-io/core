package tags

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTagsNew(t *testing.T) {
	tags, err := New(nil)
	assert.Nil(t, err)
	assert.NotNil(t, tags)
	assert.Equal(t, tags.Data.Scope, "pki.io")
}

func TestTagsDump(t *testing.T) {
	tags, _ := New(nil)
	tagsJson := tags.Dump()
	assert.NotEqual(t, len(tagsJson), 0)
}

func TestTagsAddCAString(t *testing.T) {
	tags, _ := New(nil)
	err := tags.AddCA("ca1", "tag1")
	assert.Nil(t, err)
}

func TestTagsAddCASlice(t *testing.T) {
	tags, _ := New(nil)
	inTags := []string{"tag1", "tag2"}
	err := tags.AddCA("ca2", inTags)
	assert.Nil(t, err)
}

func TestTagsAddEntityString(t *testing.T) {
	tags, _ := New(nil)
	err := tags.AddEntity("entity1", "tag1")
	assert.Nil(t, err)
}

func TestTagsAddEntitySlice(t *testing.T) {
	tags, _ := New(nil)
	inTags := []string{"tag1", "tag2"}
	err := tags.AddEntity("entity2", inTags)
	assert.Nil(t, err)
}

func TestTagsAdd(t *testing.T) {
	tags, _ := New(nil)
	inTags1 := []string{"tag1", "tag2"}
	inTags2 := []string{"tag2", "tag3"}
	err := tags.AddEntity("entity1", inTags1)
	assert.Nil(t, err)
	err = tags.AddEntity("entity2", inTags2)
	assert.Nil(t, err)
	err = tags.AddCA("ca1", inTags2)
	assert.Nil(t, err)
	err = tags.AddCA("ca2", inTags1)
	assert.Nil(t, err)
}
