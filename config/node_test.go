package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNodeConfigNew(t *testing.T) {
	conf, err := NewNode()
	assert.Nil(t, err)
	assert.NotNil(t, conf)
}

func TestNodeConfigDumpLoad(t *testing.T) {
	conf, _ := NewNode()
	conf.AddNode("node1", "000", "123")
	configString, err := conf.Dump()
	assert.Nil(t, err)

	newConf, _ := NewNode()
	err = newConf.Load(configString)
	assert.Nil(t, err)
	assert.Equal(t, conf.Data, newConf.Data)
}

func TestNodeConfigGetNode(t *testing.T) {
	conf, _ := NewNode()
	conf.AddNode("node1", "000", "111")
	node, err := conf.GetNode("node1")
	assert.Nil(t, err)
	assert.Equal(t, node.Name, "node1")
}
