package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAdminConfigNew(t *testing.T) {
	conf, err := NewAdmin()
	assert.Nil(t, err)
	assert.NotNil(t, conf)
}

func TestAdminConfigDumpLoad(t *testing.T) {
	conf, _ := NewAdmin()
	conf.AddOrg("org1", "000", "123")
	configString, err := conf.Dump()
	assert.Nil(t, err)

	newConf, _ := NewAdmin()
	err = newConf.Load(configString)
	assert.Nil(t, err)
	assert.Equal(t, conf.Data, newConf.Data)
}

func TestAdminDuplicateOrg(t *testing.T) {
	conf, _ := NewAdmin()
	err := conf.AddOrg("org1", "000", "123")
	assert.NoError(t, err)
	err = conf.AddOrg("org1", "666", "777")
	assert.Error(t, err)
}

func TestAdminConfigGetOrg(t *testing.T) {
	conf, _ := NewAdmin()
	conf.AddOrg("org1", "000", "111")
	org, err := conf.GetOrg("org1")
	assert.Nil(t, err)
	assert.Equal(t, org.Name, "org1")
}
