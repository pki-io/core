package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOrgConfigNew(t *testing.T) {
	conf, err := NewOrg()
	assert.Nil(t, err)
	assert.NotNil(t, conf)
}

func TestOrgConfigDumpLoad(t *testing.T) {
	conf, _ := NewOrg()
	conf.Data.Name = "org1"
	conf.Data.Id = "123"
	configString, err := conf.Dump()
	assert.Nil(t, err)

	newConf, _ := NewOrg()
	err = newConf.Load(configString)
	assert.Nil(t, err)
	assert.Equal(t, conf.Data, newConf.Data)
}
