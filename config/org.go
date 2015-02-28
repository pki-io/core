package config

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
)

const orgFile string = "org.conf"

type OrgConfigData struct {
	Name  string `toml:"name"`
	Id    string `toml:"id"`
	Index string `toml:"index"`
}

type OrgConfig struct {
	Data OrgConfigData
}

func NewOrg() (*OrgConfig, error) {
	conf := new(OrgConfig)
	conf.Data = OrgConfigData{}
	return conf, nil
}

func (conf *OrgConfig) Dump() (string, error) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(conf.Data); err != nil {
		return "", fmt.Errorf("Could not encode config: %s", err)
	}
	return string(buf.Bytes()), nil
}

func (conf *OrgConfig) Load(tomlString string) error {
	data := new(OrgConfigData)

	if _, err := toml.Decode(tomlString, data); err != nil {
		return fmt.Errorf("Could not decode config: %s", err)
	}
	conf.Data = *data
	return nil
}
