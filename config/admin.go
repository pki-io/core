package config

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
)

type AdminOrgData struct {
	Name    string `toml:"name"`
	Id      string `toml:"id"`
	AdminId string `toml:"admin_id"`
}

type AdminConfigData struct {
	Org []AdminOrgData `toml:"org"`
}

type AdminConfig struct {
	Data AdminConfigData
}

func NewAdmin() (*AdminConfig, error) {
	conf := new(AdminConfig)
	conf.Data = AdminConfigData{}

	return conf, nil
}

func (conf *AdminConfig) Dump() (string, error) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(conf.Data); err != nil {
		return "", fmt.Errorf("Could not encode config: %s", err)
	}
	return string(buf.Bytes()), nil
}

func (conf *AdminConfig) Load(tomlString string) error {
	data := new(AdminConfigData)
	if _, err := toml.Decode(tomlString, data); err != nil {
		return fmt.Errorf("Could not decode config: %s", err)
	}
	conf.Data = *data
	return nil
}

func (conf *AdminConfig) AddOrg(name, id, adminId string) error {
	for _, org := range conf.Data.Org {
		if org.Name == name {
			return fmt.Errorf("Org '%s' already exists", name)
		}
	}
	conf.Data.Org = append(conf.Data.Org, AdminOrgData{name, id, adminId})
	return nil
}

func (conf *AdminConfig) GetOrg(name string) (*AdminOrgData, error) {
	for _, org := range conf.Data.Org {
		if org.Name == name {
			return &org, nil
		}
	}
	return nil, fmt.Errorf("Could not find org %s", name)
}

func (conf *AdminConfig) OrgExists(name string) bool {
	for _, org := range conf.Data.Org {
		if org.Name == name {
			return true
		}
	}
	return false
}
