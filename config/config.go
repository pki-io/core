package config

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
	"io/ioutil"
	"os"
)

type OrgData struct {
	Name string `toml:"name"`
	Id   string `toml:"id"`
}

type AdminData struct {
	Name string `toml:"name"`
	Id   string `toml:"id"`
}

type NodeData struct {
	Name string `toml:"name"`
	Id   string `toml:"id"`
}

type ConfigData struct {
	Org    OrgData     `toml:"org"`
	Admins []AdminData `toml:"admin"`
	Nodes  []NodeData  `toml:"node"`
}

type Config struct {
	Path string
	Mode os.FileMode
	Data ConfigData
}

func New(path string) *Config {
	conf := new(Config)
	conf.Path = path
	conf.Mode = 0600
	conf.Data = ConfigData{}
	return conf
}

func (conf *Config) Exists() (bool, error) {
	if f, err := os.Open(conf.Path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		} else {
			return false, err
		}
	} else {
		f.Close()
		return true, nil
	}
}

func (conf *Config) Create() error {
	exists, err := conf.Exists()
	if err != nil {
		return fmt.Errorf("Could not open file %s: %s", conf.Path, err.Error())
	}

	if exists {
		return fmt.Errorf("Config file already exists")
	} else {
		return conf.Save()
	}
}

func (conf *Config) Save() error {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(conf.Data); err != nil {
		return fmt.Errorf("Could not encode config: %s", err.Error())
	}
	if err := ioutil.WriteFile(conf.Path, buf.Bytes(), conf.Mode); err != nil {
		return fmt.Errorf("Could not write config file: %s", err.Error())
	}
	return nil
}

func (conf *Config) Load() error {
	exists, err := conf.Exists()
	if err != nil {
		return fmt.Errorf("Could not open file %s: %s", conf.Path, err.Error())
	}

	if exists {
		data := new(ConfigData)
		if _, err := toml.DecodeFile(conf.Path, data); err != nil {
			return fmt.Errorf("Could not decode file %s: %s", conf.Path, err.Error())
		}
		conf.Data = *data
		return nil
	} else {
		return fmt.Errorf("Could not load config. File %s does not exist", conf.Path)
	}
}

func (conf *Config) AddOrg(name, id string) {
	conf.Data.Org = OrgData{name, id}
}

func (conf *Config) AddAdmin(name, id string) {
	conf.Data.Admins = append(conf.Data.Admins, AdminData{name, id})
}

func (conf *Config) AddNode(name, id string) {
	conf.Data.Nodes = append(conf.Data.Nodes, NodeData{name, id})
}
