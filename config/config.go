package config

import (
    "fmt"
    "os"
    "io/ioutil"
    "bytes"
    "github.com/BurntSushi/toml"
)

type OrgConfig struct {
    Name string `toml:"name"`
    Path string `toml:"path"`
}

type ConfigData struct {
    Org []OrgConfig `toml:"org"`
}

type Config struct {
    Path string
    Mode os.FileMode
    Data ConfigData
}

func New(path string) (*Config) {
    conf := new(Config)
    conf.Path = path
    conf.Mode = 0600
    conf.Data = ConfigData{}
    return conf
}

func (conf *Config) AddOrg(name string, path string) error {
    org := OrgConfig{Name: name, Path: path}
    conf.Data.Org = append(conf.Data.Org, org)
    return nil
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
    data := &ConfigData{}
    if _, err := toml.DecodeFile(conf.Path, data); err != nil {
        return fmt.Errorf("Could not decode file %s: %s", conf.Path, err.Error())
    }
    conf.Data = *data

    return nil
}
