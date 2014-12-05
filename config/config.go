package config

import (
    "fmt"
    "os"
    "io/ioutil"
    "bytes"
    "github.com/BurntSushi/toml"
)

type orgConfig struct {
    Name string
    Path string
}

type ConfigData struct {
    Org []orgConfig
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
    org := orgConfig{Name: name, Path: path}
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
    content, err := ioutil.ReadFile(conf.Path)
    if err != nil {
        return fmt.Errorf("Could not read config file: %s", err.Error())
    }

    if _, err := toml.Decode(string(content), conf.Data); err != nil {
        return fmt.Errorf("Could not decode config: %s", err.Error())
    }

    return nil
}
