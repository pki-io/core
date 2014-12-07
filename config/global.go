package config

import (
    "fmt"
    "os"
    "io/ioutil"
    "bytes"
    "github.com/BurntSushi/toml"
)

type GlobalOrgConfig struct {
    Name string `toml:"name"`
    Path string `toml:"path"`
    Default bool `toml:"default"`
}

type GlobalData struct {
    Org []GlobalOrgConfig `toml:"org"`
}

type GlobalConfig struct {
    Path string
    Mode os.FileMode
    Data GlobalData
}

func Global(path string) (*GlobalConfig) {
    conf := new(GlobalConfig)
    conf.Path = path
    conf.Mode = 0600
    conf.Data = GlobalData{}
    return conf
}

func (conf *GlobalConfig) AddOrg(name string, path string) error {
    org := GlobalOrgConfig{Name: name, Path: path}
    if len(conf.Data.Org) == 0 {
        org.Default = true
    }
    conf.Data.Org = append(conf.Data.Org, org)
    return nil
}

func (conf *GlobalConfig) Save() error {
    buf := new(bytes.Buffer)
    if err := toml.NewEncoder(buf).Encode(conf.Data); err != nil {
        return fmt.Errorf("Could not encode config: %s", err.Error())
    }
    if err := ioutil.WriteFile(conf.Path, buf.Bytes(), conf.Mode); err != nil {
        return fmt.Errorf("Could not write config file: %s", err.Error())
    }
    return nil
}

func (conf *GlobalConfig) Load() error {
    exists, err := Exists(conf.Path)
    if err != nil {
        return fmt.Errorf("Could not open file %s: %s", conf.Path, err.Error())
    }

    if exists {
        data := new(GlobalData)
        if _, err := toml.DecodeFile(conf.Path, data); err != nil {
            return fmt.Errorf("Could not decode file %s: %s", conf.Path, err.Error())
        }
        conf.Data = *data
    }

    return nil
}
