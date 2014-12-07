package config

import (
    "fmt"
    "os"
    "io/ioutil"
    "bytes"
    "github.com/BurntSushi/toml"
)

type OrgData struct {
    OrgId string `toml:"org_id"`
    AdminId string `toml:"admin_id"`
}

type OrgConfig struct {
    Path string
    Mode os.FileMode
    Data OrgData
}

func Org(path string) (*OrgConfig) {
    conf := new(OrgConfig)
    conf.Path = path
    conf.Mode = 0600
    conf.Data = OrgData{}
    return conf
}

func (conf *OrgConfig) Save() error {
    buf := new(bytes.Buffer)
    if err := toml.NewEncoder(buf).Encode(conf.Data); err != nil {
        return fmt.Errorf("Could not encode config: %s", err.Error())
    }
    if err := ioutil.WriteFile(conf.Path, buf.Bytes(), conf.Mode); err != nil {
        return fmt.Errorf("Could not write config file: %s", err.Error())
    }
    return nil
}

func (conf *OrgConfig) Load() error {
    exists, err := Exists(conf.Path)
    if err != nil {
        return fmt.Errorf("Could not open file %s: %s", conf.Path, err.Error())
    }

    if exists {
        data := new(OrgData)
        if _, err := toml.DecodeFile(conf.Path, data); err != nil {
            return fmt.Errorf("Could not decode file %s: %s", conf.Path, err.Error())
        }
        conf.Data = *data
    }

    return nil
}
