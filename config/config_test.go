package config

import (
    //"fmt"
    //"strings"
    "os"
    "io/ioutil"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestConfigNew(t *testing.T) {
    conf := New("abc")
    assert.NotNil(t, conf)
    assert.Equal(t, conf.Path, "abc")
}

func TestConfigSaveLoad(t *testing.T) {
    file, _ := ioutil.TempFile(".", "xxx")
    filename := file.Name()
    file.Close()

    conf := New(filename)
    conf.Data.OrgId = "123"
    conf.Data.AdminId = "456"
    conf.Save()

    newConf := New(filename)
    err := newConf.Load()
    assert.Nil(t, err)
    assert.Equal(t, conf, newConf)
    os.Remove(filename)
}

func TestConfigLoadNoFile(t *testing.T) {
    conf := New("does_not_exist")
    err := conf.Load()
    assert.NotNil(t, err)
}
