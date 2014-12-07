package config

import (
    //"fmt"
    //"strings"
    "os"
    "io/ioutil"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestOrgConfigOrg(t *testing.T) {
    conf := Org("abc")
    assert.NotNil(t, conf)
    assert.Equal(t, conf.Path, "abc")
}

func TestOrgConfigSaveLoad(t *testing.T) {
    file, _ := ioutil.TempFile(".", "xxx")
    filename := file.Name()
    file.Close()

    conf := Org(filename)
    conf.Data.OrgId = "123"
    conf.Data.AdminId = "456"
    conf.Save()

    newConf := Org(filename)
    err := newConf.Load()
    assert.Nil(t, err)
    assert.Equal(t, conf, newConf)
    os.Remove(filename)
}

func TestOrgLoadNoFile(t *testing.T) {
    filename := "does_not_exist"

    confNew := Org(filename)
    conf := Org(filename)
    err := conf.Load()
    assert.Nil(t, err)
    assert.Equal(t, confNew, conf)
}
