package config

import (
    //"fmt"
    //"strings"
    "os"
    "io/ioutil"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestGlobalConfigGlobal(t *testing.T) {
    conf := Global("abc")
    assert.NotNil(t, conf)
    assert.Equal(t, conf.Path, "abc")
}

func TestGlobalConfigAddOrg(t *testing.T) {
    conf := Global("abc")
    conf.AddOrg("hello", "somewhere")
    assert.Equal(t, conf.Data.Org[0].Name, "hello")
}

func TestGlobalConfigSaveLoad(t *testing.T) {
    file, _ := ioutil.TempFile(".", "xxx")
    filename := file.Name()
    file.Close()

    conf := Global(filename)
    conf.AddOrg("org1", "path1")
    conf.AddOrg("org2", "path2")
    conf.Save()

    assert.Equal(t, conf.Data.Org[0].Default, true)
    assert.Equal(t, conf.Data.Org[1].Default, false)

    newConf := Global(filename)
    err := newConf.Load()
    assert.Nil(t, err)
    assert.Equal(t, conf, newConf)
    os.Remove(filename)
}

func TestGlobalLoadNoFile(t *testing.T) {
    filename := "does_not_exist"

    confGlobal := Global(filename)
    conf := Global(filename)
    err := conf.Load()
    assert.Nil(t, err)
    assert.Equal(t, confGlobal, conf)
}
