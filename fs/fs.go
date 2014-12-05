package fs

import (
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
)

const publicFileMode os.FileMode = 0644
const publicDirMode os.FileMode = 0755
const privateFileMode os.FileMode = 0600
const privateDirMode os.FileMode = 0700

const publicPath string = "public"
const privatePath string = "private"

type FsAPI struct {
    Id string
    Name string
    Path string
}

func NewAPI(name string, path string) (*FsAPI, error ){
    return &FsAPI{Name: name, Path: path}, nil
}

func (fs *FsAPI) SendPublic(dstId string, name string, content string) error {
    path := filepath.Join(fs.Path, fs.Name, publicPath, dstId)
    if err := os.MkdirAll(path, publicDirMode); err != nil {
        return fmt.Errorf("Could not create path '%s': %s", path, err.Error())
    }
    filename := filepath.Join(path, name)
    if err := ioutil.WriteFile(filename, []byte(content), publicFileMode); err != nil {
        return fmt.Errorf("Could not write file '%s': %s", filename, err.Error())
    }
    return nil
}

func (fs *FsAPI) SendPrivate(dstId string, name string, content string) error {
    path := filepath.Join(fs.Path, fs.Name, privatePath, dstId)
    if err := os.MkdirAll(path, privateDirMode); err != nil {
        return fmt.Errorf("Could not create path '%s': %s", path, err.Error())
    }
    filename := filepath.Join(path, name)
    if err := ioutil.WriteFile(filename, []byte(content), privateFileMode); err != nil {
        return fmt.Errorf("Could not write file '%s': %s", filename, err.Error())
    }
    return nil
}

func (fs *FsAPI) StorePublic(name string, content string) error {
    if len(fs.Id) == 0 {
        return fmt.Errorf("Id cannot be empty")
    }
    return fs.SendPublic(fs.Id, name, content)
}

func (fs *FsAPI) StorePrivate(name string, content string) error {
    if len(fs.Id) == 0 {
        return fmt.Errorf("Id cannot be empty")
    }
    return fs.SendPrivate(fs.Id, name, content)
}

func (fs *FsAPI) Push() {

}

func (fs *FsAPI) Pop() {

}

