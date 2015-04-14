package fs

import (
	"fmt"
	"github.com/pki-io/core/crypto"
	"io/ioutil"
	"os"
	"path/filepath"
)

const apiVersion string = "v0"
const pathRoot string = "api"
const publicPath string = "public"
const privatePath string = "private"

type Api struct {
	Id   string
	Path string
}

func NewAPI(path string) (*Api, error) {
	fullPath := filepath.Join(path, pathRoot, apiVersion)
	if err := os.MkdirAll(fullPath, publicDirMode); err != nil {
		return nil, fmt.Errorf("Could not create path '%s': %s", fullPath, err)
	}
	return &Api{Path: fullPath}, nil
}

func (fs *Api) SendPublic(dstId string, name string, content string) error {
	path := filepath.Join(fs.Path, dstId, publicPath)
	if err := os.MkdirAll(path, publicDirMode); err != nil {
		return fmt.Errorf("Could not create path '%s': %s", path, err)
	}
	filename := filepath.Join(path, name)
	if err := ioutil.WriteFile(filename, []byte(content), publicFileMode); err != nil {
		return fmt.Errorf("Could not write file '%s': %s", filename, err)
	}
	return nil
}

func (fs *Api) GetPublic(dstId string, name string) (string, error) {
	filename := filepath.Join(fs.Path, dstId, publicPath, name)
	if content, err := ioutil.ReadFile(filename); err != nil {
		return "", fmt.Errorf("Could not read file '%s': %s", filename, err)
	} else {
		return string(content), nil
	}
}

func (fs *Api) SendPrivate(dstId string, name string, content string) error {
	path := filepath.Join(fs.Path, dstId, privatePath)
	if err := os.MkdirAll(path, privateDirMode); err != nil {
		return fmt.Errorf("Could not create path '%s': %s", path, err)
	}
	filename := filepath.Join(path, name)
	if err := ioutil.WriteFile(filename, []byte(content), privateFileMode); err != nil {
		return fmt.Errorf("Could not write file '%s': %s", filename, err)
	}
	return nil
}

func (fs *Api) GetPrivate(dstId string, name string) (string, error) {
	filename := filepath.Join(fs.Path, dstId, privatePath, name)
	if content, err := ioutil.ReadFile(filename); err != nil {
		return "", fmt.Errorf("Could not read file '%s': %s", filename, err)
	} else {
		return string(content), nil
	}
}

func (fs *Api) StorePublic(name string, content string) error {
	if len(fs.Id) == 0 {
		return fmt.Errorf("Id cannot be empty")
	}
	return fs.SendPublic(fs.Id, name, content)
}

func (fs *Api) LoadPublic(name string) (string, error) {
	if len(fs.Id) == 0 {
		return "", fmt.Errorf("Id cannot be empty")
	}
	return fs.GetPublic(fs.Id, name)
}

func (fs *Api) StorePrivate(name string, content string) error {
	if len(fs.Id) == 0 {
		return fmt.Errorf("Id cannot be empty")
	}
	return fs.SendPrivate(fs.Id, name, content)
}

func (fs *Api) DeletePrivate(name string) error {
	if len(fs.Id) == 0 {
		return fmt.Errorf("Id cannot be empty")
	}

	filename := filepath.Join(fs.Path, fs.Id, privatePath, name)

	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("Couldn't remove file: %s", err)
	}
	return nil
}

func (fs *Api) LoadPrivate(name string) (string, error) {
	if len(fs.Id) == 0 {
		return "", fmt.Errorf("Id cannot be empty")
	}
	return fs.GetPrivate(fs.Id, name)
}

func (fs *Api) Push(dstId, name, queue, content string) error {
	path := filepath.Join(fs.Path, dstId, name, queue)

	if err := os.MkdirAll(path, privateDirMode); err != nil {
		return fmt.Errorf("Could not create path '%s': %s", path, err)
	}
	filename := filepath.Join(path, crypto.TimeOrderedUUID())
	if err := ioutil.WriteFile(filename, []byte(content), privateFileMode); err != nil {
		return fmt.Errorf("Could not write file '%s': %s", filename, err)
	}
	return nil
}

func (fs *Api) PushIncoming(dstId, queue, content string) error {
	return fs.Push(dstId, "incoming", queue, content)
}

func (fs *Api) PushOutgoing(queue, content string) error {
	if 0 == len(fs.Id) {
		return fmt.Errorf("Id cannot be empty")
	}
	return fs.Push(fs.Id, "outgoing", queue, content)
}

func (fs *Api) Pop(srcId, name, queue string) (string, error) {
	pattern := filepath.Join(fs.Path, srcId, name, queue, "*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("Could not glob files: %s", err)
	}

	if len(files) == 0 {
		return "", fmt.Errorf("Nothing to pop")
	}

	filename := files[0]
	if content, err := ioutil.ReadFile(filename); err != nil {
		return "", fmt.Errorf("Could not read file '%s': %s", filename, err)
	} else {
		if err := os.Remove(filename); err != nil {
			return "", fmt.Errorf("Couldn't remove file: %s", err)
		} else {
			return string(content), nil
		}
	}
}

func (fs *Api) PopIncoming(queue string) (string, error) {
	if 0 == len(fs.Id) {
		return "", fmt.Errorf("Id cannot be empty")
	}
	return fs.Pop(fs.Id, "incoming", queue)
}

func (fs *Api) PopOutgoing(srcId, queue string) (string, error) {
	return fs.Pop(srcId, "outgoing", queue)
}

func (fs *Api) Size(id, name, queue string) (int, error) {
	pattern := filepath.Join(fs.Path, id, name, queue, "*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return 0, fmt.Errorf("Could not glob files: %s", err)
	}
	return len(files), nil
}

func (fs *Api) IncomingSize(queue string) (int, error) {
	if 0 == len(fs.Id) {
		return 0, fmt.Errorf("Id cannot be empty")
	}
	return fs.Size(fs.Id, "incoming", queue)
}

func (fs *Api) OutgoingSize(id, queue string) (int, error) {
	return fs.Size(id, "outgoing", queue)
}

func (fs *Api) Authenticate(id, key string) error {
	fs.Id = id
	return nil
}
