package fs

import (
	"fmt"
	"github.com/pki-io/core/api"
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
	api.Api
}

func NewAPI(path string) (*Api, error) {
	fullPath := filepath.Join(path, pathRoot, apiVersion)
	if err := os.MkdirAll(fullPath, publicDirMode); err != nil {
		return nil, fmt.Errorf("Could not create path '%s': %s", fullPath, err)
	}
	api := new(Api)
	api.Path = fullPath
	return api, nil
}

func (api *Api) Connect(path string) error {
	fullPath := filepath.Join(path, pathRoot, apiVersion)
	if err := os.MkdirAll(fullPath, publicDirMode); err != nil {
		return fmt.Errorf("Could not create path '%s': %s", fullPath, err)
	}
	api.Path = fullPath
	return nil
}

func (api *Api) SendPublic(dstId string, name string, content string) error {
	path := filepath.Join(api.Path, dstId, publicPath)
	if err := os.MkdirAll(path, publicDirMode); err != nil {
		return fmt.Errorf("Could not create path '%s': %s", path, err)
	}
	filename := filepath.Join(path, name)
	if err := ioutil.WriteFile(filename, []byte(content), publicFileMode); err != nil {
		return fmt.Errorf("Could not write file '%s': %s", filename, err)
	}
	return nil
}

func (api *Api) GetPublic(dstId string, name string) (string, error) {
	filename := filepath.Join(api.Path, dstId, publicPath, name)
	if content, err := ReadFile(filename); err != nil {
		return "", fmt.Errorf("Could not read file '%s': %s", filename, err)
	} else {
		return string(content), nil
	}
}

func (api *Api) SendPrivate(dstId string, name string, content string) error {
	path := filepath.Join(api.Path, dstId, privatePath)
	if err := os.MkdirAll(path, privateDirMode); err != nil {
		return fmt.Errorf("Could not create path '%s': %s", path, err)
	}
	filename := filepath.Join(path, name)
	if err := ioutil.WriteFile(filename, []byte(content), privateFileMode); err != nil {
		return fmt.Errorf("Could not write file '%s': %s", filename, err)
	}
	return nil
}

func (api *Api) GetPrivate(dstId string, name string) (string, error) {
	filename := filepath.Join(api.Path, dstId, privatePath, name)
	if content, err := ReadFile(filename); err != nil {
		return "", fmt.Errorf("Could not read file '%s': %s", filename, err)
	} else {
		return string(content), nil
	}
}

func (api *Api) DeletePrivate(id, name string) error {
	filename := filepath.Join(api.Path, id, privatePath, name)

	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("Couldn't remove file: %s", err)
	}
	return nil
}

func (api *Api) Push(dstId, name, queue, content string) error {
	path := filepath.Join(api.Path, dstId, name, queue)

	if err := os.MkdirAll(path, privateDirMode); err != nil {
		return fmt.Errorf("Could not create path '%s': %s", path, err)
	}
	filename := filepath.Join(path, crypto.TimeOrderedUUID())
	if err := ioutil.WriteFile(filename, []byte(content), privateFileMode); err != nil {
		return fmt.Errorf("Could not write file '%s': %s", filename, err)
	}
	return nil
}

func (api *Api) PushIncoming(dstId, queue, content string) error {
	return api.Push(dstId, "incoming", queue, content)
}

func (api *Api) PushOutgoing(dstId, queue, content string) error {
	return api.Push(dstId, "outgoing", queue, content)
}

func (api *Api) Pop(srcId, name, queue string) (string, error) {
	pattern := filepath.Join(api.Path, srcId, name, queue, "*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("Could not glob files: %s", err)
	}

	if len(files) == 0 {
		return "", fmt.Errorf("Nothing to pop")
	}

	filename := files[0]
	if content, err := ReadFile(filename); err != nil {
		return "", fmt.Errorf("Could not read file '%s': %s", filename, err)
	} else {
		if err := os.Remove(filename); err != nil {
			return "", fmt.Errorf("Couldn't remove file: %s", err)
		} else {
			return string(content), nil
		}
	}
}

func (api *Api) PopOutgoing(srcId, queue string) (string, error) {
	return api.Pop(srcId, "outgoing", queue)
}

func (api *Api) PopIncoming(srcId, queue string) (string, error) {
	return api.Pop(srcId, "incoming", queue)
}

func (api *Api) Size(id, name, queue string) (int, error) {
	pattern := filepath.Join(api.Path, id, name, queue, "*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return 0, fmt.Errorf("Could not glob files: %s", err)
	}
	return len(files), nil
}

func (api *Api) OutgoingSize(id, queue string) (int, error) {
	return api.Size(id, "outgoing", queue)
}

func (api *Api) IncomingSize(id, queue string) (int, error) {
	return api.Size(id, "incoming", queue)
}

func (api *Api) Authenticate(id, key string) error {
	return nil
}
