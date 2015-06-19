package fs

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"io/ioutil"
	"os"
	"path/filepath"
)

const homePath string = ".pki.io"

type Home struct {
	Path string
}

func NewHome(path string) (*Home, error) {
	home := new(Home)
	var homeDir string
	var err error
	if path == "" {
		homeDir, err = homedir.Dir()
		if err != nil {
			return nil, fmt.Errorf("Couldn't get home directory: %s", err)
		}
	} else {
		homeDir = path
	}

	home.Path = filepath.Join(homeDir, homePath)

	if err := os.MkdirAll(home.Path, privateDirMode); err != nil {
		return nil, fmt.Errorf("Could not create path: %s", err)
	}
	return home, nil
}

func (home *Home) FullPath(name string) string {
	return filepath.Join(home.Path, name)
}

func (home *Home) Write(name, content string) error {
	if err := ioutil.WriteFile(home.FullPath(name), []byte(content), privateFileMode); err != nil {
		return fmt.Errorf("Could not write file: %s", err)
	}
	return nil
}

func (home *Home) Read(name string) (string, error) {
	if content, err := ReadFile(home.FullPath(name)); err != nil {
		return "", fmt.Errorf("Could not read file: %s", err)
	} else {
		return string(content), nil
	}
}

func (home *Home) Exists(name string) (bool, error) {
	return Exists(filepath.Join(home.Path, name))
}

func (home *Home) Delete(name string) error {
	exists, err := home.Exists(name)
	if err != nil {
		return fmt.Errorf("Couldn't check file existence for %s: %s", name, err)
	}

	if exists {
		if err := os.Remove(home.FullPath(name)); err != nil {
			return fmt.Errorf("Couldn't delete config file: %s", err)
		} else {
			return nil

		}
	} else {
		return nil
	}
}
