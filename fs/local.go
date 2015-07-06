// ThreatSpec package github.com/pki-io/core/fs as fs
package fs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Local struct {
	Path string
}

// ThreatSpec TMv0.1 for NewLocal
// Creates new local environment for App:FileSystem

func NewLocal(path string) (*Local, error) {
	local := new(Local)

	var currentDir string
	var err error
	if path == "" {
		currentDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("Couldn't get current directory: %s", err)
		}
	} else {
		currentDir = path
	}
	local.Path = currentDir
	return local, nil
}

// ThreatSpec TMv0.1 for Local.CreateDirectory
// Creates filesystem directory for App:FileSystem
// Sends mkdir from App:FileSystem to OS:FileSystem

func (local *Local) CreateDirectory(dir string) error {
	if err := os.MkdirAll(filepath.Join(local.Path, dir), privateDirMode); err != nil {
		return fmt.Errorf("Could not create path: %s", err)
	}
	return nil
}

// ThreatSpec TMv0.1 for Local.ChangeToDirectiory
// Does a change of working directory for App:FileSystem

func (local *Local) ChangeToDirectory(dir string) error {
	local.Path = filepath.Join(local.Path, dir)
	return nil
}

// ThreatSpec TMv0.1 for Local.FullPath
// Returns full local path for App:FileSystem

func (local *Local) FullPath(name string) string {
	return filepath.Join(local.Path, name)
}

func (local *Local) Write(name, content string) error {
	if err := ioutil.WriteFile(local.FullPath(name), []byte(content), privateFileMode); err != nil {
		return fmt.Errorf("Could not write file: %s", err)
	}
	return nil
}

func (local *Local) Read(name string) (string, error) {
	if content, err := ReadFile(local.FullPath(name)); err != nil {
		return "", fmt.Errorf("Could not read file: %s", err)
	} else {
		return string(content), nil
	}
}

func (local *Local) Exists(name string) (bool, error) {
	return Exists(filepath.Join(local.Path, name))
}

func (local *Local) Delete(name string) error {
	exists, err := local.Exists(name)
	if err != nil {
		return fmt.Errorf("Couldn't check file existence for %s: %s", name, err)
	}

	if exists {
		if err := os.Remove(local.FullPath(name)); err != nil {
			return fmt.Errorf("Couldn't delete config file: %s", err)
		} else {
			return nil

		}
	} else {
		return nil
	}
}
