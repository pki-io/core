package config

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
)

const nodeFile string = "node.conf"

type NodeData struct {
	Name  string `toml:"name"`
	Id    string `toml:"id"`
	Index string `toml:"index"`
}

type NodeConfigData struct {
	Node []NodeData `toml:"node"`
}

type NodeConfig struct {
	Data NodeConfigData
}

func NewNode() (*NodeConfig, error) {
	conf := new(NodeConfig)
	conf.Data = NodeConfigData{}
	return conf, nil
}

func (conf *NodeConfig) Dump() (string, error) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(conf.Data); err != nil {
		return "", fmt.Errorf("Could not encode config: %s", err)
	}
	return string(buf.Bytes()), nil
}

func (conf *NodeConfig) Load(tomlString string) error {
	data := new(NodeConfigData)

	if _, err := toml.Decode(tomlString, data); err != nil {
		return fmt.Errorf("Could not decode config: %s", err)
	}
	conf.Data = *data
	return nil
}

func (conf *NodeConfig) AddNode(name, id, indexId string) error {
	// TODO - Check for uniqueness
	conf.Data.Node = append(conf.Data.Node, NodeData{name, id, indexId})
	return nil
}

func (conf *NodeConfig) GetNode(name string) (*NodeData, error) {
	for _, node := range conf.Data.Node {
		if node.Name == name {
			return &node, nil
		}
	}
	return nil, fmt.Errorf("Couldn't find node: %s", name)
}
