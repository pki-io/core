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
	OrgId string `toml:"org_id"`
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

func (conf *NodeConfig) AddNode(name, id, indexId, orgId string) error {
	for _, node := range conf.Data.Node {
		if node.Name == name {
			return fmt.Errorf("Could not add node '%s' as one with that name already exists", name)
		}
	}
	conf.Data.Node = append(conf.Data.Node, NodeData{name, id, indexId, orgId})
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

func (conf *NodeConfig) RemoveNode(name string) error {
	for i, node := range conf.Data.Node {
		if node.Name == name {
			conf.Data.Node = append(conf.Data.Node[:i], conf.Data.Node[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("key %s does not exist: %s", name)
}

func (conf *NodeConfig) OrgExists(orgId string) bool {
	for _, node := range conf.Data.Node {
		if node.OrgId == orgId {
			return true
		}
	}
	return false
}
