// ThreatSpec package github.com/pki-io/core/node as node
package node

import (
	"fmt"
	"github.com/pki-io/core/entity"
)

type Node struct {
	entity.Entity
}

// ThreatSpec TMv0.1 for New
// Creates new node for App:Node

func New(jsonString interface{}) (*Node, error) {
	node := new(Node)
	if err := node.New(jsonString); err != nil {
		return nil, fmt.Errorf("Couldn't create node: %s", err)
	} else {
		return node, nil
	}
}
