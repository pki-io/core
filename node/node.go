package node

import (
	"fmt"
	"github.com/pki-io/pki.io/entity"
)

type Node struct {
	entity.Entity
}

func New(jsonString interface{}) (*Node, error) {
	node := new(Node)
	if err := node.New(jsonString); err != nil {
		return nil, fmt.Errorf("Couldn't create node: %s", err.Error())
	} else {
		return node, nil
	}
}
