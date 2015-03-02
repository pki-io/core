package index

import (
	"fmt"
	"github.com/pki-io/core/document"
)

const NodeIndexDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "node-index-document",
    "options": "",
    "body": {
        "parent-id": "",
        "tags": {
          "cert-forward": {},
          "cert-reverse": {}
        }
    }
}`

const NodeIndexSchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "NodeIndexDocument",
  "description": "Node Index Document",
  "type": "object",
  "required": ["scope","version","type","options","body"],
  "additionalProperties": false,
  "properties": {
      "scope": {
          "description": "Scope of the document",
          "type": "string"
      },
      "version": {
          "description": "Document schema version",
          "type": "integer"
      },
      "type": {
          "description": "Type of document",
          "type": "string"
      },
      "options": {
          "description": "Options data",
          "type": "string"
      },
      "body": {
          "description": "Body data",
          "type": "object",
          "required": ["id", "parent-id", "tags"],
          "additionalProperties": false,
          "properties": {
              "id" : {
                  "description": "ID",
                  "type": "string"
              },
              "parent-id" : {
                  "description": "Parent ID",
                  "type": "string"
              },
              "tags": {
                  "description": "Tags",
                  "type": "object",
                  "required": ["cert-forward","cert-reverse"],
                  "additionalProperties": false,
                  "properties": {
                      "cert-forward": {
                          "description": "Tags to Certs",
                          "type": "object"
                      },
                      "cert-reverse": {
                          "description": "Cert to tags",
                          "type": "object"
                      }
                  }
              }
          }
      }
  }
}`

type NodeIndexData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options string `json:"options"`
	Body    struct {
		Id       string `json:"id"`
		ParentId string `json:"parent-id"`
		Tags     struct {
			CertForward map[string][]string `json:"cert-forward"`
			CertReverse map[string][]string `json:"cert-reverse"`
		} `json:"tags"`
	} `json:"body"`
}

type NodeIndex struct {
	document.Document
	Data NodeIndexData
}

func NewNode(jsonString interface{}) (*NodeIndex, error) {
	index := new(NodeIndex)
	index.Schema = NodeIndexSchema
	index.Default = NodeIndexDefault
	if err := index.Load(jsonString); err != nil {
		return nil, fmt.Errorf("Could not create new Index: %s", err)
	} else {
		return index, nil
	}
}

func (index *NodeIndex) Load(jsonString interface{}) error {
	data := new(NodeIndexData)
	if data, err := index.FromJson(jsonString, data); err != nil {
		return fmt.Errorf("Could not load Index JSON: %s", err)
	} else {
		index.Data = *data.(*NodeIndexData)
		return nil
	}
}

func (index *NodeIndex) Dump() string {
	if jsonString, err := index.ToJson(index.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

func (index *NodeIndex) AddCertTags(cert string, i interface{}) error {
	var inTags []string
	switch t := i.(type) {
	case string:
		inTags = []string{i.(string)}
	case []string:
		inTags = i.([]string)
	default:
		return fmt.Errorf("Could not add Cert tags. Wrong data type for tags: %T", t)
	}

	for _, tag := range inTags {
		index.Data.Body.Tags.CertForward[tag] = AppendUnique(index.Data.Body.Tags.CertForward[tag], cert)
		index.Data.Body.Tags.CertReverse[cert] = AppendUnique(index.Data.Body.Tags.CertReverse[cert], tag)
	}

	return nil
}
