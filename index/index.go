package index

import (
	"fmt"
	"github.com/pki-io/pki.io/document"
)

const IndexDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "index-document",
    "options": "",
    "body": {
        "parent-id": "",
        "tags": {
          "ca-forward": {},
          "ca-reverse": {},
          "entity-forward": {},
          "entity-reverse": {}
        },
        "pairing-keys": {}
    }
}`

const IndexSchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "IndexDocument",
  "description": "Index Document",
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
          "required": ["parent-id", "tags"],
          "additionalProperties": false,
          "properties": {
              "parent-id" : {
                  "description": "Parent ID",
                  "type": "string"
              },
              "pairing-keys": {
                  "description": "Pairing Keys",
                  "type": "object"
              },
              "tags": {
                  "description": "Tags",
                  "type": "object",
                  "required": ["ca-forward","ca-reverse","entity-forward","entity-reverse"],
                  "additionalProperties": false,
                  "properties": {
                      "ca-forward": {
                          "description": "Tags to CAs",
                          "type": "object"
                      },
                      "ca-reverse": {
                          "description": "CA to tags",
                          "type": "object"
                      },
                      "entity-forward": {
                          "description": "Tags to entities",
                          "type": "object"
                      },
                      "entity-reverse": {
                          "description": "Entities to tags",
                          "type": "object"
                      }
                  }
              }
          }
      }
  }
}`

type PairingKey struct {
	Key  string   `json:"key"`
	Tags []string `json:"tags"`
}

type IndexData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options string `json:"options"`
	Body    struct {
		ParentId    string                `json:"parent-id"`
		PairingKeys map[string]PairingKey `json:"pairing-keys"`
		Tags        struct {
			CAForward     map[string][]string `json:"ca-forward"`
			CAReverse     map[string][]string `json:"ca-reverse"`
			EntityForward map[string][]string `json:"entity-forward"`
			EntityReverse map[string][]string `json:"entity-reverse"`
		} `json:"tags"`
	} `json:"body"`
}

type Index struct {
	document.Document
	Data IndexData
}

func New(jsonString interface{}) (*Index, error) {
	index := new(Index)
	index.Schema = IndexSchema
	index.Default = IndexDefault
	if err := index.Load(jsonString); err != nil {
		return nil, fmt.Errorf("Could not create new Index: %s", err.Error())
	} else {
		return index, nil
	}
}

func (index *Index) Load(jsonString interface{}) error {
	data := new(IndexData)
	if data, err := index.FromJson(jsonString, data); err != nil {
		return fmt.Errorf("Could not load Index JSON: %s", err.Error())
	} else {
		index.Data = *data.(*IndexData)
		return nil
	}
}

func (index *Index) Dump() string {
	if jsonString, err := index.ToJson(index.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

func AppendUnique(slice []string, val string) []string {
	found := false
	for _, v := range slice {
		if v == val {
			found = true
			break
		}
	}

	if found {
		return slice
	} else {
		return append(slice, val)
	}
}

func (index *Index) AddCATags(ca string, i interface{}) error {
	var inTags []string
	switch t := i.(type) {
	case string:
		inTags = []string{i.(string)}
	case []string:
		inTags = i.([]string)
	default:
		return fmt.Errorf("Could not add CA tags. Wrong data type for tags: %T", t)
	}

	for _, tag := range inTags {
		index.Data.Body.Tags.CAForward[tag] = AppendUnique(index.Data.Body.Tags.CAForward[tag], ca)
		index.Data.Body.Tags.CAReverse[ca] = AppendUnique(index.Data.Body.Tags.CAReverse[ca], tag)
	}

	return nil
}

func (index *Index) AddEntityTags(entity string, i interface{}) error {
	var inTags []string
	switch t := i.(type) {
	case string:
		inTags = []string{i.(string)}
	case []string:
		inTags = i.([]string)
	default:
		return fmt.Errorf("Could not add Entity tags. Wrong data type for tags: %T", t)
	}
	for _, tag := range inTags {
		index.Data.Body.Tags.EntityForward[tag] = AppendUnique(index.Data.Body.Tags.EntityForward[tag], entity)
		index.Data.Body.Tags.EntityReverse[entity] = AppendUnique(index.Data.Body.Tags.EntityReverse[entity], tag)
	}

	return nil
}

func (index *Index) AddPairingKey(id, key string, i interface{}) error {
	var inTags []string
	switch t := i.(type) {
	case string:
		inTags = []string{i.(string)}
	case []string:
		inTags = i.([]string)
	default:
		return fmt.Errorf("Could not add pairing key. Wrong data type for tags: %T", t)
	}

	pairingKey := new(PairingKey)
	pairingKey.Key = key

	for _, tag := range inTags {
		pairingKey.Tags = AppendUnique(pairingKey.Tags, tag)
	}
	index.Data.Body.PairingKeys[id] = *pairingKey
	return nil
}
