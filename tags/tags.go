package tags

import (
	"fmt"
	//"time"
	//"math/big"
	//"crypto/rand"
	//"crypto/rsa"
	//"crypto/x509"
	//"crypto/x509/pkix"
	//"pki.io/crypto"
	"pki.io/document"
)

const TagsDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "tags-document",
    "options": "",
    "body": {
        "parent-id": "",
        "ca-tags": {},
        "entity-tags": {}
    }
}`

const TagsSchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "TagsDocument",
  "description": "Tags Document",
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
          "required": ["parent-id", "ca-tags", "entity-tags"],
          "additionalProperties": false,
          "properties": {
              "parent-id" : {
                  "description": "Parent ID",
                  "type": "string"
              },
              "ca-tags": {
                  "description": "Map of CA tags",
                  "type": "object"
              },
              "entity-tags": {
                  "description": "Map of CA tags",
                  "type": "object"
              }
          }
      }
  }
}`

type TagsData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options string `json:"options"`
	Body    struct {
		ParentId   string              `json:"parent-id"`
		CATags     map[string][]string `json:"ca-tags"`
		EntityTags map[string][]string `json:"entity-tags"`
	} `json:"body"`
}

type Tags struct {
	document.Document
	Data TagsData
}

func New(jsonString interface{}) (*Tags, error) {
	tags := new(Tags)
	tags.Schema = TagsSchema
	tags.Default = TagsDefault
	if err := tags.Load(jsonString); err != nil {
		return nil, fmt.Errorf("Could not create new Tags: %s", err.Error())
	} else {
		return tags, nil
	}
}

func (tags *Tags) Load(jsonString interface{}) error {
	data := new(TagsData)
	if data, err := tags.FromJson(jsonString, data); err != nil {
		return fmt.Errorf("Could not load Tags JSON: %s", err.Error())
	} else {
		tags.Data = *data.(*TagsData)
		return nil
	}
}

func (tags *Tags) Dump() string {
	if jsonString, err := tags.ToJson(tags.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

func (tags *Tags) AddCA(ca string, inTags interface{}) error {
	switch t := inTags.(type) {
	case string:
		tags.Data.Body.CATags[ca] = []string{inTags.(string)}
	case []string:
		tags.Data.Body.CATags[ca] = inTags.([]string)
	default:
		return fmt.Errorf("Could not add CA tags. Wrong data type for tags: %T", t)
	}
	return nil
}

func (tags *Tags) AddEntity(entity string, inTags interface{}) error {
	switch t := inTags.(type) {
	case string:
		tags.Data.Body.EntityTags[entity] = []string{inTags.(string)}
	case []string:
		tags.Data.Body.EntityTags[entity] = inTags.([]string)
	default:
		return fmt.Errorf("Could not add Entity tags. Wrong data type for tags: %T", t)
	}
	return nil
}
