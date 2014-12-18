package tags

import (
	"fmt"
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
        "entity-tags": {},
        "tag-cas": {},
        "tag-entities": {}
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
          "required": ["parent-id", "ca-tags", "entity-tags", "tag-cas", "tag-entities"],
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
              },
              "tag-cas": {
                  "description": "Map of tag to CAs",
                  "type": "object"
              },
              "tag-entities": {
                  "description": "Map of tags to entities",
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
		ParentId    string              `json:"parent-id"`
		CATags      map[string][]string `json:"ca-tags"`
		EntityTags  map[string][]string `json:"entity-tags"`
		TagCAs      map[string][]string `json:"tag-cas"`
		TagEntities map[string][]string `json:"tag-entities"`
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

func (tags *Tags) AddCA(ca string, i interface{}) error {
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
		tags.Data.Body.CATags[ca] = AppendUnique(tags.Data.Body.CATags[ca], tag)
		tags.Data.Body.TagCAs[tag] = AppendUnique(tags.Data.Body.TagCAs[tag], ca)
	}

	return nil
}

func (tags *Tags) AddEntity(entity string, i interface{}) error {
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
		tags.Data.Body.EntityTags[entity] = AppendUnique(tags.Data.Body.EntityTags[entity], tag)
		tags.Data.Body.TagEntities[tag] = AppendUnique(tags.Data.Body.TagEntities[tag], entity)
	}

	return nil
}
