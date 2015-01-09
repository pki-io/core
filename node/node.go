package x509

import (
	"fmt"
	"pki.io/document"
	"pki.io/entity"
)

const NodeRegistrationDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "ca-document",
    "options": {
      "pairing-id": "",
      "source": "",
      "signature-mode": "",
      "signature": ""
    },
    "body": {
        "id": "",
        "name": "",
        "public-encryption-key": "",
        "public-signing-key": ""
    }
}`

const NodeRegistrationSchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "CADocument",
  "description": "CA Document",
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
          "type": "object",
          "required": ["source", "pairing-id", "signature-mode", "signature"],
          "additionalProperties": false,
          "properties": {
              "pairing-id" : {
                  "description": "Pairing ID",
                  "type": "string"
              },
              "source" : {
                  "description": "Source ID",
                  "type": "string"
              },
              "signature-mode": {
                  "description": "Signature mode",
                  "type": "string"
              },
              "signature": {
                  "description": "Base64 encoded signature",
                  "type": "string"
              }

          }
      },
      "body": {
          "description": "Body data",
          "type": "object",
          "required": ["id", "name", "certificate", "private-key", "dn-scope"],
          "additionalProperties": false,
          "properties": {
              "id" : {
                  "description": "Entity ID",
                  "type": "string"
              },
              "name" : {
                  "description": "Entity name",
                  "type": "string"
              },
              "public-signing-key" : {
                  "description": "PEM encoded public signing key",
                  "type": "string"
              },
              "public-encryption-key" : {
                  "description": "PEM encoded public encryption key",
                  "type": "string"
              }
          }
      }
  }
}`

type NodeRegistrationData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options struct {
		Source        string `json:"source"`
		PairingId     string `json:"certificate"`
		SignatureMode string `json:"signature-mode"`
		Signature     string `json:"signature"`
	} `json:"options"`
	Body struct {
		Id                  string `json:"id"`
		Name                string `json:"name"`
		PublicSigningKey    string `json:"public-signing-key"`
		PublicEncryptionKey string `json:"public-encryption-key"`
	} `json:"body"`
}

type NodeRegistration struct {
	document.Document
	Data NodeRegistrationData
}

func New(jsonString interface{}) (*entity.Entity, error) {
	if node, err := entity.New(nil); err != nil {
		return nil, fmt.Errorf("Could not create node entity: %s", err.Error())
	} else {
		return node, nil
	}
}

func NewRegistration(jsonString interface{}) (*NodeRegistration, error) {
	reg := new(NodeRegistration)
	reg.Schema = NodeRegistrationSchema
	reg.Default = NodeRegistrationDefault
	if err := reg.Load(jsonString); err != nil {
		return nil, fmt.Errorf("Could not create new node registration: %s", err.Error())
	} else {
		return reg, nil
	}
}

func (reg *NodeRegistration) Load(jsonString interface{}) error {
	data := new(NodeRegistrationData)
	if data, err := reg.FromJson(jsonString, data); err != nil {
		return fmt.Errorf("Could not load node registration JSON: %s", err.Error())
	} else {
		reg.Data = *data.(*NodeRegistrationData)
		return nil
	}
}

func (reg *NodeRegistration) Dump() string {
	if jsonString, err := reg.ToJson(reg.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}
