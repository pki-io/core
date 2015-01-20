package node

import (
	"encoding/hex"
	"fmt"
	"github.com/pki-io/pki.io/crypto"
	"github.com/pki-io/pki.io/document"
	"github.com/pki-io/pki.io/entity"
)

const NodeRegistrationDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "node-registration-document",
    "options": {
      "pairing-id": "",
      "source": "",
      "signature-mode": "",
      "signature-salt": "",
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
          "required": ["source", "pairing-id", "signature-mode", "signature-salt", "signature"],
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
              "signature-salt": {
                  "description": "Signature salt",
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
          "required": ["id", "name", "public-signing-key", "public-encryption-key" ],
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
		PairingId     string `json:"pairing-id"`
		SignatureMode string `json:"signature-mode"`
		SignatureSalt string `json:"signature-salt"`
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
	if node, err := entity.New(jsonString); err != nil {
		return nil, fmt.Errorf("Could not create node entity: %s", err.Error())
	} else {
		return node, nil
	}
}

func NewFromRegistration(reg *NodeRegistration) (*entity.Entity, error) {
	node, err := New(nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create node: %s", err.Error())
	}

	node.Data.Body.Id = reg.Data.Body.Id
	node.Data.Body.Name = reg.Data.Body.Name
	node.Data.Body.PublicSigningKey = reg.Data.Body.PublicSigningKey
	node.Data.Body.PublicEncryptionKey = reg.Data.Body.PublicEncryptionKey
	return node, nil
}

func NewRegistration(input interface{}) (*NodeRegistration, error) {
	reg := new(NodeRegistration)
	reg.Schema = NodeRegistrationSchema
	reg.Default = NodeRegistrationDefault

	switch t := input.(type) {
	case string:
		if err := reg.Load(input); err != nil {
			return nil, fmt.Errorf("Could not create new node registration: %s", err.Error())
		} else {
			return reg, nil
		}
	case *entity.Entity:
		node := input.(*entity.Entity)
		reg.Data.Body.Id = node.Data.Body.Id
		reg.Data.Body.Name = node.Data.Body.Name
		reg.Data.Body.PublicSigningKey = node.Data.Body.PublicSigningKey
		reg.Data.Body.PublicEncryptionKey = node.Data.Body.PublicEncryptionKey
		return reg, nil
	case nil:
		if err := reg.Load(nil); err != nil {
			return nil, fmt.Errorf("Could not create new node registration: %s", err.Error())
		} else {
			return reg, nil
		}
	default:
		return nil, fmt.Errorf("Invalid input type: %T", t)
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

func (reg *NodeRegistration) Authenticate(id, inKey string) error {
	key, err := hex.DecodeString(inKey)
	if err != nil {
		return fmt.Errorf("Could not decode key: %s", err)
	}

	newKey, salt, err := crypto.ExpandKey(key, nil)
	if err != nil {
		return fmt.Errorf("Cold not expand key: %s", err);
	}
	signature := crypto.NewHMAC()

	reg.Data.Options.PairingId = id
	reg.Data.Options.SignatureSalt = string(crypto.Base64Encode(salt))
	reg.Data.Options.SignatureMode = string(signature.Mode)

	regJson := reg.Dump()
	if err := crypto.HMAC([]byte(regJson), newKey, signature); err != nil {
		return fmt.Errorf("Could not HMAC node registration: %s", err.Error())
	}
	if signature.Message != regJson {
		return fmt.Errorf("Signed message doesn't match input")
	}

	reg.Data.Options.Signature = signature.Signature
	return nil
}

func (reg *NodeRegistration) Verify(inKey string) error {
	key, err := hex.DecodeString(inKey)
	if err != nil {
		return fmt.Errorf("Could not decode key: %s", err)
	}

	salt, err := crypto.Base64Decode([]byte(reg.Data.Options.SignatureSalt))
	if err != nil {
		fmt.Errorf("Could not base64 decode signature salt: %s", err)
	}

	newKey, _, err := crypto.ExpandKey(key, salt)
	if err != nil {
		return fmt.Errorf("Could not expand key: %s", err)
	}
	mac := crypto.NewHMAC()
	mac.Signature = reg.Data.Options.Signature
	reg.Data.Options.Signature = ""

	if err := crypto.HMACVerify([]byte(reg.Dump()), newKey, mac); err != nil {
		return fmt.Errorf("Couldn't verify registration: %s", err.Error())
	} else {

		return nil
	}
}
