// ThreatSpec package github.com/pki-io/core/document as document
package document

import (
	"fmt"
	"github.com/pki-io/core/crypto"
)

// ContainerDefault sets default values for a Container.
const ContainerDefault string = `{
  "scope": "pki.io",
  "version": 1,
  "type": "container",
  "options": {
    "source": "",
    "signature-mode": "",
    "signature-inputs": {},
    "signature": "",
    "encryption-keys": {},
    "encryption-mode": "",
    "encryption-inputs": {}
  },
  "body": ""
}`

// ContainerSchema defines the JSON schema for a Container.
const ContainerSchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "Container",
  "description": "Container",
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
          "required": ["source","signature-mode","signature","encryption-keys","encryption-mode","encryption-inputs"],
          "additionalProperties": false,
          "properties": {
              "source" : {
                  "description": "Source ID",
                  "type": "string"
              },
              "signature-mode": {
                  "description": "Signature mode",
                  "type": "string"
              },
              "signature-inputs": {
                  "description": "Signature inputs",
                  "type": "object"
              },
              "signature": {
                  "description": "Base64 encoded signature",
                  "type": "string"
              },
              "encryption-keys": {
                  "description": "Encryption keys",
                  "type": "object"
              },
              "encryption-mode": {
                  "description": "Encryption mode",
                  "type": "string"
              },
              "encryption-inputs": {
                  "description": "Encryption inputs",
                  "type": "object"
              }
          }
      },
      "body": {
          "description": "Encrypted data",
          "type": "string"
      }
  }
}`

// ContainerData stores the parsed JSON data.
type ContainerData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options struct {
		Source           string            `json:"source"`
		SignatureMode    string            `json:"signature-mode"`
		SignatureInputs  map[string]string `json:"signature-inputs"`
		Signature        string            `json:"signature"`
		EncryptionKeys   map[string]string `json:"encryption-keys"`
		EncryptionMode   string            `json:"encryption-mode"`
		EncryptionInputs map[string]string `json:"encryption-inputs"`
	} `json:"options"`
	Body string `json:"body"`
}

// Container is a cryptographic document that can be signed and/or encrypted.
type Container struct {
	Document
	Data ContainerData
}

// ThreatSpec TMv0.1 for NewContainer
// Creates new container for App:Document

// NewContainer creates a new Container.
func NewContainer(jsonData interface{}) (*Container, error) {
	doc := new(Container)
	data := new(ContainerData)
	doc.Schema = ContainerSchema
	doc.Default = ContainerDefault
	if data, err := doc.FromJson(jsonData, data); err != nil {
		return nil, fmt.Errorf("Could not load container json: %s", err)
	} else {
		doc.Data = *data.(*ContainerData)
		return doc, nil
	}
}

// ThreatSpec TMv0.1 for Container.Dump
// Does container dumping for App:Document

// Dump serializes the Container to JSON.
func (doc *Container) Dump() string {
	if jsonString, err := doc.ToJson(doc.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

// ThreatSpec TMv0.1 for Container.Encrypt
// Does container hybdrid encryption for App:Document

// Encrypt takes a plaintext string and group encrypts for the given public keys and updates its data to the ciphertext and inputs.
func (doc *Container) Encrypt(jsonString string, keys map[string]string) error {
	encrypted, err := crypto.GroupEncrypt(jsonString, keys)
	if err != nil {
		return fmt.Errorf("Could not group encrypt: %s", err)
	}

	doc.Data.Options.EncryptionKeys = encrypted.Keys
	doc.Data.Options.EncryptionMode = encrypted.Mode
	doc.Data.Options.EncryptionInputs = encrypted.Inputs
	doc.Data.Body = encrypted.Ciphertext

	return nil
}

// ThreatSpec TMv0.1 for Container.SymmetricEncrypt
// Does symmetric encryption of container for App:Document

// SymmetricEncrypt takes a plaintext string and encrypts with the given key. It updates its data to the ciphertext and inputs.
func (doc *Container) SymmetricEncrypt(jsonString, id, key string) error {
	encrypted, err := crypto.SymmetricEncrypt(jsonString, id, key)
	if err != nil {
		return fmt.Errorf("Couldn't symmetric encrypt content: %s", err)
	}

	doc.Data.Options.EncryptionMode = encrypted.Mode
	doc.Data.Options.EncryptionInputs = encrypted.Inputs
	doc.Data.Body = encrypted.Ciphertext

	return nil
}

// ThreatSpec TMv0.1 for Container.Decrypt
// Does hybdrid decryption of container for App:Document

// Decrypt takes a private key and decrypts the Container body, return a plaintext string.
func (doc *Container) Decrypt(id string, privateKey string) (string, error) {
	encrypted := new(crypto.Encrypted)
	encrypted.Keys = doc.Data.Options.EncryptionKeys
	encrypted.Mode = doc.Data.Options.EncryptionMode
	encrypted.Inputs = doc.Data.Options.EncryptionInputs
	encrypted.Ciphertext = doc.Data.Body

	if decryptedJson, err := crypto.GroupDecrypt(encrypted, id, privateKey); err != nil {
		return "", fmt.Errorf("Could not decrypt container: %s", err)
	} else {
		return decryptedJson, nil
	}
}

// ThreatSpec TMv0.1 for Container.SymmetricDecrypt
// Does symmetric decryption of container for App:Document

// SymmetricDecrypt takes a key and decrypts the Container body, returning a plaintext string.
func (doc *Container) SymmetricDecrypt(key string) (string, error) {
	encrypted := new(crypto.Encrypted)
	encrypted.Keys = doc.Data.Options.EncryptionKeys
	encrypted.Mode = doc.Data.Options.EncryptionMode
	encrypted.Inputs = doc.Data.Options.EncryptionInputs
	encrypted.Ciphertext = doc.Data.Body

	if decryptedJson, err := crypto.SymmetricDecrypt(encrypted, key); err != nil {
		return "", fmt.Errorf("Couldn't decrypt container: %s", err)
	} else {
		return decryptedJson, nil
	}
}

// ThreatSpec TMv0.1 for Container.IsEncrypted
// Returns whether container is encrypted for App:Document

// IsEncrypted checks whether the Container is encrypted.
func (doc *Container) IsEncrypted() bool {
	if len(doc.Data.Options.EncryptionKeys) == 0 ||
		len(doc.Data.Options.EncryptionMode) == 0 ||
		len(doc.Data.Options.EncryptionInputs) == 0 {
		return false
	} else {
		return true
	}
}

// ThreatSpec TMv0.1 for Container.IsSigned
// Returns whether container is signed for App:Document

// IsSigned checks whether the Container is signed.
func (doc *Container) IsSigned() bool {
	if len(doc.Data.Options.SignatureMode) == 0 ||
		len(doc.Data.Options.Signature) == 0 {
		return false
	} else {
		return true
	}
}
