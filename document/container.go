package document

import (
    "fmt"
    "pki.io/crypto"
)

const ContainerDefault string = `{
  "scope": "pki.io",
  "version": 1,
  "type": "container",
  "options": {
    "source": "",
    "signature-mode": "",
    "signature": "",
    "encryption-keys": {},
    "encryption-mode": "",
    "encryption-inputs": {}
  },
  "body": ""
}`

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
                  "type": "string",
                  "pattern": "^[a-fA-F0-9]{32}$"
              },
              "signature-mode": {
                  "description": "Signature mode",
                  "type": "string"
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

type ContainerData struct {
    Scope string `json:"scope"`
    Version int `json:"version"`
    Type string `json:"type"`
    Options struct {
        Source string `json:"source"`
        SignatureMode string `json:"signature-mode"`
        Signature string `json:"signature"`
        EncryptionKeys map[string]string `json:"encryption-keys"`
        EncryptionMode string `json:"encryption-mode"`
        EncryptionInputs map[string]string `json:"encryption-inputs"`
    } `json:"options"`
    Body string `json:"body"`
}

type Container struct {
    Document
    Data ContainerData
}

func NewContainer(jsonData interface{}) (*Container, error) {
    doc := new(Container)
    data := new(ContainerData)
    doc.Schema = ContainerSchema
    doc.Default = ContainerDefault
    if data, err := doc.FromJson(jsonData, data); err != nil {
        return nil, fmt.Errorf("Could not load container json: %s", err.Error())
    } else {
        doc.Data = *data.(*ContainerData)
        return doc, nil
    }
}

func (doc *Container) Dump() string {
    if jsonString, err := doc.ToJson(doc.Data); err != nil {
        return ""
    } else {
        return jsonString
    }
}

func (doc *Container) Encrypt(jsonString string, keys map[string]string) error {
    encrypted, err := crypto.GroupEncrypt(jsonString, keys)
    if err != nil {
        return fmt.Errorf("Could not group encrypt: %s", err.Error())
    }

    doc.Data.Options.EncryptionKeys = encrypted.Keys
    doc.Data.Options.EncryptionMode = encrypted.Mode
    doc.Data.Options.EncryptionInputs = encrypted.Inputs
    doc.Data.Body = encrypted.Ciphertext

    return nil
}

func (doc *Container) Decrypt(id string, privateKey string) (string, error) {
    encrypted := new(crypto.Encrypted)
    encrypted.Keys = doc.Data.Options.EncryptionKeys
    encrypted.Mode = doc.Data.Options.EncryptionMode
    encrypted.Inputs = doc.Data.Options.EncryptionInputs
    encrypted.Ciphertext = doc.Data.Body

    if decryptedJson, err := crypto.GroupDecrypt(encrypted, id, privateKey); err != nil {
        return "", fmt.Errorf("Could not decrypt container: %s", err.Error())
    } else {
        return decryptedJson, nil
    }
}

func (doc *Container) IsEncrypted() bool {
    if len(doc.Data.Options.EncryptionKeys) == 0 || 
    len(doc.Data.Options.EncryptionMode) == 0 ||
    len(doc.Data.Options.EncryptionInputs) == 0 {
        return false
    } else {
        return true
    }
}

func (doc *Container) IsSigned() bool {
    if len(doc.Data.Options.SignatureMode) == 0 || 
    len(doc.Data.Options.Signature) == 0 {
        return false
    } else {
        return true
    }
}
