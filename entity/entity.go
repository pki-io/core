package entity

import (
    "fmt"
    "pki_io/document"
    "crypto/rand"
    "crypto/rsa"
)

const EntityDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "entity-document",
    "options": "",
    "body": {
      "id": "",
      "name": "",
      "public-signing-key": "",
      "private-signing-key": "",
      "public-encryption-key": "",
      "private-encryption-key": ""
    }
}`

const EntitySchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "EntityDocument",
  "description": "Entity Document",
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
          "required": ["id", "name", "public-signing-key", "private-signing-key", "public-encryption-key", "private-encryption-key"],
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
                  "description": "Public signing key",
                  "type": "string"
              },
              "private-signing-key" : {
                  "description": "Private signing key",
                  "type": "string"
              },
              "public-encryption-key" : {
                  "description": "Public encryption key",
                  "type": "string"
              },
              "private-encryption-key" : {
                  "description": "Private encryption key",
                  "type": "string"
              }
          }
      }
  }
}`

type EntityData struct {
    Scope string `json:"scope"`
    Version int `json:"version"`
    Type string `json:"type"`
    Options string `json:"options"`
    Body struct {
        Id string `json:"id"`
        Name string `json:"name"`
        PublicSigningKey string `json:"public-signing-key"`
        PrivateSigningKey string `json:"private-signing-key"`
        PublicEncryptionKey string `json:"public-encryption-key"`
        PrivateEncryptionKey string `json:"private-encryption-key"`
    } `json:"body"`
}

type Entity struct {
    document
    Data EntityData
}

func New(jsonData interface{}) (*Entity, error) {
    doc := new(Entity)
    data := new(EntityData)
    doc.schema = EntitySchema
    doc.defaultValue = EntityDefault
    if data, err := doc.fromJson(jsonData, data); err != nil {
        return nil, err
    } else {
        doc.Data = *data.(*CADocumentData)
        return doc, nil
    }
}

func (entity *Entity) GenerateKeys() (bool, error) {
    signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return false, fmt.Errorf("Could not generate signing key: %s", err.Error())
    }
    encryptionKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return false, fmt.Errorf("Could not generate encryption key: %s", err.Error())
    }

    signingKey.Precompute()
    encryptionKey.Precompute()

    if err := signingKey.Validate(); err != nil {
        return false, err
    }

    if err := encryptionKey.Validate(); err != nil {
        return false, err
    }

    entity.SigningKey = signingKey
    entity.EncryptionKey = encryptionKey
    return true, nil
}

func (entity *Entity) Encrypt(plaintext []byte, entities []*Entity, container *Container) (bool, error) {
    /*
        Check plaintext length > 0
        Check entities > 0
        Check outDoc isn't already encrypted
        
        Generate AES inputs
        Encrypt plaintext
        For each entities
          Encrypt AES key
        Add results to outDoc
        return bool, err
    */
}

func (entity *Entity) Sign(doc *CipherDocument) (bool, error) {

}
