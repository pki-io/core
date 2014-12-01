package entity

import (
    "fmt"
    "pki.io/document"
    "pki.io/crypto"
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
    document.Document
    Data EntityData
}

func New(jsonString interface{}) (*Entity, error) {
    entity := new(Entity)
    entity.Schema = EntitySchema
    entity.Default = EntityDefault
    if err := entity.Load(jsonString); err != nil {
        return nil, fmt.Errorf("Could not create new Entity: %s", err.Error())
    } else {
        return entity, nil
    }
}

func (entity *Entity) Load(jsonString interface{}) error {
    data := new(EntityData)
    if data, err := entity.FromJson(jsonString, data); err != nil {
        return fmt.Errorf("Could not load entity JSON: %s", err.Error())
    } else {
        entity.Data = *data.(*EntityData)
        return nil
    }
}

func (entity *Entity) GenerateKeys() (bool, error) {
    signingKey := crypto.GenerateRSAKey()
    encryptionKey := crypto.GenerateRSAKey()

    signingKey.Precompute()
    encryptionKey.Precompute()

    if err := signingKey.Validate(); err != nil {
        return false, fmt.Errorf("Could not validate signing key: %s", err.Error())
    }

    if err := encryptionKey.Validate(); err != nil {
        return false, fmt.Errorf("Could not validate encryption key: %s", err.Error())
    }

    entity.Data.Body.PublicSigningKey = string(crypto.PemEncodeRSAPublic(&signingKey.PublicKey))
    entity.Data.Body.PrivateSigningKey = string(crypto.PemEncodeRSAPrivate(signingKey))
    entity.Data.Body.PublicEncryptionKey = string(crypto.PemEncodeRSAPublic(&encryptionKey.PublicKey))
    entity.Data.Body.PrivateEncryptionKey = string(crypto.PemEncodeRSAPrivate(encryptionKey))

    return true, nil
}
/*
func (entity *Entity) Encrypt(plaintext string, entities []*Entity, container *Container) (bool, error) {
    if len(plaintext) == 0 {
        return false, fmt.Errorf("Plaintext cannot be empty");
    }

    if len(entities)  == 0 {
        return false, fmt.Errorf("Number of entities cannot be zero")
    }

    if container.IsEncrypted() {
        return false, fmt.Errorf("Output container already has encrypted data")

        
    }

        Check plaintext length > 0
        Check entities > 0
        Check outDoc isn't already encrypted
        
        Generate AES inputs
        Encrypt plaintext
        For each entities
          Encrypt AES key
        Add results to outDoc
        return bool, err
}

func (entity *Entity) Sign(doc *CipherDocument) (bool, error) {

}
    */
