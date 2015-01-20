package entity

import (
	"fmt"
	"github.com/pki-io/pki.io/crypto"
	"github.com/pki-io/pki.io/document"
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
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options string `json:"options"`
	Body    struct {
		Id                   string `json:"id"`
		Name                 string `json:"name"`
		PublicSigningKey     string `json:"public-signing-key"`
		PrivateSigningKey    string `json:"private-signing-key"`
		PublicEncryptionKey  string `json:"public-encryption-key"`
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

func (entity *Entity) Dump() string {
	if jsonString, err := entity.ToJson(entity.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

func (entity *Entity) GenerateKeys() error {
	signingKey, err := crypto.GenerateRSAKey()
	if err != nil {
		return err
	}

	encryptionKey, err := crypto.GenerateRSAKey()
	if err != nil {
		return err
	}

	signingKey.Precompute()
	encryptionKey.Precompute()

	if err := signingKey.Validate(); err != nil {
		return fmt.Errorf("Could not validate signing key: %s", err.Error())
	}

	if err := encryptionKey.Validate(); err != nil {
		return fmt.Errorf("Could not validate encryption key: %s", err.Error())
	}

	if pub, err := crypto.PemEncodePublic(&signingKey.PublicKey); err != nil {
		return err
	} else {
		entity.Data.Body.PublicSigningKey = string(pub)
	}


	if key, err := crypto.PemEncodePrivate(signingKey); err != nil {
		return err
	} else {
		entity.Data.Body.PrivateSigningKey = string(key)
	}

	if pub, err := crypto.PemEncodePublic(&encryptionKey.PublicKey); err != nil {
		return err
	} else {
		entity.Data.Body.PublicEncryptionKey = string(pub)
	}

	if key, err := crypto.PemEncodePrivate(encryptionKey); err != nil {
		return err
	} else {
		entity.Data.Body.PrivateEncryptionKey = string(key)
	}

	return nil
}

func (entity *Entity) Sign(container *document.Container) error {
	signature := crypto.NewSignature(crypto.SignatureModeSha256Rsa)
	container.Data.Options.SignatureMode = signature.Mode
	// Force a clear of any existing signature values as that doesn't make sense
	container.Data.Options.Signature = ""

	containerJson := container.Dump()

	if err := crypto.Sign(containerJson, entity.Data.Body.PrivateSigningKey, signature); err != nil {
		return fmt.Errorf("Could not sign container json: %s", err.Error())
	}
	if signature.Message != containerJson {
		return fmt.Errorf("Signed message doesn't match input")
	}

	container.Data.Options.SignatureMode = string(signature.Mode)
	container.Data.Options.Signature = signature.Signature
	return nil
}

func (entity *Entity) Verify(container *document.Container) error {

	if container.IsSigned() == false {
		return fmt.Errorf("Container isn't signed")
	}

	signature := new(crypto.Signed)
	signature.Signature = container.Data.Options.Signature

	container.Data.Options.Signature = ""
	containerJson := container.Dump()
	signature.Message = containerJson

	if err := crypto.Verify(signature, entity.Data.Body.PublicSigningKey); err != nil {
		return fmt.Errorf("Could not verify org container signature: %s", err.Error())
	} else {
		return nil
	}
}

func (entity *Entity) Decrypt(container *document.Container) (string, error) {
	if container.IsEncrypted() == false {
		return "", fmt.Errorf("Container isn't encrypted")
	}

	id := entity.Data.Body.Id
	key := entity.Data.Body.PrivateEncryptionKey
	if decryptedJson, err := container.Decrypt(id, key); err != nil {
		return "", fmt.Errorf("Could not decrypt: %s", err.Error())
	} else {
		return decryptedJson, nil
	}
}

func (entity *Entity) Public() (*Entity, error) {
	selfJson := entity.Dump()
	publicEntity, err := New(selfJson)
	if err != nil {
		return nil, fmt.Errorf("Could not create public entity: %s", err.Error())
	}
	publicEntity.Data.Body.PrivateSigningKey = ""
	publicEntity.Data.Body.PrivateEncryptionKey = ""
	return publicEntity, nil
}

func (entity *Entity) SignString(content string) (*document.Container, error) {
	container, err := document.NewContainer(nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create container: %s", err.Error())
	}
	container.Data.Options.Source = entity.Data.Body.Id
	container.Data.Body = content
	if err := entity.Sign(container); err != nil {
		return nil, fmt.Errorf("Could not sign container: %s", err.Error())
	} else {
		return container, nil
	}
}

func (entity *Entity) EncryptThenSignString(content string, entities interface{}) (*document.Container, error) {

	encryptionKeys := make(map[string]string)

	switch t := entities.(type) {
	case []*Entity:
		return nil, fmt.Errorf("Not implemented")
	case nil:
		encryptionKeys[entity.Data.Body.Id] = entity.Data.Body.PublicEncryptionKey
	default:
		return nil, fmt.Errorf("Invalid entities given: %T", t)
	}

	container, err := document.NewContainer(nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create container: %s", err.Error())
	}

	container.Data.Options.Source = entity.Data.Body.Id
	if err := container.Encrypt(content, encryptionKeys); err != nil {
		return nil, fmt.Errorf("Could not encrypt container: %s", err.Error())
	}

	if err := entity.Sign(container); err != nil {
		return nil, fmt.Errorf("Could not sign container: %s", err.Error())
	}

	return container, nil
}

func (entity *Entity) VerifyThenDecrypt(container *document.Container) (string, error) {
	if err := entity.Verify(container); err != nil {
		return "", fmt.Errorf("Could not verify container: %s", err.Error())
	}

	content, err := entity.Decrypt(container)
	if err != nil {
		return "", fmt.Errorf("Could not decrypt container: %s", err.Error())
	}
	return content, nil

}
