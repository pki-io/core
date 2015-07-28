// ThreatSpec package github.com/pki-io/core/entity as entity
package entity

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/pki-io/core/crypto"
	"github.com/pki-io/core/document"
)

// EntityDefault provides default values for Entity.
const EntityDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "entity-document",
    "options": "",
    "body": {
      "id": "",
      "name": "",
      "key-type": "ec",
      "public-signing-key": "",
      "private-signing-key": "",
      "public-encryption-key": "",
      "private-encryption-key": ""
    }
}`

// EntitySchema defines the JSON Schema for Entity.
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
          "required": ["id", "name", "key-type", "public-signing-key", "private-signing-key", "public-encryption-key", "private-encryption-key"],
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
              "key-type": {
				  "description": "Key type. Either rsa or ec",
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

// EntityData represents parsed Entity JSON data.
type EntityData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options string `json:"options"`
	Body    struct {
		Id                   string `json:"id"`
		Name                 string `json:"name"`
		KeyType              string `json:"key-type"`
		PublicSigningKey     string `json:"public-signing-key"`
		PrivateSigningKey    string `json:"private-signing-key"`
		PublicEncryptionKey  string `json:"public-encryption-key"`
		PrivateEncryptionKey string `json:"private-encryption-key"`
	} `json:"body"`
}

// Entity participates in cryptographic operations, sending and receiving secured data.
type Entity struct {
	document.Document
	Data EntityData
}

// ThreatSpec TMv0.1 for New
// Creates new entity for App:Entity

// New returns a new Entity.
func New(jsonString interface{}) (*Entity, error) {
	entity := new(Entity)
	if err := entity.New(jsonString); err != nil {
		return nil, fmt.Errorf("Couldn't create new entity: %s", err)
	} else {
		return entity, nil
	}
}

// ThreatSpec TMv0.1 for Entity.New
// Does entity initialisation for App:Entity

// New initializes the entity.
func (entity *Entity) New(jsonString interface{}) error {
	entity.Schema = EntitySchema
	entity.Default = EntityDefault
	if err := entity.Load(jsonString); err != nil {
		return fmt.Errorf("Could not create new Entity: %s", err)
	} else {
		return nil
	}
}

// ThreatSpec TMv0.1 for Entity.Load
// Does entity JSON loading for App:Entity

// Load takes a JSON string and sets the entity data.
func (entity *Entity) Load(jsonString interface{}) error {
	data := new(EntityData)
	if data, err := entity.FromJson(jsonString, data); err != nil {
		return fmt.Errorf("Could not load entity JSON: %s", err)
	} else {
		entity.Data = *data.(*EntityData)
		return nil
	}
}

// ThreatSpec TMv0.1 for Entity.Dump
// Does entity JSON dumping for App:Entity

// Dump serializes the entity, returning a JSON string.
func (entity *Entity) Dump() string {
	if jsonString, err := entity.ToJson(entity.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

// ThreatSpec TMv0.1 for Entity.DumpPublic
// Does entity dumping of public JSON for App:Entity

// DumpPublic serializes the public entity data, returning a JSON string.
func (entity *Entity) DumpPublic() string {
	public, err := entity.Public()
	if err != nil {
		return ""
	} else {
		return public.Dump()
	}
}

// ThreatSpec TMv0.1 for Entity.generateRSAKeys
// Does RSA key generation for App:Entity

// generateRSAKeys generates RSA keys.
func (entity *Entity) generateRSAKeys() (*rsa.PrivateKey, *rsa.PrivateKey, error) {
	signingKey, err := crypto.GenerateRSAKey()
	if err != nil {
		return nil, nil, err
	}

	encryptionKey, err := crypto.GenerateRSAKey()
	if err != nil {
		return nil, nil, err
	}

	signingKey.Precompute()
	encryptionKey.Precompute()

	if err := signingKey.Validate(); err != nil {
		return nil, nil, fmt.Errorf("Could not validate signing key: %s", err)
	}

	if err := encryptionKey.Validate(); err != nil {
		return nil, nil, fmt.Errorf("Could not validate encryption key: %s", err)
	}

	if pub, err := crypto.PemEncodePublic(&signingKey.PublicKey); err != nil {
		return nil, nil, err
	} else {
		entity.Data.Body.PublicSigningKey = string(pub)
	}

	return signingKey, encryptionKey, nil
}

// ThreatSpec TMv0.1 for Entity.generateECKeys
// Does EC key generation for App:Entity

// generateECKeys generates EC keys.
func (entity *Entity) generateECKeys() (*ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	signingKey, err := crypto.GenerateECKey()
	if err != nil {
		return nil, nil, err
	}

	encryptionKey, err := crypto.GenerateECKey()
	if err != nil {
		return nil, nil, err
	}

	// TODO: Do we need to do any validation here?

	return signingKey, encryptionKey, nil
}

// ThreatSpec TMv0.1 for Entity.GenerateKeys
// Does key generation for App:Entity

// GenerateKeys generates RSA or EC keys for the entity, depending on the KeyType set.
func (entity *Entity) GenerateKeys() error {
	var signingKey interface{}
	var encryptionKey interface{}
	var publicSigningKey interface{}
	var publicEncryptionKey interface{}
	var err error
	switch crypto.KeyType(entity.Data.Body.KeyType) {
	case crypto.KeyTypeRSA:
		signingKey, encryptionKey, err = entity.generateRSAKeys()
		if err != nil {
			return err
		}
		publicSigningKey = &signingKey.(*rsa.PrivateKey).PublicKey
		publicEncryptionKey = &encryptionKey.(*rsa.PrivateKey).PublicKey
	case crypto.KeyTypeEC:
		signingKey, encryptionKey, err = entity.generateECKeys()
		if err != nil {
			return err
		}
		publicSigningKey = &signingKey.(*ecdsa.PrivateKey).PublicKey
		publicEncryptionKey = &encryptionKey.(*ecdsa.PrivateKey).PublicKey
	default:
		return fmt.Errorf("Invalid key type: %s", entity.Data.Body.KeyType)
	}

	if pub, err := crypto.PemEncodePublic(publicSigningKey); err != nil {
		return err
	} else {
		entity.Data.Body.PublicSigningKey = string(pub)
	}

	if key, err := crypto.PemEncodePrivate(signingKey); err != nil {
		return err
	} else {
		entity.Data.Body.PrivateSigningKey = string(key)
	}

	if pub, err := crypto.PemEncodePublic(publicEncryptionKey); err != nil {
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

// ThreatSpec TMv0.1 for Entity.Sign
// Does container using for App:Entity

// Sign takes a Container and signs it using its private signing key.
func (entity *Entity) Sign(container *document.Container) error {
	var signatureMode crypto.Mode
	switch crypto.KeyType(entity.Data.Body.KeyType) {
	case crypto.KeyTypeRSA:
		signatureMode = crypto.SignatureModeSha256Rsa
	case crypto.KeyTypeEC:
		signatureMode = crypto.SignatureModeSha256Ecdsa
	default:
		return fmt.Errorf("Invalid key type: %s", entity.Data.Body.KeyType)
	}

	signature := crypto.NewSignature(signatureMode)
	container.Data.Options.SignatureMode = string(signature.Mode)
	// Force a clear of any existing signature values as that doesn't make sense
	container.Data.Options.Signature = ""

	containerJson := container.Dump()

	if err := crypto.Sign(containerJson, entity.Data.Body.PrivateSigningKey, signature); err != nil {
		return fmt.Errorf("Could not sign container json: %s", err)
	}
	if signature.Message != containerJson {
		return fmt.Errorf("Signed message doesn't match input")
	}

	container.Data.Options.SignatureMode = string(signature.Mode)
	container.Data.Options.Signature = signature.Signature
	return nil
}

// ThreatSpec TMv0.1 for Entity.Authenticate
// Does container authentication with shared keys for App:Entity

// Authenticate takes a Container and MACs it using the provided key.
func (entity *Entity) Authenticate(container *document.Container, id, key string) error {

	// Have to expand key here as we need to add the salt to the container before we turn it into json
	rawKey, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("Could not decode key: %s", err)
	}

	newKey, salt, err := crypto.ExpandKey(rawKey, nil)
	if err != nil {
		return fmt.Errorf("Cold not expand key: %s", err)
	}

	signature := crypto.NewSignature(crypto.SignatureModeSha256Hmac)
	container.Data.Options.SignatureMode = string(signature.Mode)
	signatureInputs := make(map[string]string)
	signatureInputs["key-id"] = id
	signatureInputs["signature-salt"] = string(crypto.Base64Encode(salt))
	container.Data.Options.SignatureInputs = signatureInputs

	// Force a clear of any existing signature values as that doesn't make sense
	container.Data.Options.Signature = ""

	containerJson := container.Dump()

	if err := crypto.Authenticate(containerJson, newKey, signature); err != nil {
		return fmt.Errorf("Couldn't authenticate container: %s", err)
	}

	if signature.Message != containerJson {
		return fmt.Errorf("Authenticated message doesn't match")
	}

	container.Data.Options.Signature = signature.Signature
	return nil
}

// ThreatSpec TMv0.1 for Entity.VerifyAuthentication
// Does authenticated container verification for App:Entity

// VerifyAuthentication takes a Container and verifies the MAC for the given key.
func (entity *Entity) VerifyAuthentication(container *document.Container, key string) error {
	rawKey, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("Could not decode key: %s", err)
	}

	salt, err := crypto.Base64Decode([]byte(container.Data.Options.SignatureInputs["signature-salt"]))
	if err != nil {
		fmt.Errorf("Could not base64 decode signature salt: %s", err)
	}

	newKey, _, err := crypto.ExpandKey(rawKey, salt)
	if err != nil {
		return fmt.Errorf("Could not expand key: %s", err)
	}
	mac := crypto.NewSignature(crypto.SignatureModeSha256Hmac)

	mac.Signature = container.Data.Options.Signature
	container.Data.Options.Signature = ""

	mac.Message = container.Dump()

	if err := crypto.Verify(mac, newKey); err != nil {
		return fmt.Errorf("Couldn't verify container: %s", err)
	} else {
		return nil
	}
}

// ThreatSpec TMv0.1 for Entity.Verify
// Does container signature verification for App:Entity

// Verify takes a Container and verifies the signature using the entities public key.
func (entity *Entity) Verify(container *document.Container) error {

	if container.IsSigned() == false {
		return fmt.Errorf("Container isn't signed")
	}

	signature := new(crypto.Signed)
	signature.Signature = container.Data.Options.Signature

	container.Data.Options.Signature = ""
	containerJson := container.Dump()
	signature.Message = containerJson

	if err := crypto.Verify(signature, []byte(entity.Data.Body.PublicSigningKey)); err != nil {
		return fmt.Errorf("Could not verify org container signature: %s", err)
	} else {
		return nil
	}
}

// ThreatSpec TMv0.1 for Entity.Decrypt
// Does container decryption using private keys for App:Entity

// Decrypt takes a Container and decrypts the content using the entities private decryption key.
// It returns a plaintext string.
func (entity *Entity) Decrypt(container *document.Container) (string, error) {

	if container.IsEncrypted() == false {
		return "", fmt.Errorf("Container isn't encrypted")
	}

	id := entity.Data.Body.Id
	key := entity.Data.Body.PrivateEncryptionKey
	if decryptedJson, err := container.Decrypt(id, key); err != nil {
		return "", fmt.Errorf("Could not decrypt: %s", err)
	} else {
		return decryptedJson, nil
	}
}

// ThreatSpec TMv0.1 for Entity.SymmetricDecrypt
// Does container symmetric decryption using shared keys for App:Entity

// SymmetricDecrypt takes a Container and decrypts the content using the provided key.
// It returns a plaintext string.
func (entity *Entity) SymmetricDecrypt(container *document.Container, key string) (string, error) {

	// TODO - check container is encrypted
	if decryptedJson, err := container.SymmetricDecrypt(key); err != nil {
		return "", fmt.Errorf("Could not decrypt: %s", err)
	} else {
		return decryptedJson, nil
	}
}

// ThreatSpec  TMv0.1 for Entity.Public
// Returns public version of entity for App:Entity

// Public returns the public entity data.
func (entity *Entity) Public() (*Entity, error) {
	selfJson := entity.Dump()
	publicEntity, err := New(selfJson)
	if err != nil {
		return nil, fmt.Errorf("Could not create public entity: %s", err)
	}
	publicEntity.Data.Body.PrivateSigningKey = ""
	publicEntity.Data.Body.PrivateEncryptionKey = ""
	return publicEntity, nil
}

// ThreatSpec TMv0.1 for Entity.SignString
// Does string signing for App:Entity

// SignString takes a message string and signs it.
func (entity *Entity) SignString(content string) (*document.Container, error) {
	container, err := document.NewContainer(nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create container: %s", err)
	}
	container.Data.Options.Source = entity.Data.Body.Id
	container.Data.Body = content
	if err := entity.Sign(container); err != nil {
		return nil, fmt.Errorf("Could not sign container: %s", err)
	} else {
		return container, nil
	}
}

// ThreatSpec TMv0.1 for Entity.AuthenticateString
// Does string authentication using shared keys for App:Entity

// AuthenticateString takes a message string and key and MACs the message using the provided key.
func (entity *Entity) AuthenticateString(content, id, key string) (*document.Container, error) {
	container, err := document.NewContainer(nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create container: %s", err)
	}
	container.Data.Options.Source = entity.Data.Body.Id
	container.Data.Body = content
	if err := entity.Authenticate(container, id, key); err != nil {
		return nil, fmt.Errorf("Could not sign container: %s", err)
	} else {
		return container, nil
	}
}

// ThreatSpec TMv0.1 for Entity.Encrypt
// Does public key encryption for App:Entity

// Encrypt takes a plaintext string and encrypts it for each provided entity.
func (entity *Entity) Encrypt(content string, entities interface{}) (*document.Container, error) {
	encryptionKeys := make(map[string]string)

	switch t := entities.(type) {
	case []*Entity:
		for _, e := range entities.([]*Entity) {
			encryptionKeys[e.Data.Body.Id] = e.Data.Body.PublicEncryptionKey
		}
	case nil:
		encryptionKeys[entity.Data.Body.Id] = entity.Data.Body.PublicEncryptionKey
	default:
		return nil, fmt.Errorf("Invalid entities given: %T", t)
	}

	container, err := document.NewContainer(nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create container: %s", err)
	}

	container.Data.Options.Source = entity.Data.Body.Id
	if err := container.Encrypt(content, encryptionKeys); err != nil {
		return nil, fmt.Errorf("Could not encrypt container: %s", err)
	}
	return container, nil
}

// ThreatSpec TMv0.1 for Entity.SymmetricEncrypt
// Does symmetric encryption using shared keys for App:Entity

// SymmetricEncrypt takes a plaintext string and encrypts it with the given key.
func (entity *Entity) SymmetricEncrypt(content, id, key string) (*document.Container, error) {

	container, err := document.NewContainer(nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create container: %s", err)
	}

	container.Data.Options.Source = entity.Data.Body.Id
	if err := container.SymmetricEncrypt(content, id, key); err != nil {
		return nil, fmt.Errorf("Could not symmetric encrypt container: %s", err)
	}

	return container, nil
}

// ThreatSpec TMv0.1 for Entity.EncryptThenSignString
// Does public key encrypt-then-sign of strings for App:Entity

// EncryptThenSignString takes a plaintext string, encrypts it then signs the ciphertext.
func (entity *Entity) EncryptThenSignString(content string, entities interface{}) (*document.Container, error) {

	container, err := entity.Encrypt(content, entities)
	if err != nil {
		return nil, fmt.Errorf("Couldn't encrypt content: %s", err)
	}

	if err := entity.Sign(container); err != nil {
		return nil, fmt.Errorf("Could not sign container: %s", err)
	}

	return container, nil
}

// ThreatSpec TMv0.1 for Entity.EncryptThenAuthenticateString
// Does symmetric encrypt-then-mac of strings for App:Entity

// EncryptThenAuthenticateString takes a plaintext string, encrypts it using the key and the MACs the ciphertext using they key.
//
// Note: under the hood, the key is expanded into two separate keys, one for encryption and one for signing.
func (entity *Entity) EncryptThenAuthenticateString(content, id, key string) (*document.Container, error) {

	container, err := entity.SymmetricEncrypt(content, id, key)
	if err != nil {
		return nil, fmt.Errorf("Couldn't encrypt content: %s", err)
	}
	if err := entity.Authenticate(container, id, key); err != nil {
		return nil, fmt.Errorf("Could not authenticate container: %s", err)
	}
	return container, nil
}

// ThreatSpec TMv0.1 for Entity.VerifyThenDecrypt
// Does public key verify-then-decrypt for App:Entity

// VerifyThenDecrypt takes a container, verifies the signature then decrypts, returning a plaintext string.
func (entity *Entity) VerifyThenDecrypt(container *document.Container) (string, error) {
	if err := entity.Verify(container); err != nil {
		return "", fmt.Errorf("Could not verify container: %s", err)
	}

	content, err := entity.Decrypt(container)
	if err != nil {
		return "", fmt.Errorf("Could not decrypt container: %s", err)
	}
	return content, nil

}

// ThreatSpec TMv0.1 for Entity.VerifyAuthenticationThenDecrypt
// Does symmetric verify-then-decrypt for App:Entity

// VerifyAuthenticationThenDecrypt takes a container and verifies the MAC using the given key, then decrypts using the key, returning a plaintext string.
//
// Note: under the hood, the key is expanded into two separate keys, one for encryption and one for signing.
func (entity *Entity) VerifyAuthenticationThenDecrypt(container *document.Container, key string) (string, error) {
	if err := entity.VerifyAuthentication(container, key); err != nil {
		return "", fmt.Errorf("Could not verify container: %s", err)
	}

	content, err := entity.SymmetricDecrypt(container, key)
	if err != nil {
		return "", fmt.Errorf("Could not decrypt container: %s", err)
	}
	return content, nil
}
