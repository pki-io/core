package document

const ContainerDefault string = `{
  "scope": "pki.io",
  "version": 1,
  "type": "container",
  "options": {
    "source": "00112233445566778899aabbccddeeff",
    "signature-mode": "sha256+rsa",
    "signature": "abc",
    "encryption-keys": {
      "8899aabbccddeeff0011223344556677": "xxx"
    },
    "encryption-mode": "aes-cbc-256+rsa"
    "encryption-inputs": {
      "iv": "aaa"
    }
  },
  "body": "abc"
}`

const ContainerDefault string = `{
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
              "signature-mode" : {
                  "description": "Signature mode",
                  "type": "string"
              },
              "signature" : {
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
          "type": "string",
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
    document
    Data ContainerData
}

func NewContainer(jsonData interface{}) (*Container, error) {
    doc := new(Container)
    data := new(ContainerData)
    doc.schema = ContainerSchema
    doc.defaultValue = ContainerDefault
    if data, err := doc.fromJson(jsonData, data); err != nil {
        return nil, err
    } else {
        doc.Data = *data.(*ContainerData)
        return doc, nil
    }
}

func (doc *Container) Json() (string, error) {
    if jsonString, err := doc.toJson(doc.Data); err != nil {
        return "", err
    } else {
        return jsonString, nil
    }
}

func (doc *Container) IsEncrypted() (bool, error) {
    reurn false, nil
}

func (doc *Container) IsSigned() (bool, error) {
    reurn false, nil
}
